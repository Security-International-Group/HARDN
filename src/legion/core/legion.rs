use std::fmt;
use std::io::{self, Write};
use std::process::{self, Command};

// Import from sibling modules in the legion crate
use super::baseline::{Baseline, BaselineManager};
use super::config::Config;
use super::framework::{
    BaselineSnapshot, FindingSeverity, LegionCore, LegionCycleReport, TelemetryPayload,
};
use super::framework_pipeline;
use crate::core::config::{DEFAULT_LIB_DIR, DEFAULT_LOG_DIR};
use crate::core::cron::CronOrchestrator;
use crate::legion::modules::auth::auth as auth_mod;
use crate::legion::modules::behavioral::{
    BehaviorClassification, BehavioralAnalyzer, ProcessBehavior,
};
use crate::legion::modules::containers::containers as containers_mod;
use crate::legion::modules::correlation::CorrelationManager;
use crate::legion::modules::crypto::crypto as crypto_mod;
use crate::legion::modules::filesystem::filesystem as filesystem_mod;
use crate::legion::modules::inventory::inventory as inventory_mod;
use crate::legion::modules::kernel::kernel as kernel_mod;
use crate::legion::modules::logs::logs as logs_mod;
use crate::legion::modules::memory::memory as memory_mod;
use crate::legion::modules::network::network as network_mod;
use crate::legion::modules::packages::packages as packages_mod;
use crate::legion::modules::permissions::permissions as permissions_mod;
use crate::legion::modules::processes::processes as processes_mod;
use crate::legion::modules::response::{Anomaly, ResponseAction, ResponseEngine};
use crate::legion::modules::risk_scoring::{
    RiskScore, RiskScoringManager, ScriptResult, ScriptStatus, SecurityPlatformStatus, SystemState,
    ThreatIndicator as RiskThreatIndicator,
};
use crate::legion::modules::services::services as services_mod;
use crate::legion::modules::threat_intel::{SecurityIndicator, Severity, ThreatIntelManager};
use crate::legion::modules::usb::usb as usb_mod;
use crate::legion::modules::vulnerabilities::vulnerabilities as vulnerabilities_mod;
use chrono::{DateTime, Utc};
use clap::{Arg, Command as ClapCommand};
use comfy_table::{presets::UTF8_FULL_CONDENSED, Attribute, Cell, Color, Table};
use serde::Serialize;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::sync::{mpsc, RwLock};

/// Security event types for active monitoring
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub enum SecurityEvent {
    SyslogEntry {
        timestamp: String,
        level: String,
        message: String,
    },
    JournalEntry {
        timestamp: String,
        unit: String,
        message: String,
    },
    NetworkAlert {
        source: String,
        signature: String,
        severity: String,
    },
    ProcessEvent {
        pid: u32,
        action: String,
        details: String,
    },
    FileEvent {
        path: String,
        action: String,
        details: String,
    },
    SystemEvent {
        category: String,
        details: HashMap<String, String>,
    },
}

const LEGION_MONITOR_STATE_PATH: &str = "/var/lib/hardn/monitor/legion_summary.json";
const CRON_SUMMARY_FILENAME: &str = "cron_summary.json";
const CRON_LOG_SUBDIR: &str = "cron";

#[derive(Debug, Serialize)]
struct LegionMonitorSnapshot {
    timestamp: DateTime<Utc>,
    risk_score: f64,
    risk_level: String,
    confidence: f64,
    risk_components: BTreeMap<String, f64>,
    metrics: LegionMonitorMetrics,
    threat_indicator_count: usize,
    threat_indicator_breakdown: BTreeMap<String, usize>,
    detected_issues: Vec<String>,
    script_alerts: Vec<String>,
    baseline: Option<LegionBaselineSummary>,
    platform_health: Vec<LegionPlatformHealth>,
}

#[derive(Debug, Serialize)]
struct LegionMonitorMetrics {
    anomaly_score: f64,
    behavioral_score: f64,
    network_score: f64,
    process_score: f64,
    file_integrity_score: f64,
    system_health_score: f64,
    memory_usage: f64,
}

#[derive(Debug, Serialize)]
struct LegionBaselineSummary {
    created_at: DateTime<Utc>,
    version: u64,
    tags: Vec<String>,
}

#[derive(Debug, Serialize)]
struct LegionPlatformHealth {
    name: String,
    service_unit: String,
    active: bool,
    enabled: bool,
    recent_warnings: u32,
    last_warning: Option<String>,
}

impl LegionMonitorSnapshot {
    fn new(
        risk_score: &RiskScore,
        system_state: &SystemState,
        baseline: Option<&BaselineSnapshot>,
    ) -> Self {
        let metrics = LegionMonitorMetrics::from(system_state);

        let mut risk_components = BTreeMap::new();
        for (component, value) in &risk_score.components {
            risk_components.insert(component.clone(), sanitize_metric(*value));
        }

        let mut threat_indicator_breakdown = BTreeMap::new();
        for indicator in &system_state.threat_indicators {
            let key = indicator.severity.clone();
            *threat_indicator_breakdown.entry(key).or_insert(0) += 1;
        }

        let script_alerts = system_state
            .script_results
            .iter()
            .filter(|result| !matches!(result.status, ScriptStatus::Success))
            .map(|result| {
                let detail = result.details.as_ref().map(|s| s.as_str()).unwrap_or("-");
                format!(
                    "{}::{} [{}] {}",
                    result.domain, result.name, result.status, detail
                )
            })
            .collect::<Vec<_>>();

        let baseline_summary = baseline.map(|snapshot| LegionBaselineSummary {
            created_at: DateTime::<Utc>::from(snapshot.created_at),
            version: snapshot.version,
            tags: snapshot.tags.clone(),
        });

        let platform_health = system_state
            .security_platforms
            .iter()
            .map(|platform| LegionPlatformHealth {
                name: platform.name.clone(),
                service_unit: platform.service_unit.clone(),
                active: platform.active,
                enabled: platform.enabled,
                recent_warnings: platform.recent_warnings,
                last_warning: platform.last_warning.clone(),
            })
            .collect();

        Self {
            timestamp: risk_score.timestamp.clone(),
            risk_score: sanitize_metric(risk_score.overall_score),
            risk_level: risk_score.risk_level.to_string(),
            confidence: sanitize_metric(risk_score.confidence),
            risk_components,
            metrics,
            threat_indicator_count: system_state.threat_indicators.len(),
            threat_indicator_breakdown,
            detected_issues: system_state.detected_issues.clone(),
            script_alerts,
            baseline: baseline_summary,
            platform_health,
        }
    }
}

impl LegionMonitorMetrics {
    fn from(system_state: &SystemState) -> Self {
        Self {
            anomaly_score: sanitize_metric(system_state.anomaly_score),
            behavioral_score: sanitize_metric(system_state.behavioral_score),
            network_score: sanitize_metric(system_state.network_score),
            process_score: sanitize_metric(system_state.process_score),
            file_integrity_score: sanitize_metric(system_state.file_integrity_score),
            system_health_score: sanitize_metric(system_state.system_health_score),
            memory_usage: sanitize_metric(system_state.memory_usage),
        }
    }
}

fn sanitize_metric(value: f64) -> f64 {
    if value.is_finite() {
        value
    } else {
        0.0
    }
}

#[derive(Debug, Clone)]
struct ReactivePlanEntry {
    pid: u32,
    process_name: String,
    behavior_score: f64,
    classification: BehaviorClassification,
    baseline_status: BaselineStatus,
    recommended: ReactiveAction,
    reason: String,
    binary_path: Option<String>,
    severity_rank: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReactiveAction {
    Block,
    Quarantine,
    Monitor,
}

#[derive(Debug, Clone)]
enum BaselineStatus {
    Matches,
    Changed { baseline_cmd: String },
    NotPresent,
    NoBaseline,
}

impl ReactivePlanEntry {
    fn severity_label(&self) -> &'static str {
        match &self.classification {
            BehaviorClassification::Malicious => "Critical",
            BehaviorClassification::Suspicious => "High",
            BehaviorClassification::Unknown => "Medium",
            BehaviorClassification::Normal => "Low",
        }
    }

    fn severity_color(&self) -> Color {
        match &self.classification {
            BehaviorClassification::Malicious => Color::Red,
            BehaviorClassification::Suspicious => Color::Yellow,
            BehaviorClassification::Unknown => Color::Blue,
            BehaviorClassification::Normal => Color::Green,
        }
    }
}

impl ReactiveAction {
    fn as_str(&self) -> &'static str {
        match self {
            ReactiveAction::Block => "Block",
            ReactiveAction::Quarantine => "Quarantine",
            ReactiveAction::Monitor => "Monitor",
        }
    }

    fn color(&self) -> Color {
        match self {
            ReactiveAction::Block => Color::Red,
            ReactiveAction::Quarantine => Color::Magenta,
            ReactiveAction::Monitor => Color::Yellow,
        }
    }

    fn rank(&self) -> u8 {
        match self {
            ReactiveAction::Block => 3,
            ReactiveAction::Quarantine => 2,
            ReactiveAction::Monitor => 1,
        }
    }
}

impl fmt::Display for ReactiveAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl BaselineStatus {
    fn label(&self) -> &'static str {
        match self {
            BaselineStatus::Matches => "Baseline",
            BaselineStatus::Changed { .. } => "Changed",
            BaselineStatus::NotPresent => "New",
            BaselineStatus::NoBaseline => "Unknown",
        }
    }
}

fn normalize_cmdline(cmdline: &str) -> String {
    cmdline
        .split_whitespace()
        .map(|chunk| chunk.trim())
        .filter(|chunk| !chunk.is_empty())
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase()
}

fn truncate_for_table(text: &str, max_chars: usize) -> String {
    if text.chars().count() <= max_chars {
        return text.to_string();
    }

    let mut result = String::with_capacity(max_chars);
    for (idx, ch) in text.chars().enumerate() {
        if idx + 1 >= max_chars {
            result.push('…');
            break;
        }
        result.push(ch);
    }
    result
}

/// LEGION - Advanced Heuristics Monitoring Script
/// Enhanced system monitoring and anomaly detection with automated response
#[derive(Debug)]
#[allow(dead_code)]
pub struct Legion {
    config: Config,
    baseline: BaselineManager,
    behavioral_analyzer: BehavioralAnalyzer,
    threat_intel: Arc<RwLock<ThreatIntelManager>>,
    response_engine: Arc<RwLock<ResponseEngine>>,
    correlation_manager: CorrelationManager,
    risk_scoring: RiskScoringManager,
    core: LegionCore,
    create_baseline: bool,
    verbose: bool,
    json_output: bool,
    daemon: bool,
    predictive_enabled: bool,
    response_enabled: bool,
    detected_issues: Vec<String>,
    // Active monitoring fields
    event_sender: Option<mpsc::UnboundedSender<SecurityEvent>>,
    monitoring_active: bool,
}

impl Legion {
    fn run_self_script<F>(
        &mut self,
        domain: &'static str,
        name: &'static str,
        description: Option<&'static str>,
        f: F,
    ) -> ScriptResult
    where
        F: FnOnce(&mut Self) -> Result<(), Box<dyn std::error::Error>>,
    {
        let start = Instant::now();
        let mut details = description.map(|d| d.to_string());
        let status = match f(self) {
            Ok(_) => ScriptStatus::Success,
            Err(err) => {
                let message = err.to_string();
                safe_println!("  ✗ {}::{} failed: {}", domain, name, message);
                details = Some(message);
                ScriptStatus::Failed
            }
        };

        ScriptResult {
            domain: domain.to_string(),
            name: name.to_string(),
            status,
            duration_ms: start.elapsed().as_millis(),
            details,
        }
    }

    fn run_external_script<F>(
        &self,
        domain: &'static str,
        name: &'static str,
        description: Option<&'static str>,
        f: F,
    ) -> ScriptResult
    where
        F: FnOnce() -> Result<(), Box<dyn std::error::Error>>,
    {
        let start = Instant::now();
        let mut details = description.map(|d| d.to_string());
        let status = match f() {
            Ok(_) => ScriptStatus::Success,
            Err(err) => {
                let message = err.to_string();
                safe_println!("  ✗ {}::{} failed: {}", domain, name, message);
                details = Some(message);
                ScriptStatus::Failed
            }
        };

        ScriptResult {
            domain: domain.to_string(),
            name: name.to_string(),
            status,
            duration_ms: start.elapsed().as_millis(),
            details,
        }
    }

    pub async fn new(
        create_baseline: bool,
        verbose: bool,
        json_output: bool,
        daemon: bool,
        predictive_enabled: bool,
        response_enabled: bool,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let config = Config::load()?;
        let baseline = BaselineManager::new(&config)?;

        // Initialize threat intelligence
        let threat_intel_path = std::path::PathBuf::from("/var/lib/hardn/legion/threat_intel.json");
        let threat_intel_manager = ThreatIntelManager::new(threat_intel_path, true);
        threat_intel_manager.initialize().await?;

        // Initialize response engine
        let quarantine_dir = std::path::PathBuf::from("/var/lib/hardn/quarantine");
        std::fs::create_dir_all(&quarantine_dir)?;
        let response_engine = ResponseEngine::new(quarantine_dir, !response_enabled);

        // Initialize correlation manager
        let correlation_manager = CorrelationManager::new(60, 1000); // 60 minutes window, 1000 max events

        // Initialize risk scoring
        let risk_scoring = RiskScoringManager::new();

        // Build the minimal sequential framework pipeline
        let core = framework_pipeline::build_default_core(baseline.snapshot(), response_enabled);

        Ok(Self {
            config,
            baseline,
            behavioral_analyzer: BehavioralAnalyzer::new(),
            threat_intel: Arc::new(RwLock::new(threat_intel_manager)),
            response_engine: Arc::new(RwLock::new(response_engine)),
            correlation_manager,
            risk_scoring,
            core,
            create_baseline,
            verbose,
            json_output,
            daemon,
            predictive_enabled,
            response_enabled,
            detected_issues: Vec::new(),
            event_sender: None,
            monitoring_active: false,
        })
    }

    pub async fn run(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        use std::{thread, time::Duration};

        if self.daemon {
            safe_println!("LEGION - Advanced Daemon Mode");
            safe_println!("============================");
            safe_println!("Running as background monitoring daemon with enhanced capabilities...");
            safe_println!("Press Ctrl+C to stop");
            safe_println!();
        } else {
            safe_println!("LEGION - Advanced Heuristics Monitoring Script");
            safe_println!("===============================================");
        }

        // Privilege check
        self.check_privileges()?;

        // Load or create baseline
        if self.create_baseline {
            safe_println!("Creating new baseline...");
            self.create_baseline()?;
        } else {
            safe_println!("Loading baseline for comparison...");
            self.load_baseline()?;
        }

        if self.daemon {
            let cron_log_root = Path::new(DEFAULT_LOG_DIR).join(CRON_LOG_SUBDIR);
            if let Err(err) = fs::create_dir_all(&cron_log_root) {
                safe_println!(
                    "Warning: unable to prepare maintenance log directory {}: {}",
                    cron_log_root.display(),
                    err
                );
            }

            let cron_state_path = Path::new(DEFAULT_LIB_DIR)
                .join("monitor")
                .join(CRON_SUMMARY_FILENAME);
            if let Some(parent) = cron_state_path.parent() {
                if let Err(err) = fs::create_dir_all(parent) {
                    safe_println!(
                        "Warning: unable to prepare maintenance state directory {}: {}",
                        parent.display(),
                        err
                    );
                }
            }

            let _cron_handle =
                CronOrchestrator::standard_profile(&cron_log_root, &cron_state_path).start();

            safe_println!(
                "Maintenance scheduler active (logs: {}, summary: {})",
                cron_log_root.display(),
                cron_state_path.display()
            );

            // Enhanced daemon mode: run checks in a loop with full capabilities
            loop {
                if self.verbose {
                    safe_println!(
                        "\n[{}] Running enhanced monitoring checks...",
                        chrono::Utc::now().format("%Y-%m-%d %H:%M:%S")
                    );
                }

                // Run comprehensive monitoring checks
                let system_state = self.run_enhanced_checks().await?;

                // Calculate risk score
                let risk_score = self.risk_scoring.calculate_risk(&system_state).await;

                if self.verbose {
                    safe_println!(
                        "Current Risk Score: {:.3} ({:?})",
                        risk_score.overall_score,
                        risk_score.risk_level
                    );
                    for factor in &risk_score.contributing_factors {
                        safe_println!("  - {}", factor);
                    }
                }

                // Execute automated responses if enabled
                if self.response_enabled && risk_score.overall_score > 0.7 {
                    self.execute_automated_response(&risk_score).await?;
                }

                // Generate enhanced report
                if let Err(e) = self
                    .generate_enhanced_report(&system_state, &risk_score)
                    .await
                {
                    safe_println!("Error generating enhanced report: {}", e);
                }

                // Write compact summary line for monitor/GUI
                let platform_summary = if system_state.security_platforms.is_empty() {
                    String::new()
                } else {
                    let details = system_state
                        .security_platforms
                        .iter()
                        .map(|entry| {
                            format!(
                                "{}:{}:{}",
                                entry.name.replace(' ', "_"),
                                if entry.active { "up" } else { "down" },
                                entry.recent_warnings
                            )
                        })
                        .collect::<Vec<_>>()
                        .join(",");
                    format!(" platforms=[{}]", details)
                };

                safe_println!(
                    "LEGION SUMMARY: risk={:.3} level={:?} indicators={} issues={}{}",
                    risk_score.overall_score,
                    risk_score.risk_level,
                    risk_score.contributing_factors.len(),
                    system_state.detected_issues.len(),
                    platform_summary
                );

                if self.verbose {
                    safe_println!(
                        "Enhanced monitoring cycle completed. Sleeping for 30 seconds..."
                    );
                }

                // Sleep for 30 seconds (more frequent for enhanced monitoring)
                thread::sleep(Duration::from_secs(30));
            }
        } else {
            // One-time enhanced mode: run checks once
            let system_state = self.run_enhanced_checks().await?;
            let risk_score = self.risk_scoring.calculate_risk(&system_state).await;

            // Generate enhanced report
            self.generate_enhanced_report(&system_state, &risk_score)
                .await?;

            safe_println!("LEGION enhanced monitoring completed successfully");
            if !system_state.security_platforms.is_empty() {
                let details = system_state
                    .security_platforms
                    .iter()
                    .map(|entry| {
                        format!(
                            "{}:{} warnings={}",
                            entry.name,
                            if entry.active { "up" } else { "down" },
                            entry.recent_warnings
                        )
                    })
                    .collect::<Vec<_>>()
                    .join(" • ");
                safe_println!("Security Platforms: {}", details);
            }

            safe_println!(
                "Overall Risk Score: {:.3} ({:?})",
                risk_score.overall_score,
                risk_score.risk_level
            );
        }

        Ok(())
    }

    fn check_privileges(&self) -> Result<(), Box<dyn std::error::Error>> {
        let uid = unsafe { libc::getuid() };
        if uid != 0 {
            safe_println!("LEGION requires root privileges for comprehensive monitoring");
            safe_println!("   Run with: sudo legion");
            process::exit(1);
        }
        Ok(())
    }

    fn create_baseline(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let baseline = Baseline::capture()?;
        self.baseline.save(&baseline)?;
        // Reload to refresh in-memory snapshot for the framework pipeline
        self.baseline.load()?;
        self.refresh_framework_baseline();
        safe_println!("Baseline created and saved");
        Ok(())
    }

    fn load_baseline(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        self.baseline.load()?;
        self.refresh_framework_baseline();
        safe_println!("Baseline loaded");
        Ok(())
    }

    fn refresh_framework_baseline(&mut self) {
        if let Some(snapshot) = self.baseline.snapshot() {
            self.core.replace_baseline(snapshot);
        } else {
            self.core.clear_baseline();
        }
    }

    fn process_framework_report(
        &mut self,
        report: &LegionCycleReport,
    ) -> (Option<f64>, Option<f64>, f64) {
        let mut cpu_usage = None;
        let mut memory_usage = None;

        for record in &report.telemetry {
            if let TelemetryPayload::Metric { name, value, .. } = &record.payload {
                match name.as_str() {
                    "cpu_usage" => cpu_usage = Some(*value),
                    "memory_usage" => memory_usage = Some(*value),
                    _ => {}
                }
            }
        }

        for finding in &report.findings {
            self.detected_issues
                .push(format!("[{:?}] {}", finding.severity, finding.summary));
        }

        let anomaly_score = if report.findings.is_empty() {
            0.0
        } else {
            let total: f64 = report
                .findings
                .iter()
                .map(|finding| Self::severity_weight(finding.severity))
                .sum();
            (total / report.findings.len() as f64).clamp(0.0, 1.0)
        };

        (cpu_usage, memory_usage, anomaly_score)
    }

    fn severity_weight(severity: FindingSeverity) -> f64 {
        match severity {
            FindingSeverity::Informational => 0.1,
            FindingSeverity::Low => 0.3,
            FindingSeverity::Medium => 0.6,
            FindingSeverity::High => 0.85,
            FindingSeverity::Critical => 1.0,
        }
    }

    fn build_reactive_plan(&self) -> Vec<ReactivePlanEntry> {
        let mut plan = Vec::new();
        let suspicious = self.behavioral_analyzer.get_suspicious_processes();
        if suspicious.is_empty() {
            return plan;
        }

        let baseline_opt = self.baseline.get_current();
        let baseline_available = baseline_opt.is_some();
        let mut baseline_cmds: HashSet<String> = HashSet::new();
        let mut baseline_name_map: HashMap<String, Vec<String>> = HashMap::new();

        if let Some(baseline) = baseline_opt {
            for proc in &baseline.processes {
                let normalized_cmd = normalize_cmdline(&proc.cmdline);
                if !normalized_cmd.is_empty() {
                    baseline_cmds.insert(normalized_cmd);
                }
                baseline_name_map
                    .entry(proc.name.to_lowercase())
                    .or_default()
                    .push(proc.cmdline.clone());
            }
        }

        for pid in suspicious {
            if let Some(behavior) = self.behavioral_analyzer.get_process_behavior(pid) {
                let classification = behavior.analyze_behavior();
                if matches!(classification, BehaviorClassification::Normal) {
                    continue;
                }

                let normalized_cmd = normalize_cmdline(&behavior.command_line);
                let name_key = behavior.name.to_lowercase();

                let baseline_status = if !baseline_available {
                    BaselineStatus::NoBaseline
                } else if !normalized_cmd.is_empty() && baseline_cmds.contains(&normalized_cmd) {
                    BaselineStatus::Matches
                } else if let Some(cmds) = baseline_name_map.get(&name_key) {
                    let baseline_cmd = cmds
                        .first()
                        .cloned()
                        .unwrap_or_else(|| "(unknown)".to_string());
                    BaselineStatus::Changed { baseline_cmd }
                } else {
                    BaselineStatus::NotPresent
                };

                let recommended = match classification {
                    BehaviorClassification::Malicious => ReactiveAction::Quarantine,
                    BehaviorClassification::Suspicious => match baseline_status {
                        BaselineStatus::NotPresent | BaselineStatus::Changed { .. } => {
                            ReactiveAction::Block
                        }
                        _ => ReactiveAction::Monitor,
                    },
                    BehaviorClassification::Unknown => ReactiveAction::Monitor,
                    BehaviorClassification::Normal => ReactiveAction::Monitor,
                };

                let reason = match &baseline_status {
                    BaselineStatus::Matches => {
                        "Baseline match flagged by heuristic analysis".to_string()
                    }
                    BaselineStatus::Changed { baseline_cmd } => format!(
                        "Baseline command differs: {}",
                        truncate_for_table(baseline_cmd, 72)
                    ),
                    BaselineStatus::NotPresent => {
                        "No matching baseline entry (new execution)".to_string()
                    }
                    BaselineStatus::NoBaseline => {
                        "Baseline unavailable; using heuristic assessment".to_string()
                    }
                };

                let binary_path = std::fs::read_link(format!("/proc/{}/exe", pid))
                    .ok()
                    .map(|p| p.to_string_lossy().to_string());

                let severity_rank = match classification {
                    BehaviorClassification::Malicious => 3,
                    BehaviorClassification::Suspicious => 2,
                    BehaviorClassification::Unknown => 1,
                    BehaviorClassification::Normal => 0,
                };

                plan.push(ReactivePlanEntry {
                    pid,
                    process_name: behavior.name.clone(),
                    behavior_score: behavior.behavior_score,
                    classification,
                    baseline_status,
                    recommended,
                    reason,
                    binary_path,
                    severity_rank,
                });
            }
        }

        plan.sort_by(|a, b| {
            b.severity_rank
                .cmp(&a.severity_rank)
                .then_with(|| b.recommended.rank().cmp(&a.recommended.rank()))
                .then_with(|| a.process_name.cmp(&b.process_name))
        });

        plan
    }

    fn render_reactive_plan_table(&self, plan: &[ReactivePlanEntry]) {
        safe_println!("\nReactive Mode Plan");
        if let Some(baseline) = self.baseline.get_current() {
            if let Some(captured_at) =
                chrono::DateTime::<chrono::Utc>::from_timestamp(baseline.timestamp as i64, 0)
            {
                safe_println!(
                    "Comparing against baseline captured {}",
                    captured_at.format("%Y-%m-%d %H:%M:%S UTC")
                );
            }
        } else {
            safe_println!("Baseline unavailable; showing heuristic deviations only.");
        }

        if plan.is_empty() {
            safe_println!("No suspicious processes require operator action.");
            return;
        }

        let mut table = Table::new();
        table.load_preset(UTF8_FULL_CONDENSED);
        table.set_header(vec![
            "#",
            "Process",
            "PID",
            "Baseline",
            "Severity",
            "Score",
            "Recommended",
            "Rationale",
        ]);

        for (idx, entry) in plan.iter().enumerate() {
            let mut severity_cell =
                Cell::new(entry.severity_label()).add_attribute(Attribute::Bold);
            severity_cell = severity_cell.fg(entry.severity_color());

            let mut recommendation_cell =
                Cell::new(entry.recommended.to_string()).add_attribute(Attribute::Bold);
            recommendation_cell = recommendation_cell.fg(entry.recommended.color());

            table.add_row(vec![
                Cell::new(format!("{}", idx + 1)).fg(Color::Cyan),
                Cell::new(truncate_for_table(&entry.process_name, 32)),
                Cell::new(format!("{}", entry.pid)),
                Cell::new(entry.baseline_status.label()),
                severity_cell,
                Cell::new(format!("{:.2}", entry.behavior_score)),
                recommendation_cell,
                Cell::new(truncate_for_table(&entry.reason, 78)),
            ]);
        }

        safe_println!("{}", table);
    }

    async fn drive_reactive_plan(
        &self,
        plan: &[ReactivePlanEntry],
    ) -> Result<(), Box<dyn std::error::Error>> {
        if plan.is_empty() {
            return Ok(());
        }

        safe_println!(
            "Review each recommendation. Confirm with 'y' to execute the suggested response."
        );

        let mut executed: Vec<String> = Vec::new();

        for entry in plan {
            let prompt = format!(
                "Apply {} for {} (pid {})? [y/N]: ",
                entry.recommended, entry.process_name, entry.pid
            );

            if Self::prompt_for_confirmation(&prompt)? {
                self.execute_reactive_action(entry).await?;
                executed.push(format!(
                    "{}:{}",
                    entry.recommended.as_str(),
                    entry.process_name
                ));
            } else {
                safe_println!(
                    "  ↳ Skipping {} (pid {}) per operator choice",
                    entry.process_name,
                    entry.pid
                );
            }
        }

        if executed.is_empty() {
            safe_println!("No reactive actions were executed.");
        } else {
            safe_println!("Executed reactive actions: {}", executed.join(", "));
        }

        Ok(())
    }

    async fn execute_reactive_action(
        &self,
        entry: &ReactivePlanEntry,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let action_context = format!(
            "Reactive plan for {} (pid {}): {}",
            entry.process_name, entry.pid, entry.reason
        );

        let engine = self.response_engine.read().await;

        match entry.recommended {
            ReactiveAction::Block => {
                let action = ResponseAction::KillProcess { pid: entry.pid };
                engine
                    .execute_manual_action(&action_context, &action)
                    .await
                    .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;
                safe_println!(
                    "  → Blocked process {} (pid {})",
                    entry.process_name,
                    entry.pid
                );
            }
            ReactiveAction::Quarantine => {
                let kill_action = ResponseAction::KillProcess { pid: entry.pid };
                engine
                    .execute_manual_action(
                        &format!("{} (terminate for quarantine)", action_context),
                        &kill_action,
                    )
                    .await
                    .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;

                if let Some(path) = &entry.binary_path {
                    let quarantine_action = ResponseAction::QuarantineFile { path: path.clone() };
                    engine
                        .execute_manual_action(
                            &format!("{} (quarantine binary)", action_context),
                            &quarantine_action,
                        )
                        .await
                        .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;
                    safe_println!(
                        "  → Quarantined binary {} for process {} (pid {})",
                        path,
                        entry.process_name,
                        entry.pid
                    );
                } else {
                    safe_println!(
                        "  → Binary path unavailable; process terminated but quarantine skipped"
                    );
                }
            }
            ReactiveAction::Monitor => {
                let action = ResponseAction::LogIncident {
                    details: format!(
                        "Monitoring {} (pid {}) after operator review",
                        entry.process_name, entry.pid
                    ),
                };
                engine
                    .execute_manual_action(&action_context, &action)
                    .await
                    .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;
                safe_println!(
                    "  → Logged monitoring action for {} (pid {})",
                    entry.process_name,
                    entry.pid
                );
            }
        }

        Ok(())
    }

    fn prompt_for_confirmation(prompt: &str) -> Result<bool, Box<dyn std::error::Error>> {
        print!("{}", prompt);
        io::stdout().flush()?;
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        let decision = input.trim().eq_ignore_ascii_case("y");
        Ok(decision)
    }

    fn run_inventory_checks(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        safe_println!("Running system inventory checks...");
        // Basic inventory checks - could be expanded
        Ok(())
    }

    fn run_auth_checks(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        safe_println!("Running authentication checks...");

        // Check for recent SSH authentication failures
        let output = std::process::Command::new("journalctl")
            .args(&["-u", "sshd", "--since", "1 hour ago", "-p", "warning..err"])
            .output()?;

        let output_str = String::from_utf8(output.stdout)?;
        let failure_count = output_str
            .lines()
            .filter(|line| {
                line.contains("Failed password") || line.contains("authentication failure")
            })
            .count();

        if failure_count > 0 {
            self.detected_issues.push(format!(
                "Found {} SSH authentication failures in last hour",
                failure_count
            ));
        }

        // Check sudoers configuration
        let sudoers_content = std::fs::read_to_string("/etc/sudoers")?;
        if sudoers_content.contains("NOPASSWD") {
            self.detected_issues
                .push("Passwordless sudo entries found".to_string());
        }

        Ok(())
    }

    fn run_package_checks(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        safe_println!("Running package integrity checks...");

        // Check for debsums availability and run basic package check
        let debsums_result = std::process::Command::new("which")
            .arg("debsums")
            .output()?;

        if debsums_result.status.success() {
            // Could run debsums here
        } else {
            self.detected_issues
                .push("debsums not available for package integrity check".to_string());
        }

        Ok(())
    }

    fn run_filesystem_checks(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        safe_println!("Running filesystem checks...");

        // Check for SUID/SGID files
        let output = std::process::Command::new("find")
            .args(&["/", "-type", "f", "-perm", "/6000", "-ls"])
            .output()?;

        let output_str = String::from_utf8(output.stdout)?;
        let suid_files: Vec<&str> = output_str.lines().collect();

        if suid_files.len() > 20 {
            // Arbitrary threshold
            self.detected_issues.push(format!(
                "Found {} SUID/SGID files in system directories",
                suid_files.len()
            ));
        }

        // Check for suspicious permissions on critical files
        let critical_files = ["/usr/bin/sudo", "/usr/bin/su"];
        for file in &critical_files {
            if let Ok(metadata) = std::fs::metadata(file) {
                use std::os::unix::fs::PermissionsExt;
                let mode = metadata.permissions().mode();
                if mode & 0o6000 != 0 {
                    self.detected_issues
                        .push(format!("{} has SUID/SGID bits", file));
                }
            }
        }

        Ok(())
    }

    fn run_kernel_checks(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        safe_println!("Running kernel checks...");

        // Check kernel modules
        let output = std::process::Command::new("lsmod").output()?;
        let output_str = String::from_utf8(output.stdout)?;
        let module_count = output_str.lines().count().saturating_sub(1); // Subtract header
        safe_println!("  Checking kernel modules...");
        safe_println!("    {} kernel modules loaded", module_count);

        // Check sysctl parameters
        let sysctl_output = std::process::Command::new("sysctl")
            .args(&["kernel.kptr_restrict"])
            .output()?;
        let sysctl_str = String::from_utf8(sysctl_output.stdout)?;
        if sysctl_str.contains("kernel.kptr_restrict = 1") {
            self.detected_issues
                .push("kernel.kptr_restrict = 1 (expected 2)".to_string());
        }

        Ok(())
    }

    fn run_container_checks(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        safe_println!("Running container checks...");

        // Check Docker
        let docker_result = std::process::Command::new("which").arg("docker").output()?;
        if docker_result.status.success() {
            let docker_ps = std::process::Command::new("docker")
                .args(&["ps", "-q"])
                .output()?;
            let container_count = String::from_utf8(docker_ps.stdout)?.lines().count();
            safe_println!("    {} Docker containers running", container_count);
        } else {
            self.detected_issues
                .push("Docker not installed".to_string());
        }

        // Check Podman
        let podman_result = std::process::Command::new("which").arg("podman").output()?;
        if !podman_result.status.success() {
            self.detected_issues
                .push("Podman not installed".to_string());
        }

        // Check build tools
        let tools = ["make", "gcc", "g++", "rustc", "python3"];
        for tool in &tools {
            let tool_result = std::process::Command::new("which").arg(tool).output()?;
            if tool_result.status.success() {
                safe_println!("    {} is available", tool);
            }
        }

        Ok(())
    }

    /// Get current CPU usage as a percentage (0.0 to 1.0)
    fn get_cpu_usage() -> Result<f64, Box<dyn std::error::Error>> {
        use std::fs;
        use std::thread;
        use std::time::Duration;

        // Read /proc/stat twice with a small delay to calculate CPU usage
        let stat1 = fs::read_to_string("/proc/stat")?;
        thread::sleep(Duration::from_millis(100));
        let stat2 = fs::read_to_string("/proc/stat")?;

        // Parse CPU line from first reading
        let cpu_line1 = stat1.lines().next().ok_or("No CPU line in /proc/stat")?;
        let parts1: Vec<&str> = cpu_line1.split_whitespace().collect();
        if parts1.len() < 8 || parts1[0] != "cpu" {
            return Err("Invalid CPU line format".into());
        }
        let user1: u64 = parts1[1].parse()?;
        let nice1: u64 = parts1[2].parse()?;
        let system1: u64 = parts1[3].parse()?;
        let idle1: u64 = parts1[4].parse()?;
        let iowait1: u64 = parts1[5].parse()?;
        let irq1: u64 = parts1[6].parse()?;
        let softirq1: u64 = parts1[7].parse()?;
        let total1 = user1 + nice1 + system1 + idle1 + iowait1 + irq1 + softirq1;

        // Parse CPU line from second reading
        let cpu_line2 = stat2.lines().next().ok_or("No CPU line in /proc/stat")?;
        let parts2: Vec<&str> = cpu_line2.split_whitespace().collect();
        if parts2.len() < 8 || parts2[0] != "cpu" {
            return Err("Invalid CPU line format".into());
        }
        let user2: u64 = parts2[1].parse()?;
        let nice2: u64 = parts2[2].parse()?;
        let system2: u64 = parts2[3].parse()?;
        let idle2: u64 = parts2[4].parse()?;
        let iowait2: u64 = parts2[5].parse()?;
        let irq2: u64 = parts2[6].parse()?;
        let softirq2: u64 = parts2[7].parse()?;
        let total2 = user2 + nice2 + system2 + idle2 + iowait2 + irq2 + softirq2;

        // Calculate usage
        let total_diff = total2 - total1;
        let idle_diff = idle2 - idle1;
        if total_diff == 0 {
            return Ok(0.0);
        }
        let usage = (total_diff - idle_diff) as f64 / total_diff as f64;
        Ok(usage.min(1.0).max(0.0)) // Clamp to 0.0-1.0
    }

    /// Get current memory usage as a percentage (0.0 to 1.0)
    fn get_memory_usage() -> Result<f64, Box<dyn std::error::Error>> {
        use std::fs;
        let meminfo = fs::read_to_string("/proc/meminfo")?;
        let mut total = 0u64;
        let mut available = 0u64;

        for line in meminfo.lines() {
            if line.starts_with("MemTotal:") {
                if let Some(val) = line.split_whitespace().nth(1) {
                    total = val.parse()?;
                }
            } else if line.starts_with("MemAvailable:") {
                if let Some(val) = line.split_whitespace().nth(1) {
                    available = val.parse()?;
                }
            }
        }

        if total == 0 {
            return Ok(0.0);
        }

        let used = total - available;
        Ok(used as f64 / total as f64)
    }

    async fn run_enhanced_checks(&mut self) -> Result<SystemState, Box<dyn std::error::Error>> {
        safe_println!("Running enhanced system checks...");

        // Clear previous issues
        self.detected_issues.clear();

        self.refresh_framework_baseline();

        let mut anomaly_score = 0.0;
        let mut cpu_usage_metric: Option<f64> = None;
        let mut memory_usage_metric: Option<f64> = None;

        let mut script_results: Vec<ScriptResult> = Vec::new();
        let mut security_platforms: Vec<SecurityPlatformStatus> = Vec::new();

        let framework_start = Instant::now();
        match self.core.run_cycle() {
            Ok(report) => {
                let (cpu_opt, mem_opt, anomaly) = self.process_framework_report(&report);
                cpu_usage_metric = cpu_opt;
                memory_usage_metric = mem_opt;
                anomaly_score = anomaly;

                if self.verbose {
                    safe_println!(
                        "Framework cycle: telemetry={} findings={} responses={} latency={}ms",
                        report.telemetry.len(),
                        report.findings.len(),
                        report.responses.len(),
                        report.duration.as_millis()
                    );
                }

                script_results.push(ScriptResult {
                    domain: "Core".to_string(),
                    name: "Framework Pipeline".to_string(),
                    status: ScriptStatus::Success,
                    duration_ms: framework_start.elapsed().as_millis(),
                    details: Some(format!(
                        "telemetry: {} • findings: {} • responses: {}",
                        report.telemetry.len(),
                        report.findings.len(),
                        report.responses.len()
                    )),
                });
            }
            Err(e) => {
                safe_println!("Framework pipeline error: {}", e);
                script_results.push(ScriptResult {
                    domain: "Core".to_string(),
                    name: "Framework Pipeline".to_string(),
                    status: ScriptStatus::Failed,
                    duration_ms: framework_start.elapsed().as_millis(),
                    details: Some(e.to_string()),
                });
            }
        }

        // Run traditional checks
        script_results.push(self.run_self_script(
            "Core",
            "Inventory Checks",
            Some("System inventory sweep"),
            |legion| legion.run_inventory_checks(),
        ));
        script_results.push(self.run_self_script(
            "Core",
            "Authentication Checks",
            Some("SSH and sudo policy audit"),
            |legion| legion.run_auth_checks(),
        ));
        script_results.push(self.run_self_script(
            "Core",
            "Package Checks",
            Some("Package integrity verification"),
            |legion| legion.run_package_checks(),
        ));
        script_results.push(self.run_self_script(
            "Core",
            "Filesystem Checks",
            Some("Filesystem anomaly scan"),
            |legion| legion.run_filesystem_checks(),
        ));

        {
            let start = Instant::now();
            let description = "Behavioral process analysis";
            let mut details = Some(description.to_string());
            let status = match self.run_enhanced_process_checks().await {
                Ok(_) => ScriptStatus::Success,
                Err(err) => {
                    let message = err.to_string();
                    safe_println!("  ✗ Core::Process Analysis failed: {}", message);
                    details = Some(message);
                    ScriptStatus::Failed
                }
            };

            script_results.push(ScriptResult {
                domain: "Core".to_string(),
                name: "Process Analysis".to_string(),
                status,
                duration_ms: start.elapsed().as_millis(),
                details,
            });
        }

        {
            let start = Instant::now();
            let description = "Network socket intelligence";
            let mut details = Some(description.to_string());
            let status = match self.run_enhanced_network_checks().await {
                Ok(_) => ScriptStatus::Success,
                Err(err) => {
                    let message = err.to_string();
                    safe_println!("  ✗ Core::Network Analysis failed: {}", message);
                    details = Some(message);
                    ScriptStatus::Failed
                }
            };

            script_results.push(ScriptResult {
                domain: "Core".to_string(),
                name: "Network Analysis".to_string(),
                status,
                duration_ms: start.elapsed().as_millis(),
                details,
            });
        }

        script_results.push(self.run_self_script(
            "Core",
            "Kernel Checks",
            Some("Kernel module and sysctl review"),
            |legion| legion.run_kernel_checks(),
        ));
        script_results.push(self.run_self_script(
            "Core",
            "Container Checks",
            Some("Container and toolchain audit"),
            |legion| legion.run_container_checks(),
        ));

        // Module scripts
        script_results.push(self.run_external_script(
            "Auth",
            "Authentication Failures",
            Some("Journalctl SSH failure review"),
            auth_mod::check_auth_failures,
        ));
        script_results.push(self.run_external_script(
            "Auth",
            "Sudoers Configuration",
            Some("Sudoers policy diff"),
            auth_mod::check_sudoers_changes,
        ));
        script_results.push(self.run_external_script(
            "Auth",
            "SSH Configuration",
            Some("SSH hardening verification"),
            auth_mod::check_ssh_config,
        ));

        script_results.push(self.run_external_script(
            "Inventory",
            "System Information",
            Some("OS and kernel fingerprint"),
            inventory_mod::check_system_info,
        ));
        script_results.push(self.run_external_script(
            "Inventory",
            "Hardware Information",
            Some("Hardware inventory summary"),
            inventory_mod::check_hardware_info,
        ));

        script_results.push(self.run_external_script(
            "Packages",
            "Package Drift",
            Some("Debsums drift analysis"),
            packages_mod::check_package_drift,
        ));
        script_results.push(self.run_external_script(
            "Packages",
            "Binary Integrity",
            Some("Critical binary permission check"),
            packages_mod::check_binary_integrity,
        ));

        script_results.push(self.run_external_script(
            "Filesystem",
            "SUID/SGID Files",
            Some("SUID/SGID sweep"),
            filesystem_mod::check_suid_sgid_files,
        ));
        script_results.push(self.run_external_script(
            "Filesystem",
            "Startup Persistence",
            Some("Startup persistence audit"),
            filesystem_mod::check_startup_persistence,
        ));

        script_results.push(self.run_external_script(
            "Processes",
            "Orphan Processes",
            Some("Orphan process hunter"),
            processes_mod::check_orphan_processes,
        ));
        script_results.push(self.run_external_script(
            "Processes",
            "Suspicious Executables",
            Some("Temporary executable scan"),
            processes_mod::check_suspicious_executables,
        ));

        script_results.push(self.run_external_script(
            "Network",
            "Listening Sockets",
            Some("Listening sockets census"),
            network_mod::check_listening_sockets,
        ));
        script_results.push(self.run_external_script(
            "Network",
            "Firewall Rules",
            Some("Firewall posture review"),
            network_mod::check_firewall_rules,
        ));

        script_results.push(self.run_external_script(
            "Permissions",
            "World-writable Files",
            Some("World-writable audit"),
            permissions_mod::check_world_writable_files,
        ));
        script_results.push(self.run_external_script(
            "Permissions",
            "SUID/SGID Permissions",
            Some("SUID/SGID permission map"),
            permissions_mod::check_suid_sgid_permissions,
        ));
        script_results.push(self.run_external_script(
            "Permissions",
            "File Ownership",
            Some("Orphan ownership sweep"),
            permissions_mod::check_file_ownership,
        ));
        script_results.push(self.run_external_script(
            "Permissions",
            "Directory Permissions",
            Some("Critical directory permissions"),
            permissions_mod::check_directory_permissions,
        ));
        script_results.push(self.run_external_script(
            "Permissions",
            "Permission Anomalies",
            Some("Permission anomaly detection"),
            permissions_mod::detect_permission_anomalies,
        ));

        script_results.push(self.run_external_script(
            "Services",
            "Service Status",
            Some("Service state census"),
            services_mod::check_service_status,
        ));
        script_results.push(self.run_external_script(
            "Services",
            "Critical Services",
            Some("Critical service health"),
            services_mod::check_critical_services,
        ));
        script_results.push(self.run_external_script(
            "Services",
            "Service Anomalies",
            Some("Service anomaly detection"),
            services_mod::detect_service_anomalies,
        ));
        script_results.push(self.run_external_script(
            "Services",
            "Service Dependencies",
            Some("Dependency graph scan"),
            services_mod::check_service_dependencies,
        ));
        script_results.push(self.run_external_script(
            "Services",
            "Service Security",
            Some("Service security posture"),
            services_mod::check_service_security,
        ));

        {
            let start = Instant::now();
            let mut details = None;
            let status = match self.collect_security_platform_status() {
                Ok(statuses) => {
                    if !statuses.is_empty() {
                        let summary = statuses
                            .iter()
                            .map(|entry| {
                                format!(
                                    "{}:{} warnings={}",
                                    entry.name,
                                    if entry.active { "up" } else { "down" },
                                    entry.recent_warnings
                                )
                            })
                            .collect::<Vec<_>>()
                            .join(" • ");
                        details = Some(summary);
                    }
                    security_platforms = statuses;
                    ScriptStatus::Success
                }
                Err(err) => {
                    let message = err.to_string();
                    details = Some(message.clone());
                    ScriptStatus::Failed
                }
            };

            script_results.push(ScriptResult {
                domain: "Services".to_string(),
                name: "Security Platforms".to_string(),
                status,
                duration_ms: start.elapsed().as_millis(),
                details,
            });
        }

        script_results.push(self.run_external_script(
            "Memory",
            "Memory Usage",
            Some("Memory usage profile"),
            memory_mod::check_memory_usage,
        ));
        script_results.push(self.run_external_script(
            "Memory",
            "Swap Usage",
            Some("Swap configuration review"),
            memory_mod::check_swap_usage,
        ));
        script_results.push(self.run_external_script(
            "Memory",
            "Memory Anomalies",
            Some("Memory anomaly detection"),
            memory_mod::detect_memory_anomalies,
        ));

        script_results.push(self.run_external_script(
            "Logs",
            "System Logs",
            Some("System log triage"),
            logs_mod::check_system_logs,
        ));
        script_results.push(self.run_external_script(
            "Logs",
            "Log Integrity",
            Some("Log integrity review"),
            logs_mod::check_log_integrity,
        ));
        script_results.push(self.run_external_script(
            "Logs",
            "Log Manipulation",
            Some("Log manipulation scan"),
            logs_mod::detect_log_manipulation,
        ));

        script_results.push(self.run_external_script(
            "Containers",
            "Docker Posture",
            Some("Docker posture review"),
            containers_mod::check_docker_containers,
        ));
        script_results.push(self.run_external_script(
            "Containers",
            "Podman Posture",
            Some("Podman posture review"),
            containers_mod::check_podman_containers,
        ));
        script_results.push(self.run_external_script(
            "Containers",
            "Build Tools",
            Some("Build toolchain inventory"),
            containers_mod::check_build_tools,
        ));

        script_results.push(self.run_external_script(
            "Kernel",
            "Kernel Modules",
            Some("Kernel module sweep"),
            kernel_mod::check_kernel_modules,
        ));
        script_results.push(self.run_external_script(
            "Kernel",
            "Sysctl Parameters",
            Some("Sysctl policy audit"),
            kernel_mod::check_sysctl_params,
        ));

        script_results.push(self.run_external_script(
            "USB",
            "USB Devices",
            Some("USB device census"),
            usb_mod::check_usb_devices,
        ));
        script_results.push(self.run_external_script(
            "USB",
            "USB Storage",
            Some("USB storage audit"),
            usb_mod::check_usb_storage,
        ));
        script_results.push(self.run_external_script(
            "USB",
            "USB Anomalies",
            Some("USB anomaly detection"),
            usb_mod::detect_usb_anomalies,
        ));
        script_results.push(self.run_external_script(
            "USB",
            "USB History",
            Some("USB history review"),
            usb_mod::check_usb_history,
        ));

        script_results.push(self.run_external_script(
            "Vulnerabilities",
            "Kernel Version",
            Some("Kernel CVE posture"),
            vulnerabilities_mod::check_kernel_version,
        ));
        script_results.push(self.run_external_script(
            "Vulnerabilities",
            "Package Updates",
            Some("Package update backlog"),
            vulnerabilities_mod::check_package_updates,
        ));
        script_results.push(self.run_external_script(
            "Vulnerabilities",
            "CVE Database",
            Some("Local CVE database check"),
            vulnerabilities_mod::check_cve_database,
        ));
        script_results.push(self.run_external_script(
            "Vulnerabilities",
            "Security Policies",
            Some("Security policy audit"),
            vulnerabilities_mod::check_security_policies,
        ));
        script_results.push(self.run_external_script(
            "Vulnerabilities",
            "Vulnerable Services",
            Some("Vulnerable service sweep"),
            vulnerabilities_mod::detect_vulnerable_services,
        ));
        script_results.push(self.run_external_script(
            "Vulnerabilities",
            "File Integrity",
            Some("File integrity coverage"),
            vulnerabilities_mod::check_file_integrity,
        ));

        script_results.push(self.run_external_script(
            "Crypto",
            "SSL Certificates",
            Some("Certificate inventory"),
            crypto_mod::check_ssl_certificates,
        ));
        script_results.push(self.run_external_script(
            "Crypto",
            "Encrypted Filesystems",
            Some("Encrypted filesystem audit"),
            crypto_mod::check_encrypted_filesystems,
        ));
        script_results.push(self.run_external_script(
            "Crypto",
            "GPG Keys",
            Some("GPG key inventory"),
            crypto_mod::check_gpg_keys,
        ));
        script_results.push(self.run_external_script(
            "Crypto",
            "Crypto Anomalies",
            Some("Cryptography anomaly scan"),
            crypto_mod::detect_crypto_anomalies,
        ));

        // Get threat indicators
        let threat_indicators = self.check_threat_indicators().await?;

        // Calculate behavioral score
        let behavioral_score = self.behavioral_analyzer.get_overall_threat_score();

        // Resolve CPU usage metric, falling back to the legacy probe if the framework pipeline could not collect it.
        let cpu_usage = match cpu_usage_metric {
            Some(value) => value,
            None => match Self::get_cpu_usage() {
                Ok(usage) => usage,
                Err(e) => {
                    safe_println!("Warning: Failed to get CPU usage: {}", e);
                    0.0
                }
            },
        };

        // Resolve memory usage metric using the same preference order.
        let memory_usage = match memory_usage_metric {
            Some(value) => value,
            None => match Self::get_memory_usage() {
                Ok(usage) => usage,
                Err(e) => {
                    safe_println!("Warning: Failed to get memory usage: {}", e);
                    0.0
                }
            },
        };

        Ok(SystemState {
            timestamp: chrono::Utc::now(),
            anomaly_score,
            threat_indicators,
            behavioral_score,
            network_score: 0.0, // TODO: Implement network scoring
            process_score: behavioral_score,
            file_integrity_score: 0.0, // TODO: Implement file integrity scoring
            system_health_score: cpu_usage,
            memory_usage,
            detected_issues: self.detected_issues.clone(),
            script_results,
            security_platforms,
        })
    }

    async fn run_enhanced_process_checks(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        safe_println!("Running enhanced process checks with behavioral analysis...");

        // Get process list
        let output = tokio::process::Command::new("ps")
            .args(&["-eo", "pid,ppid,cmd"])
            .output()
            .await?;

        let output_str = String::from_utf8(output.stdout)?;
        for line in output_str.lines().skip(1) {
            // Skip header
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 3 {
                if let Ok(pid) = parts[0].parse::<u32>() {
                    let cmd = parts[2..].join(" ");
                    let behavior = ProcessBehavior::new(
                        pid,
                        parts.get(2).unwrap_or(&"unknown").to_string(),
                        cmd,
                    );
                    let classification = self.behavioral_analyzer.analyze_process(pid, behavior);

                    if self.verbose && classification != BehaviorClassification::Normal {
                        safe_println!("Process {} classified as {:?}", pid, classification);
                    }
                }
            }
        }

        Ok(())
    }

    async fn run_enhanced_network_checks(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        safe_println!("Running enhanced network checks with threat intelligence...");

        // Get network connections
        let output = tokio::process::Command::new("netstat")
            .args(&["-tuln"])
            .output()
            .await?;

        let output_str = String::from_utf8(output.stdout)?;
        for line in output_str.lines() {
            if line.contains("LISTEN") {
                // Extract IP and port
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 4 {
                    let local_addr = parts[3];
                    if let Some((ip, port)) = self.parse_address(local_addr) {
                        // Check against threat intelligence
                        let threat_level = self
                            .threat_intel
                            .read()
                            .await
                            .check_threat(&SecurityIndicator::Ip(ip))
                            .await;
                        if threat_level.level != Severity::Low && self.verbose {
                            safe_println!(
                                "Threat detected for {}:{} - {:?}",
                                ip,
                                port,
                                threat_level.level
                            );
                        }
                    }
                }
            }
        }

        Ok(())
    }

    fn collect_security_platform_status(
        &mut self,
    ) -> Result<Vec<SecurityPlatformStatus>, Box<dyn std::error::Error>> {
        let platforms = vec![
            ("Grafana", "grafana-server.service"),
            ("Wazuh Agent", "wazuh-agent.service"),
        ];

        let mut statuses = Vec::new();

        for (name, unit) in platforms {
            let active = Command::new("systemctl")
                .args(&["is-active", unit])
                .output()
                .map(|output| output.status.success())
                .unwrap_or(false);

            let enabled = Command::new("systemctl")
                .args(&["is-enabled", unit])
                .output()
                .map(|output| output.status.success())
                .unwrap_or(false);

            let journal_output = Command::new("journalctl")
                .args(&[
                    "-u",
                    unit,
                    "--since",
                    "1 hour ago",
                    "-p",
                    "warning..alert",
                    "--no-pager",
                ])
                .output();

            let (recent_warnings, last_warning) = match journal_output {
                Ok(output) if output.status.success() => {
                    let raw = String::from_utf8_lossy(&output.stdout);
                    let lines: Vec<&str> =
                        raw.lines().filter(|line| !line.trim().is_empty()).collect();
                    let count = lines.len() as u32;
                    let last = lines.last().map(|line| line.trim().to_string());
                    (count, last)
                }
                _ => (0, None),
            };

            if !active {
                self.detected_issues
                    .push(format!("{} service ({}) is not active", name, unit));
            }

            if recent_warnings > 0 {
                self.detected_issues.push(format!(
                    "{} reported {} warnings in the last hour",
                    name, recent_warnings
                ));
            }

            statuses.push(SecurityPlatformStatus {
                name: name.to_string(),
                service_unit: unit.to_string(),
                active,
                enabled,
                recent_warnings,
                last_warning,
            });
        }

        Ok(statuses)
    }

    fn parse_address(&self, addr: &str) -> Option<(std::net::IpAddr, u16)> {
        let parts: Vec<&str> = addr.split(':').collect();
        if parts.len() == 2 {
            if let (Ok(ip), Ok(port)) = (
                parts[0].parse::<std::net::IpAddr>(),
                parts[1].parse::<u16>(),
            ) {
                return Some((ip, port));
            }
        }
        None
    }

    async fn check_threat_indicators(
        &self,
    ) -> Result<Vec<RiskThreatIndicator>, Box<dyn std::error::Error>> {
        let mut indicators = Vec::new();

        // Check running processes for known malware
        let suspicious_processes = self.behavioral_analyzer.get_suspicious_processes();
        for &pid in &suspicious_processes {
            if let Some(_behavior) = self.behavioral_analyzer.get_process_behavior(pid) {
                indicators.push(RiskThreatIndicator {
                    indicator_type: "suspicious_process".to_string(),
                    severity: "medium".to_string(),
                    confidence: 0.7,
                    source: "behavioral_analysis".to_string(),
                });
            }
        }

        // Check for threat intelligence matches
        // This would be expanded with actual threat intel checks

        Ok(indicators)
    }

    async fn execute_automated_response(
        &self,
        risk_score: &RiskScore,
    ) -> Result<(), Box<dyn std::error::Error>> {
        if risk_score.overall_score < 0.8 {
            return Ok(());
        }

        safe_println!(
            "High risk detected ({}), executing automated response...",
            risk_score.risk_level
        );

        let anomaly = Anomaly {
            anomaly_type: "high_risk_score".to_string(),
            severity: format!("{:?}", risk_score.risk_level),
            score: risk_score.overall_score,
            description: format!("High risk score detected: {:.3}", risk_score.overall_score),
            indicators: risk_score.contributing_factors.clone(),
        };

        let response_engine = self.response_engine.read().await;
        let actions_taken = response_engine.execute_response(&anomaly).await?;

        if self.verbose {
            safe_println!(
                "Executed {} automated response actions",
                actions_taken.len()
            );
            for action in &actions_taken {
                safe_println!("  - {:?}", action);
            }
        }

        Ok(())
    }

    fn persist_monitor_snapshot(
        &self,
        system_state: &SystemState,
        risk_score: &RiskScore,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let snapshot = LegionMonitorSnapshot::new(risk_score, system_state, self.core.baseline());
        let path = Path::new(LEGION_MONITOR_STATE_PATH);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        let tmp_path = path
            .parent()
            .map(|dir| dir.join("legion_summary.json.tmp"))
            .unwrap_or_else(|| Path::new("legion_summary.json.tmp").to_path_buf());

        let data = serde_json::to_vec_pretty(&snapshot)?;
        fs::write(&tmp_path, &data)?;
        let _ = fs::set_permissions(&tmp_path, fs::Permissions::from_mode(0o640));
        fs::rename(&tmp_path, path)?;

        Ok(())
    }

    async fn generate_enhanced_report(
        &self,
        system_state: &SystemState,
        risk_score: &RiskScore,
    ) -> Result<(), Box<dyn std::error::Error>> {
        safe_println!("Generating enhanced monitoring report...");

        let mut sanitized_system_state = system_state.clone();
        sanitized_system_state.anomaly_score =
            sanitize_metric(sanitized_system_state.anomaly_score);
        sanitized_system_state.behavioral_score =
            sanitize_metric(sanitized_system_state.behavioral_score);
        sanitized_system_state.network_score =
            sanitize_metric(sanitized_system_state.network_score);
        sanitized_system_state.process_score =
            sanitize_metric(sanitized_system_state.process_score);
        sanitized_system_state.file_integrity_score =
            sanitize_metric(sanitized_system_state.file_integrity_score);
        sanitized_system_state.system_health_score =
            sanitize_metric(sanitized_system_state.system_health_score);
        sanitized_system_state.memory_usage = sanitize_metric(sanitized_system_state.memory_usage);

        if self.json_output {
            let mut risk_components = BTreeMap::new();
            for (component, value) in &risk_score.components {
                risk_components.insert(component.clone(), sanitize_metric(*value));
            }

            let report = serde_json::json!({
                "timestamp": risk_score.timestamp,
                "risk_score": sanitize_metric(risk_score.overall_score),
                "risk_level": risk_score.risk_level,
                "confidence": sanitize_metric(risk_score.confidence),
                "contributing_factors": risk_score.contributing_factors,
                "risk_components": risk_components,
                "system_state": sanitized_system_state,
            });
            safe_println!("{}", serde_json::to_string_pretty(&report)?);
        } else {
            safe_println!("=== LEGION MONITORING REPORT ===");
            safe_println!("Timestamp: {}", risk_score.timestamp);
            safe_println!(
                "Risk Score: {:.3} ({})  •  Confidence: {:.3}",
                sanitize_metric(risk_score.overall_score),
                risk_score.risk_level,
                sanitize_metric(risk_score.confidence)
            );
            safe_println!(
                "System Health → CPU: {:.1}% | Memory: {:.1}% | Behavioral: {:.3} | Anomaly: {:.3}",
                sanitized_system_state.system_health_score * 100.0,
                sanitized_system_state.memory_usage * 100.0,
                sanitized_system_state.behavioral_score,
                sanitized_system_state.anomaly_score
            );
            safe_println!(
                "Threat Indicators observed: {}",
                sanitized_system_state.threat_indicators.len()
            );
            safe_println!();

            let mut component_rows: Vec<_> = risk_score.components.iter().collect();
            component_rows.sort_by(|a, b| a.0.cmp(b.0));
            if !component_rows.is_empty() {
                let mut component_table = Table::new();
                component_table.load_preset(UTF8_FULL_CONDENSED);
                component_table.set_header(vec!["Component", "Score"]);
                for (component, score) in component_rows {
                    component_table.add_row(vec![
                        Cell::new(component.as_str()).fg(Color::Cyan),
                        Cell::new(format!("{:.3}", sanitize_metric(*score))),
                    ]);
                }
                safe_println!("Component Breakdown:");
                safe_println!("{}", component_table);
                safe_println!();
            }

            let mut script_table = Table::new();
            script_table.load_preset(UTF8_FULL_CONDENSED);
            script_table.set_header(vec!["Domain", "Script", "Status", "Duration", "Details"]);
            for result in &sanitized_system_state.script_results {
                let mut status_cell =
                    Cell::new(result.status.to_string()).add_attribute(Attribute::Bold);
                status_cell = match result.status {
                    ScriptStatus::Success => status_cell.fg(Color::Green),
                    ScriptStatus::Warning => status_cell.fg(Color::Yellow),
                    ScriptStatus::Failed => status_cell.fg(Color::Red),
                };

                script_table.add_row(vec![
                    Cell::new(result.domain.as_str()).fg(Color::Cyan),
                    Cell::new(result.name.as_str()),
                    status_cell,
                    Cell::new(format!("{} ms", result.duration_ms)),
                    Cell::new(result.details.clone().unwrap_or_else(|| "-".to_string())),
                ]);
            }
            safe_println!("Script Execution Summary:");
            safe_println!("{}", script_table);
            safe_println!();

            if !risk_score.contributing_factors.is_empty() {
                let mut factor_table = Table::new();
                factor_table.load_preset(UTF8_FULL_CONDENSED);
                factor_table.set_header(vec!["#", "Factor"]);
                for (idx, factor) in risk_score.contributing_factors.iter().enumerate() {
                    factor_table.add_row(vec![
                        Cell::new(format!("{}", idx + 1)),
                        Cell::new(factor.as_str()),
                    ]);
                }
                safe_println!("Contributing Factors:");
                safe_println!("{}", factor_table);
                safe_println!();
            }

            if !sanitized_system_state.detected_issues.is_empty() {
                let mut issue_table = Table::new();
                issue_table.load_preset(UTF8_FULL_CONDENSED);
                issue_table.set_header(vec!["#", "Detected Issue"]);
                for (idx, issue) in sanitized_system_state.detected_issues.iter().enumerate() {
                    issue_table.add_row(vec![
                        Cell::new(format!("{}", idx + 1)).fg(Color::Yellow),
                        Cell::new(issue.as_str()),
                    ]);
                }
                safe_println!("Detected Issues:");
                safe_println!("{}", issue_table);
            }

            if !self.daemon {
                let plan = self.build_reactive_plan();
                self.render_reactive_plan_table(&plan);
                if self.response_enabled {
                    self.drive_reactive_plan(&plan).await?;
                } else if !plan.is_empty() {
                    safe_println!(
                        "Response engine disabled; review the plan above to take manual action."
                    );
                }
            }
        }

        if let Err(err) = self.persist_monitor_snapshot(&sanitized_system_state, risk_score) {
            safe_println!("Failed to persist monitor snapshot: {}", err);
        }

        Ok(())
    }

    /// Start active monitoring with real-time log analysis and automated response
    pub async fn start_active_monitoring(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        if self.monitoring_active {
            return Ok(());
        }

        safe_println!("Starting active monitoring mode with automated response...");

        // Create event channel for inter-task communication
        let (tx, mut rx) = mpsc::unbounded_channel::<SecurityEvent>();
        self.event_sender = Some(tx.clone());
        self.monitoring_active = true;

        // Start log monitoring tasks
        let syslog_handle = tokio::spawn(Self::monitor_syslog(tx.clone()));
        let journal_handle = tokio::spawn(Self::monitor_journal(tx.clone()));
        let network_handle = tokio::spawn(Self::monitor_network(tx.clone()));
        let process_handle = tokio::spawn(Self::monitor_processes(tx.clone()));

        // Start event processing task
        let event_processor = tokio::spawn(async move {
            while let Some(event) = rx.recv().await {
                Self::process_security_event(event).await;
            }
        });

        // Wait for all monitoring tasks
        let _ = tokio::try_join!(
            syslog_handle,
            journal_handle,
            network_handle,
            process_handle
        );
        let _ = event_processor.await;

        Ok(())
    }

    /// Monitor syslog for security events
    async fn monitor_syslog(
        sender: mpsc::UnboundedSender<SecurityEvent>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let syslog_paths = ["/var/log/syslog", "/var/log/messages"];
        let mut file = None;

        for path in &syslog_paths {
            if let Ok(f) = tokio::fs::File::open(path).await {
                file = Some(f);
                break;
            }
        }

        if let Some(file) = file {
            let reader = BufReader::new(file);
            let mut lines = reader.lines();

            while let Some(line) = lines.next_line().await? {
                if let Some(event) = Self::parse_syslog_line(&line) {
                    let _ = sender.send(event);
                }
                tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
            }
        }

        Ok(())
    }

    /// Monitor systemd journal for security events
    async fn monitor_journal(
        sender: mpsc::UnboundedSender<SecurityEvent>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut cmd = tokio::process::Command::new("journalctl")
            .args(&["--follow", "--lines", "0", "-t", "kernel", "-t", "systemd"])
            .stdout(std::process::Stdio::piped())
            .spawn()?;

        if let Some(stdout) = cmd.stdout.take() {
            let reader = BufReader::new(stdout);
            let mut lines = reader.lines();

            while let Some(line) = lines.next_line().await? {
                if let Some(event) = Self::parse_journal_line(&line) {
                    let _ = sender.send(event);
                }
            }
        }

        Ok(())
    }

    /// Monitor network telemetry directly and surface suspicious activity
    async fn monitor_network(
        sender: mpsc::UnboundedSender<SecurityEvent>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut interval = tokio::time::interval(Duration::from_secs(30));
        let mut last_alerts: HashMap<String, Instant> = HashMap::new();
        let debounce_window = Duration::from_secs(300);

        loop {
            interval.tick().await;
            let loop_start = Instant::now();
            last_alerts.retain(|_, instant| {
                loop_start.duration_since(*instant) < Duration::from_secs(900)
            });

            let output = tokio::process::Command::new("ss")
                .args(&["-tunaH"])
                .output()
                .await;

            let output = match output {
                Ok(out) => out,
                Err(_) => {
                    // If ss is unavailable, wait for the next interval
                    continue;
                }
            };

            if !output.status.success() {
                continue;
            }

            let stdout = String::from_utf8_lossy(&output.stdout);
            let mut connection_counts: HashMap<String, usize> = HashMap::new();

            for line in stdout.lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() < 5 {
                    continue;
                }

                let state = parts[0];
                let local_addr = parts[3];
                let remote_addr = parts[4];

                let local = Self::extract_address(local_addr);
                let remote = Self::extract_address(remote_addr);

                let mut reasons: Vec<String> = Vec::new();
                let mut connection_key = String::new();

                if let Some((_, local_port)) = local {
                    if state == "LISTEN" && Self::is_sensitive_port(local_port) {
                        reasons.push(format!("listener on sensitive port {}", local_port));
                    } else if state == "LISTEN" && local_port >= 49152 {
                        reasons.push(format!("listener on high ephemeral port {}", local_port));
                    }
                }

                if let Some((remote_host, remote_port)) = &remote {
                    connection_key = format!("{}:{}", remote_host, remote_port);

                    if Self::is_sensitive_port(*remote_port) {
                        reasons.push(format!("remote port {}", remote_port));
                    }

                    if Self::is_bogon_address(remote_host) {
                        reasons.push("bogon remote address".to_string());
                    }
                } else if state == "LISTEN" {
                    if let Some((_, local_port)) = local {
                        connection_key = format!("*:{}", local_port);
                    }
                }

                if state == "SYN-SENT" || state == "SYN-RECV" {
                    reasons.push(format!("connection state {}", state));
                }

                if reasons.is_empty() {
                    continue;
                }

                if connection_key.is_empty() {
                    connection_key = format!("{}:{}", local_addr, remote_addr);
                }

                let occurrences = connection_counts
                    .entry(connection_key.clone())
                    .and_modify(|c| *c += 1)
                    .or_insert(1);

                let signature = format!(
                    "{} {} -> {} [{}]",
                    state,
                    local_addr,
                    remote_addr,
                    reasons.join(", ")
                );

                let now = Instant::now();
                let should_emit = match last_alerts.get(&signature) {
                    Some(previous) => now.duration_since(*previous) > debounce_window,
                    None => true,
                };

                if should_emit {
                    last_alerts.insert(signature.clone(), now);
                    let severity = Self::network_severity(*occurrences, reasons.len());
                    let event = SecurityEvent::NetworkAlert {
                        source: "legion-network-sensor".to_string(),
                        signature,
                        severity,
                    };
                    let _ = sender.send(event);
                }
            }
        }
    }

    /// Monitor process events
    async fn monitor_processes(
        sender: mpsc::UnboundedSender<SecurityEvent>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Use inotify or periodic checks for process monitoring
        loop {
            // Check for suspicious processes
            let output = tokio::process::Command::new("ps")
                .args(&["-eo", "pid,ppid,cmd"])
                .output()
                .await?;

            let output_str = String::from_utf8(output.stdout)?;
            for line in output_str.lines().skip(1) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 3 {
                    if let Ok(pid) = parts[0].parse::<u32>() {
                        // Check against known suspicious patterns
                        let cmd = parts[2..].join(" ");
                        if Self::is_suspicious_process(&cmd) {
                            let event = SecurityEvent::ProcessEvent {
                                pid,
                                action: "detected".to_string(),
                                details: format!("Suspicious process: {}", cmd),
                            };
                            let _ = sender.send(event);
                        }
                    }
                }
            }

            tokio::time::sleep(tokio::time::Duration::from_secs(30)).await;
        }
    }

    /// Process security events and take automated actions
    async fn process_security_event(event: SecurityEvent) {
        match event {
            SecurityEvent::SyslogEntry {
                timestamp,
                level,
                message,
            } => {
                if level == "CRITICAL" || level == "ALERT" || message.contains("attack") {
                    safe_println!(
                        "🚨 CRITICAL SYSLOG EVENT [{}]: {} - {}",
                        timestamp,
                        level,
                        message
                    );
                    // Trigger automated response
                }
            }
            SecurityEvent::JournalEntry {
                timestamp,
                unit,
                message,
            } => {
                if message.contains("failed") || message.contains("denied") {
                    safe_println!(
                        "⚠️  SECURITY JOURNAL EVENT [{}@{}]: {}",
                        timestamp,
                        unit,
                        message
                    );
                }
            }
            SecurityEvent::NetworkAlert {
                source,
                signature,
                severity,
            } => {
                safe_println!(
                    "🌐 NETWORK ALERT [{}] from {}: {}",
                    severity,
                    source,
                    signature
                );
                if severity == "high" || severity == "critical" {
                    // Block offending IP, isolate process, etc.
                }
            }
            SecurityEvent::ProcessEvent {
                pid,
                action,
                details,
            } => {
                safe_println!("🔍 SUSPICIOUS PROCESS {} [{}]: {}", pid, action, details);
                // Kill process, quarantine, alert
            }
            SecurityEvent::FileEvent {
                path,
                action,
                details,
            } => {
                safe_println!("📁 FILE EVENT {} on {}: {}", action, path, details);
            }
            SecurityEvent::SystemEvent { category, details } => {
                safe_println!("⚙️  SYSTEM EVENT [{}]: {:?}", category, details);
            }
        }
    }

    /// Parse syslog line into security event
    fn parse_syslog_line(line: &str) -> Option<SecurityEvent> {
        // Basic syslog parsing - extract timestamp, level, message
        if line.contains("attack") || line.contains("intrusion") || line.contains("breach") {
            Some(SecurityEvent::SyslogEntry {
                timestamp: "now".to_string(),
                level: "WARNING".to_string(),
                message: line.to_string(),
            })
        } else {
            None
        }
    }

    /// Parse journalctl line into security event
    fn parse_journal_line(line: &str) -> Option<SecurityEvent> {
        if line.contains("Failed") || line.contains("denied") || line.contains("blocked") {
            Some(SecurityEvent::JournalEntry {
                timestamp: "now".to_string(),
                unit: "systemd".to_string(),
                message: line.to_string(),
            })
        } else {
            None
        }
    }

    fn extract_address(addr: &str) -> Option<(String, u16)> {
        let trimmed = addr.trim();
        if trimmed.is_empty() || trimmed == "*" || trimmed == "*:*" {
            return None;
        }

        if let Some((host_part, port_part)) = trimmed.rsplit_once(':') {
            if port_part.is_empty() || port_part == "*" {
                return None;
            }

            if let Ok(port) = port_part.parse::<u16>() {
                let host = host_part.trim_matches(['[', ']'].as_ref()).to_string();
                return Some((host, port));
            }
        }

        None
    }

    fn is_bogon_address(addr: &str) -> bool {
        addr == "0.0.0.0"
            || addr == "::"
            || addr == "::1"
            || addr.starts_with("127.")
            || addr.starts_with("169.254.")
    }

    fn is_sensitive_port(port: u16) -> bool {
        matches!(
            port,
            21 | 22
                | 23
                | 69
                | 135
                | 139
                | 445
                | 3389
                | 4444
                | 4445
                | 4555
                | 47123
                | 5000
                | 5555
                | 5900
                | 5985
                | 5986
                | 6667
                | 6668
                | 6669
                | 8080
                | 8222
                | 8443
                | 9000
                | 31337
                | 49152
                | 49153
                | 49154
                | 49155
        )
    }

    fn network_severity(occurrences: usize, reason_count: usize) -> String {
        if occurrences >= 5 || reason_count >= 3 {
            "high".to_string()
        } else if occurrences >= 3 || reason_count == 2 {
            "medium".to_string()
        } else {
            "low".to_string()
        }
    }

    /// Check if process command looks suspicious
    fn is_suspicious_process(cmd: &str) -> bool {
        let suspicious_patterns = [
            "nc ",
            "netcat",
            "ncat",
            "socat",
            "cryptominer",
            "miner",
            "backdoor",
            "trojan",
            "wget http",
            "curl http",
        ];

        suspicious_patterns
            .iter()
            .any(|pattern| cmd.contains(pattern))
    }
}

/// Public async function to run LEGION with command line arguments
#[allow(dead_code)]
pub async fn run_with_args(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    // Check for help and version flags manually since we're in a library context
    if args.contains(&"--help".to_string()) || args.contains(&"-h".to_string()) {
        use std::io::{self, Write};
        let mut cmd = ClapCommand::new("hardn legion")
            .version("2.0")
            .author("Security International Group")
            .about("Advanced system monitoring and anomaly detection with automated response")
            .long_about("LEGION performs comprehensive system monitoring and anomaly detection.\n\n\
                         Enhanced with behavioral analysis, threat intelligence,\n\
                         automated response, incident correlation, and real-time risk scoring.\n\n\
                         EXAMPLES:\n\
                         \thardn legion --create-baseline    # Create initial system baseline\n\
                         \thardn legion --response-enabled   # Enable automated response\n\
                         \thardn legion --predictive         # Enable predictive analysis\n\
                         \thardn legion --verbose            # Run with detailed output\n\
                         \thardn legion --daemon             # Run as background monitoring daemon\n\
                         \thardn legion --json               # Output results in JSON format\n\n\
                         LEGION requires root privileges for comprehensive monitoring.\n\
                         Run with: sudo hardn legion")
            .arg(
                Arg::new("create-baseline")
                    .long("create-baseline")
                    .help("Create a new baseline instead of comparing against existing one")
                    .long_help("Creates a new baseline of the current system state. This baseline\n\
                               will be saved and used for future comparisons. Run this on a\n\
                               known-good system state.")
                    .action(clap::ArgAction::SetTrue),
            )
            .arg(
                Arg::new("predictive")
                    .long("predictive")
                    .help("Enable predictive threat analysis")
                    .long_help("Enables predictive analysis to forecast potential security issues\n\
                               based on system trends and historical data.")
                    .action(clap::ArgAction::SetTrue),
            )
            .arg(
                Arg::new("response-enabled")
                    .long("response-enabled")
                    .help("Enable automated response capabilities")
                    .long_help("Enables automated response system that can take actions like\n\
                               isolating processes, blocking network connections, and quarantining files.")
                    .action(clap::ArgAction::SetTrue),
            )
            .arg(
                Arg::new("verbose")
                    .short('v')
                    .long("verbose")
                    .help("Enable verbose output")
                    .long_help("Show detailed information about each check being performed,\n\
                               including intermediate results and debugging information.")
                    .action(clap::ArgAction::SetTrue),
            )
            .arg(
                Arg::new("daemon")
                    .long("daemon")
                    .help("Run as background monitoring daemon")
                    .long_help("Runs LEGION as a background daemon that continuously monitors\n\
                               the system and logs anomalies. Use with --verbose for detailed\n\
                               monitoring output. The daemon will run indefinitely until stopped.")
                    .action(clap::ArgAction::SetTrue),
            )
            .arg(
                Arg::new("json")
                    .long("json")
                    .help("Output results in JSON format")
                    .long_help("Format output as JSON instead of human-readable text.\n\
                               Useful for integration with other tools and automated processing.")
                    .action(clap::ArgAction::SetTrue),
            );
        let mut stdout = io::stdout();
        let _ = cmd.write_long_help(&mut stdout);
        let _ = writeln!(stdout);
        return Ok(());
    } else if args.contains(&"--version".to_string()) || args.contains(&"-V".to_string()) {
        use std::io::{self, Write};
        let mut stdout = io::stdout();
        let _ = writeln!(
            stdout,
            "hardn legion 2.0 - Enhanced with ML and Automated Response"
        );
        return Ok(());
    }

    let matches = ClapCommand::new("hardn legion")
        .version("2.0")
        .author("HARDN Security Team")
        .about("Advanced system monitoring and anomaly detection with automated response")
        .long_about("LEGION performs comprehensive system monitoring and anomaly detection.\n\n\
                     Enhanced with behavioral analysis, threat intelligence,\n\
                     automated response, incident correlation, and real-time risk scoring.\n\n\
                     EXAMPLES:\n\
                     \thardn legion --create-baseline    # Create initial system baseline\n\
                     \thardn legion --response-enabled   # Enable automated response\n\
                     \thardn legion --predictive         # Enable predictive analysis\n\
                     \thardn legion --verbose            # Run with detailed output\n\
                     \thardn legion --json               # Output results in JSON format\n\n\
                     LEGION requires root privileges for comprehensive monitoring.\n\
                     Run with: sudo hardn legion")
        .arg(
            Arg::new("create-baseline")
                .long("create-baseline")
                .help("Create a new baseline instead of comparing against existing one")
                .long_help("Creates a new baseline of the current system state. This baseline\n\
                           will be saved and used for future comparisons. Run this on a\n\
                           known-good system state.")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("predictive")
                .long("predictive")
                .help("Enable predictive threat analysis")
                .long_help("Enables predictive analysis to forecast potential security issues\n\
                           based on system trends and historical data.")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("response-enabled")
                .long("response-enabled")
                .help("Enable automated response capabilities")
                .long_help("Enables automated response system that can take actions like\n\
                           isolating processes, blocking network connections, and quarantining files.")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("verbose")
                .short('v')
                .long("verbose")
                .help("Enable verbose output")
                .long_help("Show detailed information about each check being performed,\n\
                           including intermediate results and debugging information.")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("daemon")
                .long("daemon")
                .help("Run as background monitoring daemon")
                .long_help("Runs LEGION as a background daemon that continuously monitors\n\
                           the system and logs anomalies. Use with --verbose for detailed\n\
                           monitoring output. The daemon will run indefinitely until stopped.")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("json")
                .long("json")
                .help("Output results in JSON format")
                .long_help("Format output as JSON instead of human-readable text.\n\
                           Useful for integration with other tools and automated processing.")
                .action(clap::ArgAction::SetTrue),
        )
        .get_matches_from(&["hardn legion".to_string()].iter().chain(args.iter()).cloned().collect::<Vec<_>>());

    let create_baseline = matches.get_flag("create-baseline");
    let predictive_enabled = matches.get_flag("predictive");
    let response_enabled = matches.get_flag("response-enabled");
    let verbose = matches.get_flag("verbose");
    let daemon = matches.get_flag("daemon");
    let json_output = matches.get_flag("json");

    let mut legion = Legion::new(
        create_baseline,
        verbose,
        json_output,
        daemon,
        predictive_enabled,
        response_enabled,
    )
    .await?;

    // Start active monitoring if response is enabled
    if response_enabled {
        legion.start_active_monitoring().await?;
    }

    legion.run().await
}
