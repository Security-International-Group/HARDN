use std::process;
use std::time::Instant;

// Import from sibling modules in the legion crate
use super::baseline::{Baseline, BaselineManager};
use super::config::Config;
use super::framework::{FindingSeverity, LegionCore, LegionCycleReport, TelemetryPayload};
use super::framework_pipeline;
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
use crate::legion::modules::response::{Anomaly, ResponseEngine};
use crate::legion::modules::risk_scoring::{
    RiskScore, RiskScoringManager, ScriptResult, ScriptStatus, SystemState,
    ThreatIndicator as RiskThreatIndicator,
};
use crate::legion::modules::services::services as services_mod;
use crate::legion::modules::threat_intel::{SecurityIndicator, Severity, ThreatIntelManager};
use crate::legion::modules::usb::usb as usb_mod;
use crate::legion::modules::vulnerabilities::vulnerabilities as vulnerabilities_mod;
use clap::{Arg, Command};
use comfy_table::{presets::UTF8_FULL_CONDENSED, Attribute, Cell, Color, Table};
use std::collections::HashMap;
use std::sync::Arc;
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
                safe_println!(
                    "LEGION SUMMARY: risk={:.3} level={:?} indicators={} issues={}",
                    risk_score.overall_score,
                    risk_score.risk_level,
                    risk_score.contributing_factors.len(),
                    system_state.detected_issues.len()
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

    async fn generate_enhanced_report(
        &self,
        system_state: &SystemState,
        risk_score: &RiskScore,
    ) -> Result<(), Box<dyn std::error::Error>> {
        safe_println!("Generating enhanced monitoring report...");

        if self.json_output {
            // Sanitize floats for JSON serialization
            let sanitized_system_state = SystemState {
                timestamp: system_state.timestamp,
                anomaly_score: if system_state.anomaly_score.is_finite() {
                    system_state.anomaly_score
                } else {
                    0.0
                },
                threat_indicators: system_state.threat_indicators.clone(),
                behavioral_score: if system_state.behavioral_score.is_finite() {
                    system_state.behavioral_score
                } else {
                    0.0
                },
                network_score: if system_state.network_score.is_finite() {
                    system_state.network_score
                } else {
                    0.0
                },
                process_score: if system_state.process_score.is_finite() {
                    system_state.process_score
                } else {
                    0.0
                },
                file_integrity_score: if system_state.file_integrity_score.is_finite() {
                    system_state.file_integrity_score
                } else {
                    0.0
                },
                system_health_score: if system_state.system_health_score.is_finite() {
                    system_state.system_health_score
                } else {
                    0.0
                },
                memory_usage: if system_state.memory_usage.is_finite() {
                    system_state.memory_usage
                } else {
                    0.0
                },
                detected_issues: system_state.detected_issues.clone(),
                script_results: system_state.script_results.clone(),
            };
            let report = serde_json::json!({
                "timestamp": risk_score.timestamp,
                "risk_score": if risk_score.overall_score.is_finite() { risk_score.overall_score } else { 0.0 },
                "risk_level": risk_score.risk_level,
                "contributing_factors": risk_score.contributing_factors,
                "system_state": sanitized_system_state,
                "confidence": if risk_score.confidence.is_finite() { risk_score.confidence } else { 0.0 }
            });
            safe_println!("{}", serde_json::to_string_pretty(&report)?);
        } else {
            safe_println!("=== LEGION MONITORING REPORT ===");
            safe_println!("Timestamp: {}", risk_score.timestamp);
            safe_println!(
                "Risk Score: {:.3} ({})  •  Confidence: {:.3}",
                risk_score.overall_score,
                risk_score.risk_level,
                risk_score.confidence
            );
            safe_println!(
                "System Health → CPU: {:.1}% | Memory: {:.1}% | Behavioral: {:.3} | Anomaly: {:.3}",
                system_state.system_health_score * 100.0,
                system_state.memory_usage * 100.0,
                system_state.behavioral_score,
                system_state.anomaly_score
            );
            safe_println!(
                "Threat Indicators observed: {}",
                system_state.threat_indicators.len()
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
                        Cell::new(format!("{:.3}", score)),
                    ]);
                }
                safe_println!("Component Breakdown:");
                safe_println!("{}", component_table);
                safe_println!();
            }

            let mut script_table = Table::new();
            script_table.load_preset(UTF8_FULL_CONDENSED);
            script_table.set_header(vec!["Domain", "Script", "Status", "Duration", "Details"]);
            for result in &system_state.script_results {
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

            if !system_state.detected_issues.is_empty() {
                let mut issue_table = Table::new();
                issue_table.load_preset(UTF8_FULL_CONDENSED);
                issue_table.set_header(vec!["#", "Detected Issue"]);
                for (idx, issue) in system_state.detected_issues.iter().enumerate() {
                    issue_table.add_row(vec![
                        Cell::new(format!("{}", idx + 1)).fg(Color::Yellow),
                        Cell::new(issue.as_str()),
                    ]);
                }
                safe_println!("Detected Issues:");
                safe_println!("{}", issue_table);
            }
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

    /// Monitor network traffic and Suricata alerts
    async fn monitor_network(
        sender: mpsc::UnboundedSender<SecurityEvent>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Monitor Suricata logs if available
        let suricata_paths = ["/var/log/suricata/fast.log", "/var/log/suricata/eve.json"];

        for path in &suricata_paths {
            if tokio::fs::metadata(path).await.is_ok() {
                let file = tokio::fs::File::open(path).await?;
                let reader = BufReader::new(file);
                let mut lines = reader.lines();

                while let Some(line) = lines.next_line().await? {
                    if let Some(event) = Self::parse_suricata_line(&line) {
                        let _ = sender.send(event);
                    }
                }
            }
        }

        Ok(())
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

    /// Parse Suricata alert line
    fn parse_suricata_line(line: &str) -> Option<SecurityEvent> {
        if line.contains("alert") || line.contains("threat") {
            Some(SecurityEvent::NetworkAlert {
                source: "suricata".to_string(),
                signature: line.to_string(),
                severity: "medium".to_string(),
            })
        } else {
            None
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
        let mut cmd = Command::new("hardn legion")
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

    let matches = Command::new("hardn legion")
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
