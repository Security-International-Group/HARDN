use std::process;

// Import from sibling modules in the legion crate
use super::config::Config;
use super::baseline::{Baseline, BaselineManager};
use super::behavioral::{BehavioralAnalyzer, ProcessBehavior, BehaviorClassification};
use super::threat_intel::{ThreatIntelManager, SecurityIndicator};
use super::response::{ResponseEngine, Anomaly};
use super::correlation::{CorrelationManager};
use super::risk_scoring::{RiskScoringManager, RiskScore, SystemState, ThreatIndicator as RiskThreatIndicator};
use clap::{Command, Arg};
use std::sync::Arc;
use tokio::sync::{RwLock, mpsc};
use tokio::io::{AsyncBufReadExt, BufReader};
use std::collections::HashMap;

/// Security event types for active monitoring
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub enum SecurityEvent {
    SyslogEntry { timestamp: String, level: String, message: String },
    JournalEntry { timestamp: String, unit: String, message: String },
    NetworkAlert { source: String, signature: String, severity: String },
    ProcessEvent { pid: u32, action: String, details: String },
    FileEvent { path: String, action: String, details: String },
    SystemEvent { category: String, details: HashMap<String, String> },
}

macro_rules! safe_println {
    () => {{
        use std::io::{self, Write};
        if let Err(e) = writeln!(io::stdout()) {
            if e.kind() == io::ErrorKind::BrokenPipe {
                std::process::exit(0);
            } else {
                let _ = writeln!(io::stderr(), "Write error: {}", e);
            }
        }
    }};
    ($($arg:tt)*) => {{
        use std::io::{self, Write};
        if let Err(e) = writeln!(io::stdout(), $($arg)*) {
            if e.kind() == io::ErrorKind::BrokenPipe {
                std::process::exit(0);
            } else {
                let _ = writeln!(io::stderr(), "Write error: {}", e);
            }
        }
    }};
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
    pub async fn new(create_baseline: bool, verbose: bool, json_output: bool, daemon: bool, predictive_enabled: bool, response_enabled: bool) -> Result<Self, Box<dyn std::error::Error>> {
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

        Ok(Self {
            config,
            baseline,
            behavioral_analyzer: BehavioralAnalyzer::new(),
            threat_intel: Arc::new(RwLock::new(threat_intel_manager)),
            response_engine: Arc::new(RwLock::new(response_engine)),
            correlation_manager,
            risk_scoring,
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
                    safe_println!("\n[{}] Running enhanced monitoring checks...", chrono::Utc::now().format("%Y-%m-%d %H:%M:%S"));
                }

                // Run comprehensive monitoring checks
                let system_state = self.run_enhanced_checks().await?;

                // Calculate risk score
                let risk_score = self.risk_scoring.calculate_risk(&system_state).await;

                if self.verbose {
                    safe_println!("Current Risk Score: {:.3} ({:?})", risk_score.overall_score, risk_score.risk_level);
                    for factor in &risk_score.contributing_factors {
                        safe_println!("  - {}", factor);
                    }
                }

                // Execute automated responses if enabled
                if self.response_enabled && risk_score.overall_score > 0.7 {
                    self.execute_automated_response(&risk_score).await?;
                }

                // Generate enhanced report
                if let Err(e) = self.generate_enhanced_report(&system_state, &risk_score).await {
                    safe_println!("Error generating enhanced report: {}", e);
                }

                if self.verbose {
                    safe_println!("Enhanced monitoring cycle completed. Sleeping for 30 seconds...");
                }

                // Sleep for 30 seconds (more frequent for enhanced monitoring)
                thread::sleep(Duration::from_secs(30));
            }
        } else {
            // One-time enhanced mode: run checks once
            let system_state = self.run_enhanced_checks().await?;
            let risk_score = self.risk_scoring.calculate_risk(&system_state).await;

            // Generate enhanced report
            self.generate_enhanced_report(&system_state, &risk_score).await?;

            safe_println!("LEGION enhanced monitoring completed successfully");
            safe_println!("Overall Risk Score: {:.3} ({:?})", risk_score.overall_score, risk_score.risk_level);
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
        safe_println!("Baseline created and saved");
        Ok(())
    }

    fn load_baseline(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        self.baseline.load()?;
        safe_println!("Baseline loaded");
        Ok(())
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
        let failure_count = output_str.lines()
            .filter(|line| line.contains("Failed password") || line.contains("authentication failure"))
            .count();
        
        if failure_count > 0 {
            self.detected_issues.push(format!("Found {} SSH authentication failures in last hour", failure_count));
        }
        
        // Check sudoers configuration
        let sudoers_content = std::fs::read_to_string("/etc/sudoers")?;
        if sudoers_content.contains("NOPASSWD") {
            self.detected_issues.push("Passwordless sudo entries found".to_string());
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
            self.detected_issues.push("debsums not available for package integrity check".to_string());
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
        
        if suid_files.len() > 20 {  // Arbitrary threshold
            self.detected_issues.push(format!("Found {} SUID/SGID files in system directories", suid_files.len()));
        }
        
        // Check for suspicious permissions on critical files
        let critical_files = ["/usr/bin/sudo", "/usr/bin/su"];
        for file in &critical_files {
            if let Ok(metadata) = std::fs::metadata(file) {
                use std::os::unix::fs::PermissionsExt;
                let mode = metadata.permissions().mode();
                if mode & 0o6000 != 0 {
                    self.detected_issues.push(format!("{} has SUID/SGID bits", file));
                }
            }
        }
        
        Ok(())
    }

    fn run_kernel_checks(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        safe_println!("Running kernel checks...");
        
        // Check kernel modules
        let output = std::process::Command::new("lsmod")
            .output()?;
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
            self.detected_issues.push("kernel.kptr_restrict = 1 (expected 2)".to_string());
        }
        
        Ok(())
    }

    fn run_container_checks(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        safe_println!("Running container checks...");
        
        // Check Docker
        let docker_result = std::process::Command::new("which")
            .arg("docker")
            .output()?;
        if docker_result.status.success() {
            let docker_ps = std::process::Command::new("docker")
                .args(&["ps", "-q"])
                .output()?;
            let container_count = String::from_utf8(docker_ps.stdout)?
                .lines()
                .count();
            safe_println!("    {} Docker containers running", container_count);
        } else {
            self.detected_issues.push("Docker not installed".to_string());
        }
        
        // Check Podman
        let podman_result = std::process::Command::new("which")
            .arg("podman")
            .output()?;
        if !podman_result.status.success() {
            self.detected_issues.push("Podman not installed".to_string());
        }
        
        // Check build tools
        let tools = ["make", "gcc", "g++", "rustc", "python3"];
        for tool in &tools {
            let tool_result = std::process::Command::new("which")
                .arg(tool)
                .output()?;
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

        // Run traditional checks
        if let Err(e) = self.run_inventory_checks() {
            safe_println!("Error in inventory checks: {}", e);
        }
        if let Err(e) = self.run_auth_checks() {
            safe_println!("Error in auth checks: {}", e);
        }
        if let Err(e) = self.run_package_checks() {
            safe_println!("Error in package checks: {}", e);
        }
        if let Err(e) = self.run_filesystem_checks() {
            safe_println!("Error in filesystem checks: {}", e);
        }

        // Enhanced process checks with behavioral analysis
        self.run_enhanced_process_checks().await?;

        // Enhanced network checks with threat intelligence
        self.run_enhanced_network_checks().await?;

        if let Err(e) = self.run_kernel_checks() {
            safe_println!("Error in kernel checks: {}", e);
        }
        if let Err(e) = self.run_container_checks() {
            safe_println!("Error in container checks: {}", e);
        }

        // Calculate simple anomaly score based on system metrics
        let anomaly_score = 0.0; // Simplified - no ML anomaly detection

        // Get threat indicators
        let threat_indicators = self.check_threat_indicators().await?;

        // Calculate behavioral score
        let behavioral_score = self.behavioral_analyzer.get_overall_threat_score();

        // Get actual CPU usage
        let cpu_usage = match Self::get_cpu_usage() {
            Ok(usage) => usage,
            Err(e) => {
                safe_println!("Warning: Failed to get CPU usage: {}", e);
                0.0
            }
        };

        // Get actual memory usage
        let memory_usage = match Self::get_memory_usage() {
            Ok(usage) => usage,
            Err(e) => {
                safe_println!("Warning: Failed to get memory usage: {}", e);
                0.0
            }
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
        for line in output_str.lines().skip(1) { // Skip header
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 3 {
                if let Ok(pid) = parts[0].parse::<u32>() {
                    let cmd = parts[2..].join(" ");
                    let behavior = ProcessBehavior::new(pid, parts.get(2).unwrap_or(&"unknown").to_string(), cmd);
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
                        let threat_level = self.threat_intel.read().await.check_threat(&SecurityIndicator::Ip(ip)).await;
                        if threat_level.level != super::threat_intel::Severity::Low && self.verbose {
                            safe_println!("Threat detected for {}:{} - {:?}", ip, port, threat_level.level);
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
            if let (Ok(ip), Ok(port)) = (parts[0].parse::<std::net::IpAddr>(), parts[1].parse::<u16>()) {
                return Some((ip, port));
            }
        }
        None
    }

    async fn check_threat_indicators(&self) -> Result<Vec<RiskThreatIndicator>, Box<dyn std::error::Error>> {
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

    async fn execute_automated_response(&self, risk_score: &RiskScore) -> Result<(), Box<dyn std::error::Error>> {
        if risk_score.overall_score < 0.8 {
            return Ok(());
        }

        safe_println!("High risk detected ({}), executing automated response...", risk_score.risk_level);

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
            safe_println!("Executed {} automated response actions", actions_taken.len());
            for action in &actions_taken {
                safe_println!("  - {:?}", action);
            }
        }

        Ok(())
    }

    async fn generate_enhanced_report(&self, system_state: &SystemState, risk_score: &RiskScore) -> Result<(), Box<dyn std::error::Error>> {
        safe_println!("Generating enhanced monitoring report...");

        if self.json_output {
            // Sanitize floats for JSON serialization
            let sanitized_system_state = SystemState {
                timestamp: system_state.timestamp,
                anomaly_score: if system_state.anomaly_score.is_finite() { system_state.anomaly_score } else { 0.0 },
                threat_indicators: system_state.threat_indicators.clone(),
                behavioral_score: if system_state.behavioral_score.is_finite() { system_state.behavioral_score } else { 0.0 },
                network_score: if system_state.network_score.is_finite() { system_state.network_score } else { 0.0 },
                process_score: if system_state.process_score.is_finite() { system_state.process_score } else { 0.0 },
                file_integrity_score: if system_state.file_integrity_score.is_finite() { system_state.file_integrity_score } else { 0.0 },
                system_health_score: if system_state.system_health_score.is_finite() { system_state.system_health_score } else { 0.0 },
                memory_usage: if system_state.memory_usage.is_finite() { system_state.memory_usage } else { 0.0 },
                detected_issues: system_state.detected_issues.clone(),
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
            safe_println!("Risk Score: {:.3} ({:?})", risk_score.overall_score, risk_score.risk_level);
            safe_println!("Confidence: {:.3}", risk_score.confidence);
            safe_println!();
            safe_println!("Contributing Factors:");
            for factor in &risk_score.contributing_factors {
                safe_println!("  - {}", factor);
            }
            safe_println!();
            safe_println!("System State:");
            safe_println!("  CPU Usage: {:.1}%", system_state.system_health_score * 100.0);
            safe_println!("  Memory Usage: {:.1}%", system_state.memory_usage * 100.0);
            safe_println!("  Anomaly Score: {:.3}", system_state.anomaly_score);
            safe_println!("  Behavioral Score: {:.3}", system_state.behavioral_score);
            safe_println!("  Threat Indicators: {}", system_state.threat_indicators.len());
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
        let _ = tokio::try_join!(syslog_handle, journal_handle, network_handle, process_handle);
        let _ = event_processor.await;

        Ok(())
    }

    /// Monitor syslog for security events
    async fn monitor_syslog(sender: mpsc::UnboundedSender<SecurityEvent>) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
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
    async fn monitor_journal(sender: mpsc::UnboundedSender<SecurityEvent>) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
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
    async fn monitor_network(sender: mpsc::UnboundedSender<SecurityEvent>) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
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
    async fn monitor_processes(sender: mpsc::UnboundedSender<SecurityEvent>) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
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
            SecurityEvent::SyslogEntry { timestamp, level, message } => {
                if level == "CRITICAL" || level == "ALERT" || message.contains("attack") {
                    safe_println!("🚨 CRITICAL SYSLOG EVENT [{}]: {} - {}", timestamp, level, message);
                    // Trigger automated response
                }
            }
            SecurityEvent::JournalEntry { timestamp, unit, message } => {
                if message.contains("failed") || message.contains("denied") {
                    safe_println!("⚠️  SECURITY JOURNAL EVENT [{}@{}]: {}", timestamp, unit, message);
                }
            }
            SecurityEvent::NetworkAlert { source, signature, severity } => {
                safe_println!("🌐 NETWORK ALERT [{}] from {}: {}", severity, source, signature);
                if severity == "high" || severity == "critical" {
                    // Block offending IP, isolate process, etc.
                }
            }
            SecurityEvent::ProcessEvent { pid, action, details } => {
                safe_println!("🔍 SUSPICIOUS PROCESS {} [{}]: {}", pid, action, details);
                // Kill process, quarantine, alert
            }
            SecurityEvent::FileEvent { path, action, details } => {
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
            "nc ", "netcat", "ncat", "socat",
            "cryptominer", "miner",
            "backdoor", "trojan",
            "wget http", "curl http",
        ];

        suspicious_patterns.iter().any(|pattern| cmd.contains(pattern))
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
        let _ = writeln!(stdout, "hardn legion 2.0 - Enhanced with ML and Automated Response");
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

    let mut legion = Legion::new(create_baseline, verbose, json_output, daemon, predictive_enabled, response_enabled).await?;

    // Start active monitoring if response is enabled
    if response_enabled {
        legion.start_active_monitoring().await?;
    }

    legion.run().await
}