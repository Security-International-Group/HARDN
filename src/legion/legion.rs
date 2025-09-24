use std::process;

// Import from sibling modules in the legion crate
use super::config::Config;
use super::baseline::{Baseline, BaselineManager};
use super::ml_baseline::{MLBaselineManager, SystemSnapshot};
use super::behavioral::{BehavioralAnalyzer, ProcessBehavior, BehaviorClassification};
use super::threat_intel::{ThreatIntelManager, SecurityIndicator};
use super::response::{ResponseEngine, Anomaly};
use super::correlation::{CorrelationManager};
use super::risk_scoring::{RiskScoringManager, RiskScore, SystemState, ThreatIndicator as RiskThreatIndicator};
use clap::{Command, Arg};
use std::sync::Arc;
use tokio::sync::RwLock;

/// LEGION - Advanced Heuristics Monitoring Script
/// Enhanced system monitoring and anomaly detection with ML and automated response
#[derive(Debug)]
#[allow(dead_code)]
pub struct Legion {
    config: Config,
    baseline: BaselineManager,
    ml_baseline: Option<MLBaselineManager>,
    behavioral_analyzer: BehavioralAnalyzer,
    threat_intel: Arc<RwLock<ThreatIntelManager>>,
    response_engine: Arc<RwLock<ResponseEngine>>,
    correlation_manager: CorrelationManager,
    risk_scoring: RiskScoringManager,
    create_baseline: bool,
    verbose: bool,
    json_output: bool,
    daemon: bool,
    ml_enabled: bool,
    predictive_enabled: bool,
    response_enabled: bool,
}

#[allow(dead_code)]
impl Legion {
    pub async fn new(create_baseline: bool, verbose: bool, json_output: bool, daemon: bool, ml_enabled: bool, predictive_enabled: bool, response_enabled: bool) -> Result<Self, Box<dyn std::error::Error>> {
        let config = Config::load()?;
        let baseline = BaselineManager::new(&config)?;

        // Initialize ML baseline if enabled
        let ml_baseline = if ml_enabled {
            let mut manager = MLBaselineManager::new(std::path::PathBuf::from("/var/lib/hardn/legion/ml_baseline.json"));
            manager.load_model()?;
            Some(manager)
        } else {
            None
        };

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
            ml_baseline,
            behavioral_analyzer: BehavioralAnalyzer::new(),
            threat_intel: Arc::new(RwLock::new(threat_intel_manager)),
            response_engine: Arc::new(RwLock::new(response_engine)),
            correlation_manager,
            risk_scoring,
            create_baseline,
            verbose,
            json_output,
            daemon,
            ml_enabled,
            predictive_enabled,
            response_enabled,
        })
    }

    pub async fn run(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        use std::{thread, time::Duration};

        if self.daemon {
            println!("LEGION - Advanced Daemon Mode");
            println!("============================");
            println!("Running as background monitoring daemon with enhanced capabilities...");
            println!("Press Ctrl+C to stop");
            println!();
        } else {
            println!("LEGION - Advanced Heuristics Monitoring Script");
            println!("===============================================");
        }

        // Privilege check
        self.check_privileges()?;

        // Initialize ML training data collection if enabled
        if self.ml_enabled && self.ml_baseline.is_none() {
            println!("Collecting initial training data for ML baseline...");
            self.collect_training_data().await?;
        }

        // Load or create baseline
        if self.create_baseline {
            println!("Creating new baseline...");
            self.create_baseline()?;
        } else {
            println!("Loading baseline for comparison...");
            self.load_baseline()?;
        }

        if self.daemon {
            // Enhanced daemon mode: run checks in a loop with full capabilities
            loop {
                if self.verbose {
                    println!("\n[{}] Running enhanced monitoring checks...", chrono::Utc::now().format("%Y-%m-%d %H:%M:%S"));
                }

                // Run comprehensive monitoring checks
                let system_state = self.run_enhanced_checks().await?;

                // Calculate risk score
                let risk_score = self.risk_scoring.calculate_risk(&system_state).await;

                if self.verbose {
                    println!("Current Risk Score: {:.3} ({:?})", risk_score.overall_score, risk_score.risk_level);
                    for factor in &risk_score.contributing_factors {
                        println!("  - {}", factor);
                    }
                }

                // Execute automated responses if enabled
                if self.response_enabled && risk_score.overall_score > 0.7 {
                    self.execute_automated_response(&risk_score).await?;
                }

                // Generate enhanced report
                if let Err(e) = self.generate_enhanced_report(&system_state, &risk_score).await {
                    eprintln!("Error generating enhanced report: {}", e);
                }

                if self.verbose {
                    println!("Enhanced monitoring cycle completed. Sleeping for 30 seconds...");
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

            println!("LEGION enhanced monitoring completed successfully");
            println!("Overall Risk Score: {:.3} ({:?})", risk_score.overall_score, risk_score.risk_level);
        }

        Ok(())
    }

    fn check_privileges(&self) -> Result<(), Box<dyn std::error::Error>> {
        let uid = unsafe { libc::getuid() };
        if uid != 0 {
            eprintln!("LEGION requires root privileges for comprehensive monitoring");
            eprintln!("   Run with: sudo legion");
            process::exit(1);
        }
        Ok(())
    }

    fn create_baseline(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let baseline = Baseline::capture()?;
        self.baseline.save(&baseline)?;
        println!("Baseline created and saved");
        Ok(())
    }

    fn load_baseline(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        self.baseline.load()?;
        println!("Baseline loaded");
        Ok(())
    }

    fn run_inventory_checks(&self) -> Result<(), Box<dyn std::error::Error>> {
        println!("Running system inventory checks...");
        super::inventory::inventory::check_system_info()?;
        super::inventory::inventory::check_hardware_info()?;
        Ok(())
    }

    fn run_auth_checks(&self) -> Result<(), Box<dyn std::error::Error>> {
        println!("Running authentication checks...");
        super::auth::auth::check_auth_failures()?;
        super::auth::auth::check_sudoers_changes()?;
        super::auth::auth::check_ssh_config()?;
        Ok(())
    }

    fn run_package_checks(&self) -> Result<(), Box<dyn std::error::Error>> {
        println!("Running package integrity checks...");
        super::packages::packages::check_package_drift()?;
        super::packages::packages::check_binary_integrity()?;
        Ok(())
    }

    fn run_filesystem_checks(&self) -> Result<(), Box<dyn std::error::Error>> {
        println!("Running filesystem checks...");
        super::filesystem::filesystem::check_suid_sgid_files()?;
        super::filesystem::filesystem::check_startup_persistence()?;
        Ok(())
    }

    fn run_process_checks(&self) -> Result<(), Box<dyn std::error::Error>> {
        println!("Running process checks...");
        super::processes::processes::check_orphan_processes()?;
        super::processes::processes::check_suspicious_executables()?;
        Ok(())
    }

    fn run_network_checks(&self) -> Result<(), Box<dyn std::error::Error>> {
        println!("Running network checks...");
        super::network::network::check_listening_sockets()?;
        super::network::network::check_firewall_rules()?;
        Ok(())
    }

    fn run_kernel_checks(&self) -> Result<(), Box<dyn std::error::Error>> {
        println!("Running kernel checks...");
        super::kernel::kernel::check_kernel_modules()?;
        super::kernel::kernel::check_sysctl_params()?;
        Ok(())
    }

    fn run_container_checks(&self) -> Result<(), Box<dyn std::error::Error>> {
        println!("Running container checks...");
        super::containers::containers::check_docker_containers()?;
        super::containers::containers::check_podman_containers()?;
        super::containers::containers::check_build_tools()?;
        Ok(())
    }

    async fn collect_training_data(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        println!("Collecting training data for ML baseline...");

        // Collect 10 samples over time for initial training
        for i in 0..10 {
            println!("Collecting sample {}/10...", i + 1);

            let snapshot = self.capture_system_snapshot().await?;
            if let Some(ref mut ml_baseline) = self.ml_baseline {
                ml_baseline.add_training_sample(snapshot);
            }

            // Wait 5 seconds between samples
            tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
        }

        // Train the model
        if let Some(ref mut ml_baseline) = self.ml_baseline {
            ml_baseline.train_model()?;
            println!("ML model trained successfully");
        }

        Ok(())
    }

    async fn capture_system_snapshot(&self) -> Result<SystemSnapshot, Box<dyn std::error::Error>> {
        // Capture current system metrics for ML analysis
        let cpu_usage = self.get_cpu_usage().await?;
        let memory_usage = self.get_memory_usage().await?;
        let disk_usage = self.get_disk_usage().await?;
        let network_connections = self.get_network_connections().await?;
        let running_processes = self.get_running_processes().await?;
        let open_files = self.get_open_files().await?;
        let entropy = self.get_system_entropy().await?;

        Ok(SystemSnapshot {
            cpu_usage,
            memory_usage,
            disk_usage,
            network_connections,
            running_processes,
            open_files,
            entropy,
        })
    }

    async fn get_cpu_usage(&self) -> Result<f64, Box<dyn std::error::Error>> {
        let content = tokio::fs::read_to_string("/proc/stat").await?;
        let lines: Vec<&str> = content.lines().collect();
        if let Some(cpu_line) = lines.get(0) {
            let parts: Vec<&str> = cpu_line.split_whitespace().collect();
            if parts.len() >= 8 {
                let user: f64 = parts[1].parse().unwrap_or(0.0);
                let nice: f64 = parts[2].parse().unwrap_or(0.0);
                let system: f64 = parts[3].parse().unwrap_or(0.0);
                let idle: f64 = parts[4].parse().unwrap_or(0.0);
                let total = user + nice + system + idle;
                if total > 0.0 {
                    return Ok((user + nice + system) / total);
                }
            }
        }
        Ok(0.0)
    }

    async fn get_memory_usage(&self) -> Result<f64, Box<dyn std::error::Error>> {
        let content = tokio::fs::read_to_string("/proc/meminfo").await?;
        let mut total = 0.0;
        let mut available = 0.0;

        for line in content.lines() {
            if line.starts_with("MemTotal:") {
                total = line.split_whitespace().nth(1).unwrap_or("0").parse::<f64>().unwrap_or(0.0);
            } else if line.starts_with("MemAvailable:") {
                available = line.split_whitespace().nth(1).unwrap_or("0").parse::<f64>().unwrap_or(0.0);
            }
        }

        if total > 0.0 {
            Ok(1.0 - (available / total))
        } else {
            Ok(0.0)
        }
    }

    async fn get_disk_usage(&self) -> Result<f64, Box<dyn std::error::Error>> {
        // Simple disk usage check for root filesystem
        let output = tokio::process::Command::new("df")
            .args(&["/", "--output=pcent"])
            .output()
            .await?;

        let output_str = String::from_utf8(output.stdout)?;
        let lines: Vec<&str> = output_str.lines().collect();
        if lines.len() >= 2 {
            let percent_str = lines[1].trim().trim_end_matches('%');
            let percent: f64 = percent_str.parse().unwrap_or(0.0);
            Ok(percent / 100.0)
        } else {
            Ok(0.0)
        }
    }

    async fn get_network_connections(&self) -> Result<usize, Box<dyn std::error::Error>> {
        let content = tokio::fs::read_to_string("/proc/net/tcp").await?;
        Ok(content.lines().count().saturating_sub(1)) // Subtract header line
    }

    async fn get_running_processes(&self) -> Result<usize, Box<dyn std::error::Error>> {
        let output = tokio::process::Command::new("ps")
            .args(&["--no-headers", "-e"])
            .output()
            .await?;
        let output_str = String::from_utf8(output.stdout)?;
        Ok(output_str.lines().count())
    }

    async fn get_open_files(&self) -> Result<usize, Box<dyn std::error::Error>> {
        let output = tokio::process::Command::new("lsof")
            .output()
            .await?;
        let output_str = String::from_utf8(output.stdout)?;
        Ok(output_str.lines().count())
    }

    async fn get_system_entropy(&self) -> Result<f64, Box<dyn std::error::Error>> {
        // Read from /proc/sys/kernel/random/entropy_avail
        match tokio::fs::read_to_string("/proc/sys/kernel/random/entropy_avail").await {
            Ok(content) => {
                let entropy: f64 = content.trim().parse().unwrap_or(2048.0);
                // Normalize to 0-1 range (4096 is typical max)
                Ok((entropy / 4096.0).min(1.0))
            }
            Err(_) => Ok(0.5), // Default if not available
        }
    }

    async fn run_enhanced_checks(&mut self) -> Result<SystemState, Box<dyn std::error::Error>> {
        println!("Running enhanced system checks...");

        // Run traditional checks
        if let Err(e) = self.run_inventory_checks() {
            eprintln!("Error in inventory checks: {}", e);
        }
        if let Err(e) = self.run_auth_checks() {
            eprintln!("Error in auth checks: {}", e);
        }
        if let Err(e) = self.run_package_checks() {
            eprintln!("Error in package checks: {}", e);
        }
        if let Err(e) = self.run_filesystem_checks() {
            eprintln!("Error in filesystem checks: {}", e);
        }

        // Enhanced process checks with behavioral analysis
        self.run_enhanced_process_checks().await?;

        // Enhanced network checks with threat intelligence
        self.run_enhanced_network_checks().await?;

        if let Err(e) = self.run_kernel_checks() {
            eprintln!("Error in kernel checks: {}", e);
        }
        if let Err(e) = self.run_container_checks() {
            eprintln!("Error in container checks: {}", e);
        }

        // Capture current system state for risk scoring
        let current_snapshot = self.capture_system_snapshot().await?;

        // Check for ML anomalies
        let anomaly_score = if let Some(ref ml_baseline) = self.ml_baseline {
            match ml_baseline.predict_anomaly(&current_snapshot) {
                Ok(score) => {
                    if self.verbose {
                        println!("ML Anomaly Score: {:.3} ({})", score.score, score.details);
                    }
                    score.score
                }
                Err(e) => {
                    eprintln!("ML prediction error: {}", e);
                    0.0
                }
            }
        } else {
            0.0
        };

        // Get threat indicators
        let threat_indicators = self.check_threat_indicators().await?;

        // Calculate behavioral score
        let behavioral_score = self.behavioral_analyzer.get_overall_threat_score();

        Ok(SystemState {
            timestamp: chrono::Utc::now(),
            anomaly_score,
            threat_indicators,
            behavioral_score,
            network_score: 0.0, // TODO: Implement network scoring
            process_score: behavioral_score,
            file_integrity_score: 0.0, // TODO: Implement file integrity scoring
            system_health_score: 1.0 - current_snapshot.cpu_usage.max(current_snapshot.memory_usage),
        })
    }

    async fn run_enhanced_process_checks(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        println!("Running enhanced process checks with behavioral analysis...");

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
                        println!("Process {} classified as {:?}", pid, classification);
                    }
                }
            }
        }

        Ok(())
    }

    async fn run_enhanced_network_checks(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        println!("Running enhanced network checks with threat intelligence...");

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
                            println!("Threat detected for {}:{} - {:?}", ip, port, threat_level.level);
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

        println!("High risk detected ({}), executing automated response...", risk_score.risk_level);

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
            println!("Executed {} automated response actions", actions_taken.len());
            for action in &actions_taken {
                println!("  - {:?}", action);
            }
        }

        Ok(())
    }

    async fn generate_enhanced_report(&self, system_state: &SystemState, risk_score: &RiskScore) -> Result<(), Box<dyn std::error::Error>> {
        println!("Generating enhanced monitoring report...");

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
            };
            let report = serde_json::json!({
                "timestamp": risk_score.timestamp,
                "risk_score": if risk_score.overall_score.is_finite() { risk_score.overall_score } else { 0.0 },
                "risk_level": risk_score.risk_level,
                "contributing_factors": risk_score.contributing_factors,
                "system_state": sanitized_system_state,
                "confidence": if risk_score.confidence.is_finite() { risk_score.confidence } else { 0.0 }
            });
            println!("{}", serde_json::to_string_pretty(&report)?);
        } else {
            println!("=== ENHANCED LEGION MONITORING REPORT ===");
            println!("Timestamp: {}", risk_score.timestamp);
            println!("Risk Score: {:.3} ({:?})", risk_score.overall_score, risk_score.risk_level);
            println!("Confidence: {:.3}", risk_score.confidence);
            println!();
            println!("Contributing Factors:");
            for factor in &risk_score.contributing_factors {
                println!("  - {}", factor);
            }
            println!();
            println!("System State:");
            println!("  CPU Usage: {:.1}%", system_state.system_health_score * 100.0);
            println!("  Anomaly Score: {:.3}", system_state.anomaly_score);
            println!("  Behavioral Score: {:.3}", system_state.behavioral_score);
            println!("  Threat Indicators: {}", system_state.threat_indicators.len());
        }

        Ok(())
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
            .author("HARDN Security Team")
            .about("Advanced system monitoring and anomaly detection with ML and automated response")
            .long_about("LEGION performs comprehensive system monitoring and anomaly detection.\n\n\
                         Enhanced with machine learning, behavioral analysis, threat intelligence,\n\
                         automated response, incident correlation, and real-time risk scoring.\n\n\
                         EXAMPLES:\n\
                         \thardn legion --create-baseline    # Create initial system baseline\n\
                         \thardn legion --ml-enabled         # Enable ML-based anomaly detection\n\
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
                Arg::new("ml-enabled")
                    .long("ml-enabled")
                    .help("Enable machine learning-based anomaly detection")
                    .long_help("Enables ML-powered anomaly detection using clustering algorithms\n\
                               to identify deviations from normal system behavior patterns.")
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
        .about("Advanced system monitoring and anomaly detection with ML and automated response")
        .long_about("LEGION performs comprehensive system monitoring and anomaly detection.\n\n\
                     Enhanced with machine learning, behavioral analysis, threat intelligence,\n\
                     automated response, incident correlation, and real-time risk scoring.\n\n\
                     EXAMPLES:\n\
                     \thardn legion --create-baseline    # Create initial system baseline\n\
                     \thardn legion --ml-enabled         # Enable ML-based anomaly detection\n\
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
            Arg::new("ml-enabled")
                .long("ml-enabled")
                .help("Enable machine learning-based anomaly detection")
                .long_help("Enables ML-powered anomaly detection using clustering algorithms\n\
                           to identify deviations from normal system behavior patterns.")
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
    let ml_enabled = matches.get_flag("ml-enabled");
    let predictive_enabled = matches.get_flag("predictive");
    let response_enabled = matches.get_flag("response-enabled");
    let verbose = matches.get_flag("verbose");
    let daemon = matches.get_flag("daemon");
    let json_output = matches.get_flag("json");

    let mut legion = Legion::new(create_baseline, verbose, json_output, daemon, ml_enabled, predictive_enabled, response_enabled).await?;
    legion.run().await
}