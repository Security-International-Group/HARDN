use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::process::Command;
use chrono::{DateTime, Utc};
use tokio::sync::RwLock;
use std::sync::Arc;

/// Automated Response System
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ResponseAction {
    IsolateProcess { pid: u32 },
    BlockNetwork { ip: String, port: u16 },
    QuarantineFile { path: String },
    KillProcess { pid: u32 },
    DisableService { name: String },
    AlertAdmin { message: String, severity: String },
    LogIncident { details: String },
    CustomCommand { command: String, args: Vec<String> },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseRule {
    pub id: String,
    pub name: String,
    pub condition: ResponseCondition,
    pub actions: Vec<ResponseAction>,
    pub enabled: bool,
    pub priority: u8,
    pub cooldown_minutes: u32,
    pub last_triggered: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseCondition {
    pub anomaly_score_threshold: f64,
    pub threat_level: Option<String>,
    pub process_name_pattern: Option<String>,
    pub network_pattern: Option<String>,
    pub file_pattern: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncidentDetails {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub anomaly: Anomaly,
    pub actions_taken: Vec<ResponseAction>,
    pub success: bool,
    pub error_message: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Anomaly {
    pub anomaly_type: String,
    pub severity: String,
    pub score: f64,
    pub description: String,
    pub indicators: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct ResponseEngine {
    rules: Arc<RwLock<Vec<ResponseRule>>>,
    quarantine_dir: PathBuf,
    alert_channels: Vec<AlertChannel>,
    incident_log: Arc<RwLock<Vec<IncidentDetails>>>,
    dry_run: bool,
    max_actions_per_hour: u32,
    action_count_this_hour: Arc<RwLock<HashMap<String, u32>>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertChannel {
    pub channel_type: AlertChannelType,
    pub destination: String,
    pub enabled: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum AlertChannelType {
    Email,
    Slack,
    Webhook,
    Syslog,
    File,
}

#[allow(dead_code)]
impl ResponseEngine {
    pub fn new(quarantine_dir: PathBuf, dry_run: bool) -> Self {
        Self {
            rules: Arc::new(RwLock::new(Vec::new())),
            quarantine_dir,
            alert_channels: Vec::new(),
            incident_log: Arc::new(RwLock::new(Vec::new())),
            dry_run,
            max_actions_per_hour: 10,
            action_count_this_hour: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn add_rule(&self, rule: ResponseRule) {
        let mut rules = self.rules.write().await;
        rules.push(rule);
        rules.sort_by(|a, b| b.priority.cmp(&a.priority)); // Higher priority first
    }

    pub async fn execute_response(&self, anomaly: &Anomaly) -> Result<Vec<ResponseAction>, ResponseError> {
        let rules = self.rules.read().await;
        let mut executed_actions = Vec::new();

        for rule in rules.iter() {
            if !rule.enabled {
                continue;
            }

            // Check cooldown
            if let Some(last_triggered) = rule.last_triggered {
                let cooldown_duration = chrono::Duration::minutes(rule.cooldown_minutes as i64);
                if Utc::now().signed_duration_since(last_triggered) < cooldown_duration {
                    continue;
                }
            }

            // Check if condition matches
            if self.condition_matches(&rule.condition, anomaly) {
                eprintln!("Executing response rule: {}", rule.name);

                for action in &rule.actions {
                    if self.can_execute_action(&action).await {
                        match self.execute_action(action).await {
                            Ok(_) => {
                                executed_actions.push(action.clone());
                                self.record_action_execution(&rule.id).await;
                            }
                            Err(e) => {
                                eprintln!("Failed to execute action {:?}: {}", action, e);
                            }
                        }
                    } else {
                        eprintln!("Action rate limit exceeded for: {:?}", action);
                    }
                }

                // Update last triggered time
                // Note: In a real implementation, you'd update the rule in storage
                break; // Execute only the highest priority matching rule
            }
        }

        // Log incident
        self.log_incident(anomaly, &executed_actions, true, None).await;

        Ok(executed_actions)
    }

    fn condition_matches(&self, condition: &ResponseCondition, anomaly: &Anomaly) -> bool {
        // Check anomaly score threshold
        if anomaly.score < condition.anomaly_score_threshold {
            return false;
        }

        // Check threat level if specified
        if let Some(ref required_level) = condition.threat_level {
            if &anomaly.severity != required_level {
                return false;
            }
        }

        // Check patterns (simplified - in real implementation, use regex)
        if let Some(ref pattern) = condition.process_name_pattern {
            if !anomaly.description.contains(pattern) {
                return false;
            }
        }

        if let Some(ref pattern) = condition.network_pattern {
            for indicator in &anomaly.indicators {
                if indicator.contains(pattern) {
                    return true;
                }
            }
            return false;
        }

        if let Some(ref pattern) = condition.file_pattern {
            for indicator in &anomaly.indicators {
                if indicator.contains(pattern) {
                    return true;
                }
            }
            return false;
        }

        true
    }

    async fn can_execute_action(&self, action: &ResponseAction) -> bool {
        let action_counts = self.action_count_this_hour.write().await;
        let action_key = format!("{:?}", action);

        let count = action_counts.get(&action_key).unwrap_or(&0);
        *count < self.max_actions_per_hour
    }

    async fn execute_action(&self, action: &ResponseAction) -> Result<(), ResponseError> {
        if self.dry_run {
            eprintln!("DRY RUN: Would execute action: {:?}", action);
            return Ok(());
        }

        match action {
            ResponseAction::IsolateProcess { pid } => {
                self.isolate_process(*pid).await
            }
            ResponseAction::BlockNetwork { ip, port } => {
                self.block_network(ip, *port).await
            }
            ResponseAction::QuarantineFile { path } => {
                self.quarantine_file(path).await
            }
            ResponseAction::KillProcess { pid } => {
                self.kill_process(*pid).await
            }
            ResponseAction::DisableService { name } => {
                self.disable_service(name).await
            }
            ResponseAction::AlertAdmin { message, severity } => {
                self.alert_admin(message, severity).await
            }
            ResponseAction::LogIncident { details } => {
                eprintln!("Logging incident: {}", details);
                Ok(())
            }
            ResponseAction::CustomCommand { command, args } => {
                self.execute_custom_command(command, args).await
            }
        }
    }

    async fn isolate_process(&self, pid: u32) -> Result<(), ResponseError> {
        // Use cgroups or other isolation mechanisms
        eprintln!("Isolating process {}", pid);

        // In a real implementation, this would use cgroups, namespaces, or other isolation
        let output = Command::new("kill")
            .args(&["-STOP", &pid.to_string()])
            .output()
            .map_err(|e| ResponseError::ExecutionFailed(format!("Failed to stop process: {}", e)))?;

        if output.status.success() {
            Ok(())
        } else {
            Err(ResponseError::ExecutionFailed("Process isolation failed".to_string()))
        }
    }

    async fn block_network(&self, ip: &str, port: u16) -> Result<(), ResponseError> {
        eprintln!("Blocking network access to {}:{}", ip, port);

        // Use iptables to block the connection
        let _rule = format!("-A INPUT -s {} -p tcp --dport {} -j DROP", ip, port);
        let output = Command::new("iptables")
            .args(&["-I", "INPUT", "-s", ip, "-p", "tcp", "--dport", &port.to_string(), "-j", "DROP"])
            .output()
            .map_err(|e| ResponseError::ExecutionFailed(format!("Failed to block network: {}", e)))?;

        if output.status.success() {
            Ok(())
        } else {
            Err(ResponseError::ExecutionFailed("Network blocking failed".to_string()))
        }
    }

    async fn quarantine_file(&self, path: &str) -> Result<(), ResponseError> {
        eprintln!("Quarantining file: {}", path);

        let source_path = PathBuf::from(path);
        let file_name = source_path.file_name()
            .ok_or_else(|| ResponseError::InvalidPath("Invalid file path".to_string()))?;

        let quarantine_path = self.quarantine_dir.join(format!("{}_{}",
            Utc::now().timestamp(),
            file_name.to_string_lossy()
        ));

        // Create quarantine directory if it doesn't exist
        std::fs::create_dir_all(&self.quarantine_dir)
            .map_err(|e| ResponseError::ExecutionFailed(format!("Failed to create quarantine dir: {}", e)))?;

        // Move file to quarantine
        std::fs::rename(&source_path, &quarantine_path)
            .map_err(|e| ResponseError::ExecutionFailed(format!("Failed to quarantine file: {}", e)))?;

        Ok(())
    }

    async fn kill_process(&self, pid: u32) -> Result<(), ResponseError> {
        eprintln!("Killing process {}", pid);

        let output = Command::new("kill")
            .args(&["-9", &pid.to_string()])
            .output()
            .map_err(|e| ResponseError::ExecutionFailed(format!("Failed to kill process: {}", e)))?;

        if output.status.success() {
            Ok(())
        } else {
            Err(ResponseError::ExecutionFailed("Process termination failed".to_string()))
        }
    }

    async fn disable_service(&self, name: &str) -> Result<(), ResponseError> {
        eprintln!("Disabling service: {}", name);

        let output = Command::new("systemctl")
            .args(&["stop", name])
            .output()
            .map_err(|e| ResponseError::ExecutionFailed(format!("Failed to stop service: {}", e)))?;

        if output.status.success() {
            // Also disable the service
            Command::new("systemctl")
                .args(&["disable", name])
                .output()
                .map_err(|e| ResponseError::ExecutionFailed(format!("Failed to disable service: {}", e)))?;

            Ok(())
        } else {
            Err(ResponseError::ExecutionFailed("Service disable failed".to_string()))
        }
    }

    async fn alert_admin(&self, message: &str, severity: &str) -> Result<(), ResponseError> {
        eprintln!("ALERT [{}]: {}", severity, message);

        for channel in &self.alert_channels {
            if !channel.enabled {
                continue;
            }

            match channel.channel_type {
                AlertChannelType::Email => {
                    // In a real implementation, send email
                    eprintln!("Would send email alert to: {}", channel.destination);
                }
                AlertChannelType::Slack => {
                    // In a real implementation, send Slack message
                    eprintln!("Would send Slack alert to: {}", channel.destination);
                }
                AlertChannelType::Webhook => {
                    // In a real implementation, send HTTP webhook
                    eprintln!("Would send webhook alert to: {}", channel.destination);
                }
                AlertChannelType::Syslog => {
                    // Log to syslog
                    eprintln!("Logging to syslog: {}", message);
                }
                AlertChannelType::File => {
                    // Append to log file
                    eprintln!("Would append to log file: {}", channel.destination);
                }
            }
        }

        Ok(())
    }

    async fn execute_custom_command(&self, command: &str, args: &[String]) -> Result<(), ResponseError> {
        eprintln!("Executing custom command: {} {:?}", command, args);

        let output = Command::new(command)
            .args(args)
            .output()
            .map_err(|e| ResponseError::ExecutionFailed(format!("Custom command failed: {}", e)))?;

        if output.status.success() {
            Ok(())
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            Err(ResponseError::ExecutionFailed(format!("Command failed: {}", stderr)))
        }
    }

    async fn record_action_execution(&self, rule_id: &str) {
        let mut action_counts = self.action_count_this_hour.write().await;
        let count = action_counts.entry(rule_id.to_string()).or_insert(0);
        *count += 1;
    }

    async fn log_incident(&self, anomaly: &Anomaly, actions: &[ResponseAction], success: bool, error: Option<String>) {
        let incident = IncidentDetails {
            id: uuid::Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            anomaly: anomaly.clone(),
            actions_taken: actions.to_vec(),
            success,
            error_message: error,
        };

        let mut incidents = self.incident_log.write().await;
        incidents.push(incident);
    }

    pub async fn get_incident_log(&self) -> Vec<IncidentDetails> {
        self.incident_log.read().await.clone()
    }

    pub async fn add_alert_channel(&mut self, channel: AlertChannel) {
        self.alert_channels.push(channel);
    }

    pub fn set_dry_run(&mut self, dry_run: bool) {
        self.dry_run = dry_run;
    }

    pub fn set_max_actions_per_hour(&mut self, max: u32) {
        self.max_actions_per_hour = max;
    }
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub enum ResponseError {
    ExecutionFailed(String),
    InvalidPath(String),
    RateLimitExceeded,
    ConditionNotMet,
}

impl std::fmt::Display for ResponseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ResponseError::ExecutionFailed(msg) => write!(f, "Execution failed: {}", msg),
            ResponseError::InvalidPath(msg) => write!(f, "Invalid path: {}", msg),
            ResponseError::RateLimitExceeded => write!(f, "Rate limit exceeded"),
            ResponseError::ConditionNotMet => write!(f, "Condition not met"),
        }
    }
}

impl std::error::Error for ResponseError {}