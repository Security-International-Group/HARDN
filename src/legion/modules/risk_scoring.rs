use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Scoring System
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskScore {
    pub overall_score: f64, // 0.0 to 1.0
    pub components: HashMap<String, f64>,
    pub confidence: f64,
    pub timestamp: DateTime<Utc>,
    pub risk_level: RiskLevel,
    pub contributing_factors: Vec<String>,
    pub component_factors: HashMap<String, Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for RiskLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RiskLevel::Low => write!(f, "Low"),
            RiskLevel::Medium => write!(f, "Medium"),
            RiskLevel::High => write!(f, "High"),
            RiskLevel::Critical => write!(f, "Critical"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ScriptStatus {
    Success,
    Warning,
    Failed,
}

impl std::fmt::Display for ScriptStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScriptStatus::Success => write!(f, "Success"),
            ScriptStatus::Warning => write!(f, "Warning"),
            ScriptStatus::Failed => write!(f, "Failed"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScriptResult {
    pub domain: String,
    pub name: String,
    pub status: ScriptStatus,
    pub duration_ms: u128,
    pub details: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityPlatformStatus {
    pub name: String,
    pub service_unit: String,
    pub active: bool,
    pub enabled: bool,
    pub recent_warnings: u32,
    pub last_warning: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemState {
    pub timestamp: DateTime<Utc>,
    pub anomaly_score: f64,
    pub threat_indicators: Vec<ThreatIndicator>,
    pub behavioral_score: f64,
    pub network_score: f64,
    pub process_score: f64,
    pub file_integrity_score: f64,
    pub system_health_score: f64,
    pub memory_usage: f64,
    pub detected_issues: Vec<String>,
    pub script_results: Vec<ScriptResult>,
    pub security_platforms: Vec<SecurityPlatformStatus>,
    pub baseline_drift: Option<BaselineDriftSummary>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BaselineDriftSummary {
    pub new_processes: Vec<String>,
    pub missing_processes: Vec<String>,
    pub new_listening_ports: Vec<String>,
    pub missing_listening_ports: Vec<String>,
}

impl BaselineDriftSummary {
    pub fn is_empty(&self) -> bool {
        self.new_processes.is_empty()
            && self.missing_processes.is_empty()
            && self.new_listening_ports.is_empty()
            && self.missing_listening_ports.is_empty()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatIndicator {
    pub indicator_type: String,
    pub severity: String,
    pub confidence: f64,
    pub source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskScoringEngine {
    pub weights: RiskWeights,
    pub thresholds: RiskThresholds,
    pub historical_scores: Vec<RiskScore>,
    pub max_history_size: usize,
    pub adaptive_enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskWeights {
    pub anomaly_weight: f64,
    pub threat_intel_weight: f64,
    pub behavioral_weight: f64,
    pub network_weight: f64,
    pub process_weight: f64,
    pub file_integrity_weight: f64,
    pub system_health_weight: f64,
    pub temporal_weight: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskThresholds {
    pub low_threshold: f64,
    pub medium_threshold: f64,
    pub high_threshold: f64,
    pub critical_threshold: f64,
}

impl Default for RiskWeights {
    fn default() -> Self {
        Self {
            anomaly_weight: 0.25,
            threat_intel_weight: 0.20,
            behavioral_weight: 0.15,
            network_weight: 0.10,
            process_weight: 0.10,
            file_integrity_weight: 0.10,
            system_health_weight: 0.05,
            temporal_weight: 0.05,
        }
    }
}

impl Default for RiskThresholds {
    fn default() -> Self {
        Self {
            low_threshold: 0.2,
            medium_threshold: 0.4,
            high_threshold: 0.7,
            critical_threshold: 0.9,
        }
    }
}

#[allow(dead_code)]
impl RiskScoringEngine {
    pub fn new() -> Self {
        Self {
            weights: RiskWeights::default(),
            thresholds: RiskThresholds::default(),
            historical_scores: Vec::new(),
            max_history_size: 1000,
            adaptive_enabled: true,
        }
    }

    pub fn calculate_risk(&mut self, system_state: &SystemState) -> RiskScore {
        let mut components = HashMap::new();
        let mut contributing_factors: Vec<String> = Vec::new();
        let mut component_factors: HashMap<String, Vec<String>> = HashMap::new();

        // Calculate component scores
        let (anomaly_score, anomaly_details) = self.calculate_anomaly_component(system_state);
        if !anomaly_details.is_empty() {
            contributing_factors.extend(anomaly_details.iter().cloned());
            component_factors.insert("anomaly".to_string(), anomaly_details.clone());
        }
        components.insert("anomaly".to_string(), anomaly_score);

        let (threat_score, threat_details) = self.calculate_threat_component(system_state);
        if !threat_details.is_empty() {
            contributing_factors.extend(threat_details.iter().cloned());
            component_factors.insert("threat_intel".to_string(), threat_details.clone());
        }
        components.insert("threat_intel".to_string(), threat_score);

        let (behavioral_score, behavioral_details) =
            self.calculate_behavioral_component(system_state);
        if !behavioral_details.is_empty() {
            contributing_factors.extend(behavioral_details.iter().cloned());
            component_factors.insert("behavioral".to_string(), behavioral_details.clone());
        }
        components.insert("behavioral".to_string(), behavioral_score);

        let (network_score, network_details) = self.calculate_network_component(system_state);
        if !network_details.is_empty() {
            contributing_factors.extend(network_details.iter().cloned());
            component_factors.insert("network".to_string(), network_details.clone());
        }
        components.insert("network".to_string(), network_score);

        let (process_score, process_details) = self.calculate_process_component(system_state);
        if !process_details.is_empty() {
            contributing_factors.extend(process_details.iter().cloned());
            component_factors.insert("process".to_string(), process_details.clone());
        }
        components.insert("process".to_string(), process_score);

        let (file_score, file_details) = self.calculate_file_component(system_state);
        if !file_details.is_empty() {
            contributing_factors.extend(file_details.iter().cloned());
            component_factors.insert("file_integrity".to_string(), file_details.clone());
        }
        components.insert("file_integrity".to_string(), file_score);

        let (health_score, health_details) = self.calculate_health_component(system_state);
        if !health_details.is_empty() {
            contributing_factors.extend(health_details.iter().cloned());
            component_factors.insert("system_health".to_string(), health_details.clone());
        }
        components.insert("system_health".to_string(), health_score);

        let (temporal_score, temporal_details) = self.calculate_temporal_component(system_state);
        if !temporal_details.is_empty() {
            contributing_factors.extend(temporal_details.iter().cloned());
            component_factors.insert("temporal".to_string(), temporal_details.clone());
        }
        components.insert("temporal".to_string(), temporal_score);

        // Add detected issues from system checks
        for issue in &system_state.detected_issues {
            contributing_factors.push(issue.clone());
        }

        for platform in &system_state.security_platforms {
            if !platform.active {
                contributing_factors.push(format!(
                    "{} service ({}) is not active",
                    platform.name, platform.service_unit
                ));
            }
            if platform.recent_warnings > 0 {
                contributing_factors.push(format!(
                    "{} reported {} warnings in the last hour",
                    platform.name, platform.recent_warnings
                ));
            }
        }

        // Calculate weighted overall score
        let overall_score = self.calculate_weighted_score(&components);

        // Determine risk level
        let risk_level = self.determine_risk_level(overall_score);

        // Calculate confidence based on data completeness and consistency
        let confidence = self.calculate_confidence(&components);

        contributing_factors.sort();
        contributing_factors.dedup();

        let risk_score = RiskScore {
            overall_score,
            components,
            confidence,
            timestamp: Utc::now(),
            risk_level,
            contributing_factors,
            component_factors,
        };

        // Store in history
        self.add_to_history(risk_score.clone());

        // Adapt weights if enabled
        if self.adaptive_enabled {
            self.adapt_weights();
        }

        risk_score
    }

    fn calculate_anomaly_component(&self, state: &SystemState) -> (f64, Vec<String>) {
        let score = state.anomaly_score;
        let mut factors = Vec::new();

        if score > 0.8 {
            factors.push("High anomaly detection score".to_string());
        } else if score > 0.5 {
            factors.push("Moderate anomaly detection".to_string());
        }

        (score, factors)
    }

    fn calculate_threat_component(&self, state: &SystemState) -> (f64, Vec<String>) {
        if state.threat_indicators.is_empty() {
            return (0.0, Vec::new());
        }

        let mut total_severity = 0.0;
        let mut factors = Vec::new();

        for indicator in &state.threat_indicators {
            let severity_score = match indicator.severity.as_str() {
                "critical" => 1.0,
                "high" => 0.8,
                "medium" => 0.5,
                "low" => 0.2,
                _ => 0.1,
            };

            total_severity += severity_score * indicator.confidence;

            if indicator.confidence > 0.8 {
                factors.push(format!(
                    "High confidence threat: {}",
                    indicator.indicator_type
                ));
            }
        }

        let avg_severity = total_severity / state.threat_indicators.len() as f64;
        (avg_severity.min(1.0), factors)
    }

    fn calculate_behavioral_component(&self, state: &SystemState) -> (f64, Vec<String>) {
        let score = state.behavioral_score;
        let mut factors = Vec::new();

        if score > 0.7 {
            factors.push("Suspicious process behavior detected".to_string());
        } else if score > 0.4 {
            factors.push("Abnormal process patterns observed".to_string());
        }

        (score, factors)
    }

    fn calculate_network_component(&self, state: &SystemState) -> (f64, Vec<String>) {
        let mut score = state.network_score;
        let mut factors = Vec::new();

        if score > 0.8 {
            factors.push("Critical network security issues".to_string());
        } else if score > 0.5 {
            factors.push("Network anomalies detected".to_string());
        }

        if let Some(drift) = &state.baseline_drift {
            if !drift.new_listening_ports.is_empty() {
                factors.push(format!(
                    "{} new listening port(s) observed since baseline: {}",
                    drift.new_listening_ports.len(),
                    summarize_list(&drift.new_listening_ports, 5)
                ));
                score = score.max(0.6);
            }
            if !drift.missing_listening_ports.is_empty() {
                factors.push(format!(
                    "{} baseline listening port(s) no longer present: {}",
                    drift.missing_listening_ports.len(),
                    summarize_list(&drift.missing_listening_ports, 5)
                ));
            }
        }

        (score, factors)
    }

    fn calculate_process_component(&self, state: &SystemState) -> (f64, Vec<String>) {
        let mut score = state.process_score;
        let mut factors = Vec::new();

        if score > 0.7 {
            factors.push("Critical process security violations".to_string());
        } else if score > 0.5 {
            factors.push("Process security concerns".to_string());
        }

        if let Some(drift) = &state.baseline_drift {
            if !drift.new_processes.is_empty() {
                factors.push(format!(
                    "{} running process(es) not seen in baseline: {}",
                    drift.new_processes.len(),
                    summarize_list(&drift.new_processes, 5)
                ));
                score = score.max(0.6);
            }
            if !drift.missing_processes.is_empty() {
                factors.push(format!(
                    "{} baseline process(es) missing: {}",
                    drift.missing_processes.len(),
                    summarize_list(&drift.missing_processes, 5)
                ));
            }
        }

        (score, factors)
    }

    fn calculate_file_component(&self, state: &SystemState) -> (f64, Vec<String>) {
        let score = state.file_integrity_score;
        let mut factors = Vec::new();

        if score > 0.8 {
            factors.push("File integrity severely compromised".to_string());
        } else if score > 0.5 {
            factors.push("File integrity issues detected".to_string());
        }

        (score, factors)
    }

    fn calculate_health_component(&self, state: &SystemState) -> (f64, Vec<String>) {
        let mut health_score = 0.0;
        let mut issue_count = 0;
        let mut factors = Vec::new();

        // Check CPU usage (high usage is bad)
        if state.system_health_score > 0.8 {
            factors.push(format!(
                "High CPU usage: {:.1}%",
                state.system_health_score * 100.0
            ));
            health_score += state.system_health_score;
            issue_count += 1;
        } else if state.system_health_score > 0.6 {
            factors.push(format!(
                "Elevated CPU usage: {:.1}%",
                state.system_health_score * 100.0
            ));
            health_score += state.system_health_score * 0.5;
        }

        // Check memory usage (high usage is bad)
        if state.memory_usage > 0.9 {
            factors.push(format!(
                "Critical memory usage: {:.1}%",
                state.memory_usage * 100.0
            ));
            health_score += 1.0;
            issue_count += 1;
        } else if state.memory_usage > 0.8 {
            factors.push(format!(
                "High memory usage: {:.1}%",
                state.memory_usage * 100.0
            ));
            health_score += state.memory_usage;
            issue_count += 1;
        } else if state.memory_usage > 0.7 {
            factors.push(format!(
                "Elevated memory usage: {:.1}%",
                state.memory_usage * 100.0
            ));
            health_score += state.memory_usage * 0.5;
        }

        // If no specific issues but overall health is poor, add general message
        if issue_count == 0 && (state.system_health_score > 0.5 || state.memory_usage > 0.6) {
            factors.push("General system health concerns".to_string());
        }

        // Return risk score based on health issues
        let score = if health_score > 0.0 {
            (health_score / (issue_count.max(1) as f64)).min(1.0)
        } else {
            0.0
        };

        (score, factors)
    }

    fn calculate_temporal_component(&self, _state: &SystemState) -> (f64, Vec<String>) {
        if self.historical_scores.len() < 5 {
            return (0.0, Vec::new());
        }

        // Calculate trend in risk scores over last few measurements
        let recent_scores: Vec<f64> = self
            .historical_scores
            .iter()
            .rev()
            .take(5)
            .map(|s| s.overall_score)
            .collect();

        let trend = self.calculate_trend(&recent_scores);
        let mut factors = Vec::new();

        if trend > 0.2 {
            factors.push("Risk score trending upward".to_string());
        } else if trend < -0.2 {
            factors.push("Risk score trending downward".to_string());
        }

        (trend.abs().min(1.0), factors)
    }

    fn calculate_trend(&self, scores: &[f64]) -> f64 {
        if scores.len() < 2 {
            return 0.0;
        }

        let mut trend = 0.0;
        for i in 1..scores.len() {
            trend += scores[i] - scores[i - 1];
        }

        trend / (scores.len() - 1) as f64
    }

    fn calculate_weighted_score(&self, components: &HashMap<String, f64>) -> f64 {
        let mut total_score = 0.0;
        let mut total_weight = 0.0;

        total_score += components.get("anomaly").unwrap_or(&0.0) * self.weights.anomaly_weight;
        total_weight += self.weights.anomaly_weight;

        total_score +=
            components.get("threat_intel").unwrap_or(&0.0) * self.weights.threat_intel_weight;
        total_weight += self.weights.threat_intel_weight;

        total_score +=
            components.get("behavioral").unwrap_or(&0.0) * self.weights.behavioral_weight;
        total_weight += self.weights.behavioral_weight;

        total_score += components.get("network").unwrap_or(&0.0) * self.weights.network_weight;
        total_weight += self.weights.network_weight;

        total_score += components.get("process").unwrap_or(&0.0) * self.weights.process_weight;
        total_weight += self.weights.process_weight;

        total_score +=
            components.get("file_integrity").unwrap_or(&0.0) * self.weights.file_integrity_weight;
        total_weight += self.weights.file_integrity_weight;

        total_score +=
            components.get("system_health").unwrap_or(&0.0) * self.weights.system_health_weight;
        total_weight += self.weights.system_health_weight;

        total_score += components.get("temporal").unwrap_or(&0.0) * self.weights.temporal_weight;
        total_weight += self.weights.temporal_weight;

        if total_weight > 0.0 {
            (total_score / total_weight).min(1.0)
        } else {
            0.0
        }
    }

    fn determine_risk_level(&self, score: f64) -> RiskLevel {
        if score >= self.thresholds.critical_threshold {
            RiskLevel::Critical
        } else if score >= self.thresholds.high_threshold {
            RiskLevel::High
        } else if score >= self.thresholds.medium_threshold {
            RiskLevel::Medium
        } else {
            RiskLevel::Low
        }
    }

    fn calculate_confidence(&self, components: &HashMap<String, f64>) -> f64 {
        // Calculate confidence based on data completeness and variance
        let available_components = components.len();
        let total_components = 8; // Expected number of components

        let completeness = available_components as f64 / total_components as f64;

        // Calculate variance (lower variance = higher confidence)
        let values: Vec<f64> = components.values().cloned().collect();
        if values.is_empty() {
            return 0.0;
        }
        let mean = values.iter().sum::<f64>() / values.len() as f64;
        let variance = values.iter().map(|v| (v - mean).powi(2)).sum::<f64>() / values.len() as f64;

        let consistency = 1.0 / (1.0 + variance); // Lower variance = higher consistency

        (completeness * 0.6 + consistency * 0.4).min(1.0)
    }

    fn add_to_history(&mut self, score: RiskScore) {
        self.historical_scores.push(score);

        if self.historical_scores.len() > self.max_history_size {
            self.historical_scores.remove(0);
        }
    }

    fn adapt_weights(&mut self) {
        if self.historical_scores.len() < 10 {
            return;
        }

        // Simple adaptation: increase weights for components that frequently contribute to high risk
        let recent_scores =
            &self.historical_scores[self.historical_scores.len().saturating_sub(10)..];

        // Collect adjustments first to avoid borrowing conflicts
        let mut adjustments = Vec::new();
        let component_names = [
            ("anomaly", "anomaly"),
            ("threat_intel", "threat"),
            ("behavioral", "behavioral"),
            ("network", "network"),
            ("process", "process"),
            ("file_integrity", "file"),
            ("system_health", "health"),
            ("temporal", "temporal"),
        ];

        for (component_key, search_token) in &component_names {
            let contribution_frequency = recent_scores
                .iter()
                .filter(|score| {
                    score
                        .contributing_factors
                        .iter()
                        .any(|factor| factor.to_lowercase().contains(&search_token.to_lowercase()))
                })
                .count() as f64
                / recent_scores.len() as f64;

            // Slightly adjust weight based on contribution frequency
            let adjustment = (contribution_frequency - 0.5) * 0.01; // Small adjustment
            adjustments.push((*component_key, adjustment));
        }

        // Apply adjustments
        for (component_name, adjustment) in adjustments {
            match component_name {
                "anomaly" => {
                    self.weights.anomaly_weight =
                        (self.weights.anomaly_weight + adjustment).clamp(0.01, 0.5)
                }
                "threat_intel" => {
                    self.weights.threat_intel_weight =
                        (self.weights.threat_intel_weight + adjustment).clamp(0.01, 0.5)
                }
                "behavioral" => {
                    self.weights.behavioral_weight =
                        (self.weights.behavioral_weight + adjustment).clamp(0.01, 0.5)
                }
                "network" => {
                    self.weights.network_weight =
                        (self.weights.network_weight + adjustment).clamp(0.01, 0.5)
                }
                "process" => {
                    self.weights.process_weight =
                        (self.weights.process_weight + adjustment).clamp(0.01, 0.5)
                }
                "file_integrity" => {
                    self.weights.file_integrity_weight =
                        (self.weights.file_integrity_weight + adjustment).clamp(0.01, 0.5)
                }
                "system_health" => {
                    self.weights.system_health_weight =
                        (self.weights.system_health_weight + adjustment).clamp(0.01, 0.5)
                }
                "temporal" => {
                    self.weights.temporal_weight =
                        (self.weights.temporal_weight + adjustment).clamp(0.01, 0.5)
                }
                _ => {}
            }
        }

        // Renormalize weights
        self.normalize_weights();
    }

    fn get_weight_refs(&mut self) -> Vec<(&str, &mut f64)> {
        vec![
            ("anomaly", &mut self.weights.anomaly_weight),
            ("threat", &mut self.weights.threat_intel_weight),
            ("behavioral", &mut self.weights.behavioral_weight),
            ("network", &mut self.weights.network_weight),
            ("process", &mut self.weights.process_weight),
            ("file", &mut self.weights.file_integrity_weight),
            ("health", &mut self.weights.system_health_weight),
            ("temporal", &mut self.weights.temporal_weight),
        ]
    }

    fn normalize_weights(&mut self) {
        let total_weight = self.weights.anomaly_weight
            + self.weights.threat_intel_weight
            + self.weights.behavioral_weight
            + self.weights.network_weight
            + self.weights.process_weight
            + self.weights.file_integrity_weight
            + self.weights.system_health_weight
            + self.weights.temporal_weight;

        if total_weight > 0.0 {
            let factor = 1.0 / total_weight;
            self.weights.anomaly_weight *= factor;
            self.weights.threat_intel_weight *= factor;
            self.weights.behavioral_weight *= factor;
            self.weights.network_weight *= factor;
            self.weights.process_weight *= factor;
            self.weights.file_integrity_weight *= factor;
            self.weights.system_health_weight *= factor;
            self.weights.temporal_weight *= factor;
        }
    }

    pub fn get_historical_trend(&self, hours: i64) -> Vec<RiskScore> {
        let cutoff_time = Utc::now() - chrono::Duration::hours(hours);
        self.historical_scores
            .iter()
            .filter(|score| score.timestamp > cutoff_time)
            .cloned()
            .collect()
    }

    pub fn get_current_risk_level(&self) -> Option<RiskLevel> {
        self.historical_scores
            .last()
            .map(|score| score.risk_level.clone())
    }
}

fn summarize_list(items: &[String], limit: usize) -> String {
    if items.is_empty() {
        return "-".to_string();
    }

    let limit = limit.max(1);
    if items.len() <= limit {
        return items.join(", ");
    }

    let mut parts = items.iter().take(limit).cloned().collect::<Vec<_>>();
    let remaining = items.len() - limit;
    parts.push(format!("+{} more", remaining));
    parts.join(", ")
}

/// Risk Scoring Manager with async support
#[derive(Debug)]
pub struct RiskScoringManager {
    engine: Arc<RwLock<RiskScoringEngine>>,
}

#[allow(dead_code)]
impl RiskScoringManager {
    pub fn new() -> Self {
        Self {
            engine: Arc::new(RwLock::new(RiskScoringEngine::new())),
        }
    }

    pub async fn calculate_risk(&self, system_state: &SystemState) -> RiskScore {
        let mut engine = self.engine.write().await;
        engine.calculate_risk(system_state)
    }

    pub async fn get_historical_trend(&self, hours: i64) -> Vec<RiskScore> {
        let engine = self.engine.read().await;
        engine.get_historical_trend(hours)
    }

    pub async fn get_current_risk_level(&self) -> Option<RiskLevel> {
        let engine = self.engine.read().await;
        engine.get_current_risk_level()
    }

    pub async fn update_weights(&self, weights: RiskWeights) {
        let mut engine = self.engine.write().await;
        engine.weights = weights;
    }

    pub async fn enable_adaptive_scoring(&self, enabled: bool) {
        let mut engine = self.engine.write().await;
        engine.adaptive_enabled = enabled;
    }
}
