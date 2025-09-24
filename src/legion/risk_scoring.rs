use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use chrono::{DateTime, Utc};
use std::sync::Arc;
use tokio::sync::RwLock;

/// Scoring System
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskScore {
    pub overall_score: f64,  // 0.0 to 1.0
    pub components: HashMap<String, f64>,
    pub confidence: f64,
    pub timestamp: DateTime<Utc>,
    pub risk_level: RiskLevel,
    pub contributing_factors: Vec<String>,
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
pub struct SystemState {
    pub timestamp: DateTime<Utc>,
    pub anomaly_score: f64,
    pub threat_indicators: Vec<ThreatIndicator>,
    pub behavioral_score: f64,
    pub network_score: f64,
    pub process_score: f64,
    pub file_integrity_score: f64,
    pub system_health_score: f64,
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
        let mut contributing_factors = Vec::new();

        // Calculate component scores
        let anomaly_score = self.calculate_anomaly_component(system_state, &mut contributing_factors);
        components.insert("anomaly".to_string(), anomaly_score);

        let threat_score = self.calculate_threat_component(system_state, &mut contributing_factors);
        components.insert("threat_intel".to_string(), threat_score);

        let behavioral_score = self.calculate_behavioral_component(system_state, &mut contributing_factors);
        components.insert("behavioral".to_string(), behavioral_score);

        let network_score = self.calculate_network_component(system_state, &mut contributing_factors);
        components.insert("network".to_string(), network_score);

        let process_score = self.calculate_process_component(system_state, &mut contributing_factors);
        components.insert("process".to_string(), process_score);

        let file_score = self.calculate_file_component(system_state, &mut contributing_factors);
        components.insert("file_integrity".to_string(), file_score);

        let health_score = self.calculate_health_component(system_state, &mut contributing_factors);
        components.insert("system_health".to_string(), health_score);

        let temporal_score = self.calculate_temporal_component(system_state, &mut contributing_factors);
        components.insert("temporal".to_string(), temporal_score);

        // Calculate weighted overall score
        let overall_score = self.calculate_weighted_score(&components);

        // Determine risk level
        let risk_level = self.determine_risk_level(overall_score);

        // Calculate confidence based on data completeness and consistency
        let confidence = self.calculate_confidence(&components);

        let risk_score = RiskScore {
            overall_score,
            components,
            confidence,
            timestamp: Utc::now(),
            risk_level,
            contributing_factors,
        };

        // Store in history
        self.add_to_history(risk_score.clone());

        // Adapt weights if enabled
        if self.adaptive_enabled {
            self.adapt_weights();
        }

        risk_score
    }

    fn calculate_anomaly_component(&self, state: &SystemState, factors: &mut Vec<String>) -> f64 {
        let score = state.anomaly_score;

        if score > 0.8 {
            factors.push("High anomaly detection score".to_string());
        } else if score > 0.5 {
            factors.push("Moderate anomaly detection".to_string());
        }

        score
    }

    fn calculate_threat_component(&self, state: &SystemState, factors: &mut Vec<String>) -> f64 {
        if state.threat_indicators.is_empty() {
            return 0.0;
        }

        let mut total_severity = 0.0;

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
                factors.push(format!("High confidence threat: {}", indicator.indicator_type));
            }
        }

        let avg_severity = total_severity / state.threat_indicators.len() as f64;
        avg_severity.min(1.0)
    }

    fn calculate_behavioral_component(&self, state: &SystemState, factors: &mut Vec<String>) -> f64 {
        let score = state.behavioral_score;

        if score > 0.7 {
            factors.push("Suspicious process behavior detected".to_string());
        } else if score > 0.4 {
            factors.push("Abnormal process patterns observed".to_string());
        }

        score
    }

    fn calculate_network_component(&self, state: &SystemState, factors: &mut Vec<String>) -> f64 {
        let score = state.network_score;

        if score > 0.8 {
            factors.push("Critical network security issues".to_string());
        } else if score > 0.5 {
            factors.push("Network anomalies detected".to_string());
        }

        score
    }

    fn calculate_process_component(&self, state: &SystemState, factors: &mut Vec<String>) -> f64 {
        let score = state.process_score;

        if score > 0.7 {
            factors.push("Critical process security violations".to_string());
        } else if score > 0.5 {
            factors.push("Process security concerns".to_string());
        }

        score
    }

    fn calculate_file_component(&self, state: &SystemState, factors: &mut Vec<String>) -> f64 {
        let score = state.file_integrity_score;

        if score > 0.8 {
            factors.push("File integrity severely compromised".to_string());
        } else if score > 0.5 {
            factors.push("File integrity issues detected".to_string());
        }

        score
    }

    fn calculate_health_component(&self, state: &SystemState, factors: &mut Vec<String>) -> f64 {
        let score = state.system_health_score;

        if score < 0.3 {
            factors.push("Poor system health indicators".to_string());
        }

        // Invert health score for risk (lower health = higher risk)
        1.0 - score
    }

    fn calculate_temporal_component(&self, _state: &SystemState, factors: &mut Vec<String>) -> f64 {
        if self.historical_scores.len() < 5 {
            return 0.0;
        }

        // Calculate trend in risk scores over last few measurements
        let recent_scores: Vec<f64> = self.historical_scores
            .iter()
            .rev()
            .take(5)
            .map(|s| s.overall_score)
            .collect();

        let trend = self.calculate_trend(&recent_scores);

        if trend > 0.2 {
            factors.push("Risk score trending upward".to_string());
        } else if trend < -0.2 {
            factors.push("Risk score trending downward".to_string());
        }

        trend.abs().min(1.0)
    }

    fn calculate_trend(&self, scores: &[f64]) -> f64 {
        if scores.len() < 2 {
            return 0.0;
        }

        let mut trend = 0.0;
        for i in 1..scores.len() {
            trend += scores[i] - scores[i-1];
        }

        trend / (scores.len() - 1) as f64
    }

    fn calculate_weighted_score(&self, components: &HashMap<String, f64>) -> f64 {
        let mut total_score = 0.0;
        let mut total_weight = 0.0;

        total_score += components.get("anomaly").unwrap_or(&0.0) * self.weights.anomaly_weight;
        total_weight += self.weights.anomaly_weight;

        total_score += components.get("threat_intel").unwrap_or(&0.0) * self.weights.threat_intel_weight;
        total_weight += self.weights.threat_intel_weight;

        total_score += components.get("behavioral").unwrap_or(&0.0) * self.weights.behavioral_weight;
        total_weight += self.weights.behavioral_weight;

        total_score += components.get("network").unwrap_or(&0.0) * self.weights.network_weight;
        total_weight += self.weights.network_weight;

        total_score += components.get("process").unwrap_or(&0.0) * self.weights.process_weight;
        total_weight += self.weights.process_weight;

        total_score += components.get("file_integrity").unwrap_or(&0.0) * self.weights.file_integrity_weight;
        total_weight += self.weights.file_integrity_weight;

        total_score += components.get("system_health").unwrap_or(&0.0) * self.weights.system_health_weight;
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
        let mean = values.iter().sum::<f64>() / values.len() as f64;
        let variance = values.iter()
            .map(|v| (v - mean).powi(2))
            .sum::<f64>() / values.len() as f64;

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
        let recent_scores = &self.historical_scores[self.historical_scores.len().saturating_sub(10)..];

        // Collect adjustments first to avoid borrowing conflicts
        let mut adjustments = Vec::new();
        let component_names = ["anomaly", "threat", "behavioral", "network", "process", "file", "health", "temporal"];

        for component_name in &component_names {
            let contribution_frequency = recent_scores
                .iter()
                .filter(|score| {
                    score.contributing_factors.iter()
                        .any(|factor| factor.to_lowercase().contains(&component_name.to_lowercase()))
                })
                .count() as f64 / recent_scores.len() as f64;

            // Slightly adjust weight based on contribution frequency
            let adjustment = (contribution_frequency - 0.5) * 0.01; // Small adjustment
            adjustments.push((*component_name, adjustment));
        }

        // Apply adjustments
        for (component_name, adjustment) in adjustments {
            match component_name {
                "anomaly" => self.weights.anomaly_weight = (self.weights.anomaly_weight + adjustment).max(0.01).min(0.5),
                "threat" => self.weights.threat_intel_weight = (self.weights.threat_intel_weight + adjustment).max(0.01).min(0.5),
                "behavioral" => self.weights.behavioral_weight = (self.weights.behavioral_weight + adjustment).max(0.01).min(0.5),
                "network" => self.weights.network_weight = (self.weights.network_weight + adjustment).max(0.01).min(0.5),
                "process" => self.weights.process_weight = (self.weights.process_weight + adjustment).max(0.01).min(0.5),
                "file" => self.weights.file_integrity_weight = (self.weights.file_integrity_weight + adjustment).max(0.01).min(0.5),
                "health" => self.weights.system_health_weight = (self.weights.system_health_weight + adjustment).max(0.01).min(0.5),
                "temporal" => self.weights.temporal_weight = (self.weights.temporal_weight + adjustment).max(0.01).min(0.5),
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
        let total_weight = self.weights.anomaly_weight +
                          self.weights.threat_intel_weight +
                          self.weights.behavioral_weight +
                          self.weights.network_weight +
                          self.weights.process_weight +
                          self.weights.file_integrity_weight +
                          self.weights.system_health_weight +
                          self.weights.temporal_weight;

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
        self.historical_scores.last().map(|score| score.risk_level.clone())
    }
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