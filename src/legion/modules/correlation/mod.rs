use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use tokio::sync::RwLock;

/// Incident Correlation Engine
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncidentCorrelator {
    pub event_window: TimeWindow,
    pub correlation_rules: Vec<CorrelationRule>,
    pub active_incidents: HashMap<String, Incident>,
    pub event_buffer: VecDeque<SecurityEvent>,
    pub max_buffer_size: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeWindow {
    pub duration_minutes: i64,
    pub max_events: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelationRule {
    pub id: String,
    pub name: String,
    pub conditions: Vec<CorrelationCondition>,
    pub correlation_logic: CorrelationLogic,
    pub incident_template: IncidentTemplate,
    pub enabled: bool,
    pub priority: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelationCondition {
    pub event_type: String,
    pub field: String,
    pub operator: ConditionOperator,
    pub value: String,
    pub weight: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ConditionOperator {
    Equals,
    Contains,
    Regex,
    GreaterThan,
    LessThan,
    In,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelationLogic {
    pub logic_type: LogicType,
    pub threshold: f64,
    pub time_window_minutes: i64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum LogicType {
    Any,      // Any condition matches
    All,      // All conditions must match
    Weighted, // Weighted sum of conditions
    Sequence, // Events in specific sequence
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncidentTemplate {
    pub title: String,
    pub description: String,
    pub severity: String,
    pub tags: Vec<String>,
    pub recommended_actions: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityEvent {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub event_type: String,
    pub source: String,
    pub severity: String,
    pub data: HashMap<String, serde_json::Value>,
    pub raw_data: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Incident {
    pub id: String,
    pub title: String,
    pub description: String,
    pub severity: String,
    pub status: IncidentStatus,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub events: Vec<SecurityEvent>,
    pub correlated_events: Vec<String>, // Event IDs
    pub tags: Vec<String>,
    pub assigned_to: Option<String>,
    pub recommended_actions: Vec<String>,
    pub confidence_score: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum IncidentStatus {
    Open,
    Investigating,
    Resolved,
    Closed,
    FalsePositive,
}

#[allow(dead_code)]
impl IncidentCorrelator {
    pub fn new(window_duration_minutes: i64, max_events: usize) -> Self {
        Self {
            event_window: TimeWindow {
                duration_minutes: window_duration_minutes,
                max_events,
            },
            correlation_rules: Vec::new(),
            active_incidents: HashMap::new(),
            event_buffer: VecDeque::new(),
            max_buffer_size: 10000,
        }
    }

    pub fn add_event(&mut self, event: SecurityEvent) {
        // Add event to buffer
        self.event_buffer.push_back(event.clone());

        // Maintain buffer size
        while self.event_buffer.len() > self.max_buffer_size {
            self.event_buffer.pop_front();
        }

        // Clean old events outside time window
        let cutoff_time = Utc::now() - Duration::minutes(self.event_window.duration_minutes);
        while let Some(event) = self.event_buffer.front() {
            if event.timestamp < cutoff_time {
                self.event_buffer.pop_front();
            } else {
                break;
            }
        }

        // Check for correlations
        self.check_correlations(event);
    }

    pub fn correlate_events(&mut self, events: Vec<SecurityEvent>) -> Vec<Incident> {
        let mut new_incidents = Vec::new();

        for event in events {
            self.add_event(event.clone());

            // Check if this event triggers any correlation rules
            for rule in &self.correlation_rules {
                if !rule.enabled {
                    continue;
                }

                if let Some(incident) = self.evaluate_rule(rule, &event) {
                    new_incidents.push(incident);
                }
            }
        }

        new_incidents
    }

    fn check_correlations(&mut self, new_event: SecurityEvent) {
        for rule in &self.correlation_rules {
            if !rule.enabled {
                continue;
            }

            if let Some(incident) = self.evaluate_rule(rule, &new_event) {
                self.active_incidents.insert(incident.id.clone(), incident);
            }
        }
    }

    fn evaluate_rule(
        &self,
        rule: &CorrelationRule,
        trigger_event: &SecurityEvent,
    ) -> Option<Incident> {
        // Get events in the time window
        let window_start =
            trigger_event.timestamp - Duration::minutes(rule.correlation_logic.time_window_minutes);
        let relevant_events: Vec<&SecurityEvent> = self
            .event_buffer
            .iter()
            .filter(|e| e.timestamp >= window_start)
            .collect();

        match rule.correlation_logic.logic_type {
            LogicType::Any => self.evaluate_any_logic(rule, &relevant_events, trigger_event),
            LogicType::All => self.evaluate_all_logic(rule, &relevant_events, trigger_event),
            LogicType::Weighted => {
                self.evaluate_weighted_logic(rule, &relevant_events, trigger_event)
            }
            LogicType::Sequence => {
                self.evaluate_sequence_logic(rule, &relevant_events, trigger_event)
            }
        }
    }

    fn evaluate_any_logic(
        &self,
        rule: &CorrelationRule,
        events: &[&SecurityEvent],
        trigger_event: &SecurityEvent,
    ) -> Option<Incident> {
        // Check if any condition matches any event
        for condition in &rule.conditions {
            for event in events {
                if self.condition_matches(condition, event) {
                    return Some(self.create_incident_from_rule(
                        rule,
                        vec![trigger_event.clone()],
                        0.8,
                    ));
                }
            }
        }
        None
    }

    fn evaluate_all_logic(
        &self,
        rule: &CorrelationRule,
        events: &[&SecurityEvent],
        _trigger_event: &SecurityEvent,
    ) -> Option<Incident> {
        // Check if all conditions are met
        let mut matched_events = Vec::new();

        for condition in &rule.conditions {
            let mut condition_met = false;
            for event in events {
                if self.condition_matches(condition, event) {
                    matched_events.push((*event).clone());
                    condition_met = true;
                    break;
                }
            }
            if !condition_met {
                return None;
            }
        }

        Some(self.create_incident_from_rule(rule, matched_events, 0.9))
    }

    fn evaluate_weighted_logic(
        &self,
        rule: &CorrelationRule,
        events: &[&SecurityEvent],
        _trigger_event: &SecurityEvent,
    ) -> Option<Incident> {
        let mut total_weight = 0.0;
        let mut matched_events = Vec::new();

        for condition in &rule.conditions {
            for event in events {
                if self.condition_matches(condition, event) {
                    total_weight += condition.weight;
                    matched_events.push((*event).clone());
                    break; // Only count each condition once
                }
            }
        }

        if total_weight >= rule.correlation_logic.threshold {
            Some(self.create_incident_from_rule(
                rule,
                matched_events,
                (total_weight / rule.conditions.len() as f64).min(1.0),
            ))
        } else {
            None
        }
    }

    fn evaluate_sequence_logic(
        &self,
        rule: &CorrelationRule,
        events: &[&SecurityEvent],
        _trigger_event: &SecurityEvent,
    ) -> Option<Incident> {
        // Check if events occur in specific sequence (simplified implementation)
        if rule.conditions.len() < 2 {
            return None;
        }

        let mut sequence_matched = true;
        let mut matched_events = Vec::new();

        for (_i, condition) in rule.conditions.iter().enumerate() {
            let mut found = false;
            for event in events {
                if self.condition_matches(condition, event) {
                    matched_events.push((*event).clone());
                    found = true;
                    break;
                }
            }
            if !found {
                sequence_matched = false;
                break;
            }
        }

        if sequence_matched {
            Some(self.create_incident_from_rule(rule, matched_events, 0.95))
        } else {
            None
        }
    }

    fn condition_matches(&self, condition: &CorrelationCondition, event: &SecurityEvent) -> bool {
        // Check if event type matches
        if event.event_type != condition.event_type {
            return false;
        }

        // Get field value from event data
        let field_value = match event.data.get(&condition.field) {
            Some(value) => value.as_str().unwrap_or(""),
            None => return false,
        };

        match condition.operator {
            ConditionOperator::Equals => field_value == condition.value,
            ConditionOperator::Contains => field_value.contains(&condition.value),
            ConditionOperator::Regex => {
                regex::Regex::new(&condition.value).map_or(false, |re| re.is_match(field_value))
            }
            ConditionOperator::GreaterThan => {
                field_value.parse::<f64>().unwrap_or(0.0)
                    > condition.value.parse::<f64>().unwrap_or(0.0)
            }
            ConditionOperator::LessThan => {
                field_value.parse::<f64>().unwrap_or(0.0)
                    < condition.value.parse::<f64>().unwrap_or(0.0)
            }
            ConditionOperator::In => {
                let values: HashSet<&str> = condition.value.split(',').collect();
                values.contains(field_value)
            }
        }
    }

    fn create_incident_from_rule(
        &self,
        rule: &CorrelationRule,
        events: Vec<SecurityEvent>,
        confidence: f64,
    ) -> Incident {
        let event_ids: Vec<String> = events.iter().map(|e| e.id.clone()).collect();

        Incident {
            id: uuid::Uuid::new_v4().to_string(),
            title: rule.incident_template.title.clone(),
            description: rule.incident_template.description.clone(),
            severity: rule.incident_template.severity.clone(),
            status: IncidentStatus::Open,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            events: events.clone(),
            correlated_events: event_ids,
            tags: rule.incident_template.tags.clone(),
            assigned_to: None,
            recommended_actions: rule.incident_template.recommended_actions.clone(),
            confidence_score: confidence,
        }
    }

    pub fn add_correlation_rule(&mut self, rule: CorrelationRule) {
        self.correlation_rules.push(rule);
        self.correlation_rules
            .sort_by(|a, b| b.priority.cmp(&a.priority));
    }

    pub fn get_active_incidents(&self) -> Vec<&Incident> {
        self.active_incidents.values().collect()
    }

    pub fn update_incident_status(&mut self, incident_id: &str, status: IncidentStatus) {
        if let Some(incident) = self.active_incidents.get_mut(incident_id) {
            incident.status = status;
            incident.updated_at = Utc::now();
        }
    }

    pub fn get_incident(&self, incident_id: &str) -> Option<&Incident> {
        self.active_incidents.get(incident_id)
    }

    pub fn cleanup_old_incidents(&mut self, max_age_hours: i64) {
        let cutoff_time = Utc::now() - Duration::hours(max_age_hours);
        self.active_incidents
            .retain(|_, incident| incident.created_at > cutoff_time);
    }

    pub fn get_correlation_statistics(&self) -> CorrelationStats {
        let total_events = self.event_buffer.len();
        let active_incidents = self.active_incidents.len();
        let enabled_rules = self.correlation_rules.iter().filter(|r| r.enabled).count();

        CorrelationStats {
            total_events,
            active_incidents,
            enabled_rules,
            buffer_utilization: total_events as f64 / self.max_buffer_size as f64,
        }
    }
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct CorrelationStats {
    pub total_events: usize,
    pub active_incidents: usize,
    pub enabled_rules: usize,
    pub buffer_utilization: f64,
}

/// Incident Correlation Manager with async support
#[derive(Debug)]
#[allow(dead_code)]
pub struct CorrelationManager {
    correlator: Arc<RwLock<IncidentCorrelator>>,
}

#[allow(dead_code)]
impl CorrelationManager {
    pub fn new(window_duration_minutes: i64, max_events: usize) -> Self {
        Self {
            correlator: Arc::new(RwLock::new(IncidentCorrelator::new(
                window_duration_minutes,
                max_events,
            ))),
        }
    }

    pub async fn add_event(&self, event: SecurityEvent) {
        let mut correlator = self.correlator.write().await;
        correlator.add_event(event);
    }

    pub async fn add_correlation_rule(&self, rule: CorrelationRule) {
        let mut correlator = self.correlator.write().await;
        correlator.add_correlation_rule(rule);
    }

    pub async fn get_active_incidents(&self) -> Vec<Incident> {
        let correlator = self.correlator.read().await;
        correlator
            .get_active_incidents()
            .into_iter()
            .cloned()
            .collect()
    }

    pub async fn update_incident_status(&self, incident_id: &str, status: IncidentStatus) {
        let mut correlator = self.correlator.write().await;
        correlator.update_incident_status(incident_id, status);
    }

    pub async fn get_statistics(&self) -> CorrelationStats {
        let correlator = self.correlator.read().await;
        correlator.get_correlation_statistics()
    }

    pub async fn correlate_events_batch(&self, events: Vec<SecurityEvent>) -> Vec<Incident> {
        let mut correlator = self.correlator.write().await;
        correlator.correlate_events(events)
    }
}
