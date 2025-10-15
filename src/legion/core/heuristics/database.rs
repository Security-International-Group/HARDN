use crate::legion::core::framework::{
    AnalysisContext, FindingSeverity, FrameworkError, HeuristicFinding, HeuristicModule,
    TelemetryPayload,
};

#[derive(Debug, Clone)]
pub struct DatabaseHealthHeuristic {
    max_anomaly_rate: f64,
    min_baseline_age_hours: f64,
}

impl DatabaseHealthHeuristic {
    #[allow(dead_code)]
    pub fn new(max_anomaly_rate: f64, min_baseline_age_hours: f64) -> Self {
        Self {
            max_anomaly_rate,
            min_baseline_age_hours,
        }
    }
}

impl Default for DatabaseHealthHeuristic {
    fn default() -> Self {
        Self {
            max_anomaly_rate: 0.1,        // 10% anomaly rate threshold
            min_baseline_age_hours: 25.0, // Baseline should be updated within 25 hours
        }
    }
}

impl HeuristicModule for DatabaseHealthHeuristic {
    fn id(&self) -> &'static str {
        "heuristic/database_health"
    }

    fn evaluate(
        &mut self,
        context: &AnalysisContext<'_>,
    ) -> Result<Vec<HeuristicFinding>, FrameworkError> {
        let mut findings = Vec::new();

        // Extract database metrics from telemetry
        let _db_status = extract_db_metric(context, "db_status");
        let baseline_count = extract_db_metric(context, "db_baselines").unwrap_or(0.0) as i64;
        let anomaly_count = extract_db_metric(context, "db_anomalies").unwrap_or(0.0) as i64;
        let latest_age = extract_db_metric(context, "db_latest_age");

        // Check if database is initialized (we'll check this by looking for baseline count)
        if baseline_count == 0 {
            findings.push(HeuristicFinding {
                module: self.id(),
                code: "DB_NOT_INITIALIZED".to_string(),
                summary: "Database not initialized - no baseline data available".to_string(),
                detail: Some(
                    "Run 'hardn legion --create-baseline' to initialize the database".to_string(),
                ),
                severity: FindingSeverity::Medium,
                tags: vec!["database".to_string(), "initialization".to_string()],
            });
        }

        // Check anomaly rate
        if baseline_count > 0 {
            let anomaly_rate = anomaly_count as f64 / baseline_count as f64;
            if anomaly_rate > self.max_anomaly_rate {
                let severity = if anomaly_rate > self.max_anomaly_rate * 2.0 {
                    FindingSeverity::High
                } else {
                    FindingSeverity::Medium
                };
                findings.push(HeuristicFinding {
                    module: self.id(),
                    code: "HIGH_ANOMALY_RATE".to_string(),
                    summary: format!(
                        "High anomaly rate: {:.1}% ({}/{}) exceeds threshold {:.1}%",
                        anomaly_rate * 100.0,
                        anomaly_count,
                        baseline_count,
                        self.max_anomaly_rate * 100.0
                    ),
                    detail: Some(format!("anomaly_rate={:.3}", anomaly_rate)),
                    severity,
                    tags: vec!["database".to_string(), "anomalies".to_string()],
                });
            }
        }

        // Check baseline freshness
        if let Some(age) = latest_age {
            if age > self.min_baseline_age_hours {
                let severity = if age > self.min_baseline_age_hours * 2.0 {
                    FindingSeverity::High
                } else {
                    FindingSeverity::Medium
                };
                findings.push(HeuristicFinding {
                    module: self.id(),
                    code: "STALE_BASELINE".to_string(),
                    summary: format!(
                        "Baseline is stale: {:.1} hours old (threshold: {:.1} hours)",
                        age, self.min_baseline_age_hours
                    ),
                    detail: Some(format!("baseline_age_hours={:.1}", age)),
                    severity,
                    tags: vec!["database".to_string(), "baseline".to_string()],
                });
            }
        }

        Ok(findings)
    }
}

#[derive(Debug, Clone)]
pub struct DatabaseGrowthHeuristic {
    max_size_mb: f64,
}

impl DatabaseGrowthHeuristic {
    #[allow(dead_code)]
    pub fn new(max_size_mb: f64) -> Self {
        Self { max_size_mb }
    }
}

impl Default for DatabaseGrowthHeuristic {
    fn default() -> Self {
        Self {
            max_size_mb: 500.0, // 500 MB max
        }
    }
}

impl HeuristicModule for DatabaseGrowthHeuristic {
    fn id(&self) -> &'static str {
        "heuristic/database_growth"
    }

    fn evaluate(
        &mut self,
        context: &AnalysisContext<'_>,
    ) -> Result<Vec<HeuristicFinding>, FrameworkError> {
        let mut findings = Vec::new();

        let db_size = extract_db_metric(context, "db_size_mb");

        if let Some(size) = db_size {
            // Check maximum size
            if size > self.max_size_mb {
                findings.push(HeuristicFinding {
                    module: self.id(),
                    code: "DB_SIZE_EXCEEDED".to_string(),
                    summary: format!(
                        "Database size {:.1} MB exceeds maximum {:.1} MB",
                        size, self.max_size_mb
                    ),
                    detail: Some(format!("database_size_mb={:.1}", size)),
                    severity: FindingSeverity::High,
                    tags: vec!["database".to_string(), "size".to_string()],
                });
            }

            // Note: Growth rate would require historical data comparison
            // This could be enhanced with trend analysis in the future
        }

        Ok(findings)
    }
}

#[derive(Debug, Clone)]
pub struct AnomalyRateHeuristic {
    critical_threshold: f64,
    warning_threshold: f64,
    time_window_hours: f64,
}

impl AnomalyRateHeuristic {
    #[allow(dead_code)]
    pub fn new(critical_threshold: f64, warning_threshold: f64, time_window_hours: f64) -> Self {
        Self {
            critical_threshold,
            warning_threshold,
            time_window_hours,
        }
    }
}

impl Default for AnomalyRateHeuristic {
    fn default() -> Self {
        Self {
            critical_threshold: 5.0, // 5 anomalies per time window
            warning_threshold: 2.0,  // 2 anomalies per time window
            time_window_hours: 24.0, // 24 hour window
        }
    }
}

impl HeuristicModule for AnomalyRateHeuristic {
    fn id(&self) -> &'static str {
        "heuristic/anomaly_rate"
    }

    fn evaluate(
        &mut self,
        context: &AnalysisContext<'_>,
    ) -> Result<Vec<HeuristicFinding>, FrameworkError> {
        let mut findings = Vec::new();

        let anomaly_count = extract_db_metric(context, "db_anomalies").unwrap_or(0.0) as i64;

        if anomaly_count > 0 {
            // Calculate rate per time window
            let rate_per_window = anomaly_count as f64 / (self.time_window_hours / 24.0); // Convert to per day for simplicity

            if rate_per_window >= self.critical_threshold {
                findings.push(HeuristicFinding {
                    module: self.id(),
                    code: "CRITICAL_ANOMALY_RATE".to_string(),
                    summary: format!(
                        "Critical anomaly rate: {:.1} per day (threshold: {:.1})",
                        rate_per_window, self.critical_threshold
                    ),
                    detail: Some(format!("anomaly_rate_per_day={:.1}", rate_per_window)),
                    severity: FindingSeverity::Critical,
                    tags: vec![
                        "database".to_string(),
                        "anomalies".to_string(),
                        "rate".to_string(),
                    ],
                });
            } else if rate_per_window >= self.warning_threshold {
                findings.push(HeuristicFinding {
                    module: self.id(),
                    code: "HIGH_ANOMALY_RATE".to_string(),
                    summary: format!(
                        "High anomaly rate: {:.1} per day (threshold: {:.1})",
                        rate_per_window, self.warning_threshold
                    ),
                    detail: Some(format!("anomaly_rate_per_day={:.1}", rate_per_window)),
                    severity: FindingSeverity::High,
                    tags: vec![
                        "database".to_string(),
                        "anomalies".to_string(),
                        "rate".to_string(),
                    ],
                });
            }
        }

        Ok(findings)
    }
}

fn extract_db_metric(context: &AnalysisContext<'_>, key: &str) -> Option<f64> {
    for record in context.telemetry {
        if let TelemetryPayload::Metric { name, value, .. } = &record.payload {
            if name == key {
                return Some(*value);
            }
        }
    }
    None
}
