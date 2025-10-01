use crate::legion::core::framework::{
    AnalysisContext, FindingSeverity, FrameworkError, HeuristicFinding, HeuristicModule,
    TelemetryPayload,
};

#[derive(Debug, Clone)]
pub struct CpuSaturationHeuristic {
    threshold: f64,
}

impl CpuSaturationHeuristic {
    #[allow(dead_code)]
    pub fn new(threshold: f64) -> Self {
        Self { threshold }
    }
}

impl Default for CpuSaturationHeuristic {
    fn default() -> Self {
        Self { threshold: 0.85 }
    }
}

impl HeuristicModule for CpuSaturationHeuristic {
    fn id(&self) -> &'static str {
        "heuristic/cpu"
    }

    fn evaluate(
        &mut self,
        context: &AnalysisContext<'_>,
    ) -> Result<Vec<HeuristicFinding>, FrameworkError> {
        let usage = extract_metric(context, "cpu_usage");
        let mut findings = Vec::new();

        if let Some(value) = usage {
            if value > self.threshold {
                let severity = compute_severity(value, self.threshold);
                findings.push(HeuristicFinding {
                    module: self.id(),
                    code: "CPU_HIGH".to_string(),
                    summary: format!(
                        "CPU usage {:.1}% exceeds {:.0}% threshold",
                        value * 100.0,
                        self.threshold * 100.0
                    ),
                    detail: Some(format!("cpu_usage={:.3}", value)),
                    severity,
                    tags: vec!["resource".to_string(), "cpu".to_string()],
                });
            }
        }

        Ok(findings)
    }
}

#[derive(Debug, Clone)]
pub struct MemoryPressureHeuristic {
    threshold: f64,
}

impl MemoryPressureHeuristic {
    #[allow(dead_code)]
    pub fn new(threshold: f64) -> Self {
        Self { threshold }
    }
}

impl Default for MemoryPressureHeuristic {
    fn default() -> Self {
        Self { threshold: 0.9 }
    }
}

impl HeuristicModule for MemoryPressureHeuristic {
    fn id(&self) -> &'static str {
        "heuristic/memory"
    }

    fn evaluate(
        &mut self,
        context: &AnalysisContext<'_>,
    ) -> Result<Vec<HeuristicFinding>, FrameworkError> {
        let usage = extract_metric(context, "memory_usage");
        let mut findings = Vec::new();

        if let Some(value) = usage {
            if value > self.threshold {
                let severity = compute_severity(value, self.threshold);
                findings.push(HeuristicFinding {
                    module: self.id(),
                    code: "MEMORY_PRESSURE".to_string(),
                    summary: format!(
                        "Memory usage {:.1}% exceeds {:.0}% threshold",
                        value * 100.0,
                        self.threshold * 100.0
                    ),
                    detail: Some(format!("memory_usage={:.3}", value)),
                    severity,
                    tags: vec!["resource".to_string(), "memory".to_string()],
                });
            }
        }

        Ok(findings)
    }
}

fn extract_metric(context: &AnalysisContext<'_>, name: &str) -> Option<f64> {
    context
        .telemetry
        .iter()
        .find_map(|record| match &record.payload {
            TelemetryPayload::Metric {
                name: metric_name,
                value,
                ..
            } if metric_name == name => Some(*value),
            _ => None,
        })
}

fn compute_severity(value: f64, threshold: f64) -> FindingSeverity {
    if value >= 0.95 {
        FindingSeverity::Critical
    } else if value >= 0.9 {
        FindingSeverity::High
    } else if value > threshold {
        FindingSeverity::Medium
    } else {
        FindingSeverity::Low
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::legion::core::framework::{TelemetryCategory, TelemetryRecord};

    #[test]
    fn cpu_heuristic_emits_when_above_threshold() {
        let mut heuristic = CpuSaturationHeuristic::default();
        let record = TelemetryRecord::new(
            "test",
            TelemetryCategory::Resource,
            TelemetryPayload::Metric {
                name: "cpu_usage".to_string(),
                value: 0.93,
                unit: None,
            },
        );
        let telemetry = vec![record];
        let context = AnalysisContext {
            baseline: None,
            telemetry: &telemetry,
        };
        let findings = heuristic.evaluate(&context).expect("evaluation succeeds");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, FindingSeverity::High);
    }

    #[test]
    fn memory_heuristic_ignores_low_usage() {
        let mut heuristic = MemoryPressureHeuristic::default();
        let record = TelemetryRecord::new(
            "test",
            TelemetryCategory::Resource,
            TelemetryPayload::Metric {
                name: "memory_usage".to_string(),
                value: 0.5,
                unit: None,
            },
        );
        let telemetry = vec![record];
        let context = AnalysisContext {
            baseline: None,
            telemetry: &telemetry,
        };
        let findings = heuristic.evaluate(&context).expect("evaluation succeeds");
        assert!(findings.is_empty());
    }
}
