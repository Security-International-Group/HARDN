use crate::legion::core::baseline::BaselineManager;
use crate::legion::core::framework::{
    CollectionContext, FrameworkError, TelemetryCategory, TelemetryPayload, TelemetryRecord,
    TelemetrySource,
};
use std::sync::Arc;

#[derive(Debug)]
pub struct DatabaseTelemetrySource {
    baseline_manager: Arc<BaselineManager>,
}

impl DatabaseTelemetrySource {
    pub fn new(baseline_manager: Arc<BaselineManager>) -> Self {
        Self { baseline_manager }
    }
}

impl TelemetrySource for DatabaseTelemetrySource {
    fn id(&self) -> &'static str {
        "database"
    }

    fn collect(
        &mut self,
        _context: &CollectionContext<'_>,
    ) -> Result<Vec<TelemetryRecord>, FrameworkError> {
        let mut records = Vec::new();

        if let Ok(Some((baseline_count, anomaly_count, latest_timestamp, db_size))) =
            self.baseline_manager.get_database_stats()
        {
            let db_size_mb = db_size as f64 / (1024.0 * 1024.0);
            let latest_age_hours = latest_timestamp.map(|ts| {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs() as i64;
                ((now - ts) / 3600) as f64
            });

            records.push(TelemetryRecord::new(
                "database",
                TelemetryCategory::Resource,
                TelemetryPayload::Metric {
                    name: "db_baselines".to_string(),
                    value: baseline_count as f64,
                    unit: Some("count".to_string()),
                },
            ));

            records.push(TelemetryRecord::new(
                "database",
                TelemetryCategory::Resource,
                TelemetryPayload::Metric {
                    name: "db_anomalies".to_string(),
                    value: anomaly_count as f64,
                    unit: Some("count".to_string()),
                },
            ));

            if let Some(age) = latest_age_hours {
                records.push(TelemetryRecord::new(
                    "database",
                    TelemetryCategory::Resource,
                    TelemetryPayload::Metric {
                        name: "db_latest_age".to_string(),
                        value: age,
                        unit: Some("hours".to_string()),
                    },
                ));
            }

            records.push(TelemetryRecord::new(
                "database",
                TelemetryCategory::Resource,
                TelemetryPayload::Metric {
                    name: "db_size_mb".to_string(),
                    value: db_size_mb,
                    unit: Some("MB".to_string()),
                },
            ));
        }

        Ok(records)
    }
}
