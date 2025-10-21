use crate::legion::core::collectors::{
    CpuTelemetrySource, DatabaseTelemetrySource, MemoryTelemetrySource,
};
use crate::legion::core::framework::{BaselineSnapshot, LegionCore};
use crate::legion::core::heuristics::{
    AnomalyRateHeuristic, CpuSaturationHeuristic, DatabaseGrowthHeuristic, DatabaseHealthHeuristic,
    MemoryPressureHeuristic,
};
use crate::legion::core::responders::NoopResponder;

/// Build the default sequential Legion pipeline with database telemetry support.
pub fn build_default_core(
    baseline: Option<BaselineSnapshot>,
    allow_automatic_response: bool,
    baseline_manager: std::sync::Arc<super::baseline::BaselineManager>,
) -> LegionCore {
    let mut builder = LegionCore::builder().allow_automatic_response(allow_automatic_response);

    if let Some(baseline) = baseline {
        builder = builder.baseline(baseline);
    }

    builder
        .with_source(CpuTelemetrySource::default())
        .with_source(MemoryTelemetrySource::default())
        .with_source(DatabaseTelemetrySource::new(baseline_manager))
        .with_heuristic(CpuSaturationHeuristic::default())
        .with_heuristic(MemoryPressureHeuristic::default())
        .with_heuristic(DatabaseHealthHeuristic::default())
        .with_heuristic(DatabaseGrowthHeuristic::default())
        .with_heuristic(AnomalyRateHeuristic::default())
        .with_responder(NoopResponder::default())
        .build()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

   #[test]
fn pipeline_runs_collection_cycle() {
    // Use a temporary baseline directory so tests don't depend on system paths/permissions
    let mut config = crate::legion::core::config::Config::default();
    let tmp_baseline_dir = std::env::temp_dir().join(format!(
        "hardn_test_baseline_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    ));
    // escaping the baseline data if needed for CI
    std::fs::create_dir_all(&tmp_baseline_dir).expect("create temp baseline dir");
    config.baseline_dir = tmp_baseline_dir.to_string_lossy().into_owned();

    let baseline_manager =
        Arc::new(crate::legion::core::baseline::BaselineManager::new(&config).unwrap());
    let mut core = build_default_core(None, false, baseline_manager);
    let report = core
        .run_cycle()
        .expect("pipeline run should succeed with default sources");

    assert!(
        report.telemetry.len() >= 3,
        "expected cpu, memory, and database telemetry"
    );
    assert_eq!(
        report.responses.len(),
        1,
        "noop responder emits a single response outcome"
    );
  }
}
