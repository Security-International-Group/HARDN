use crate::legion::core::collectors::{CpuTelemetrySource, MemoryTelemetrySource};
use crate::legion::core::framework::{BaselineSnapshot, LegionCore};
use crate::legion::core::heuristics::{CpuSaturationHeuristic, MemoryPressureHeuristic};
use crate::legion::core::responders::NoopResponder;

/// Build the default sequential Legion pipeline with resource-conscious collectors and heuristics.
pub fn build_default_core(
    baseline: Option<BaselineSnapshot>,
    allow_automatic_response: bool,
) -> LegionCore {
    let mut builder = LegionCore::builder().allow_automatic_response(allow_automatic_response);

    if let Some(baseline) = baseline {
        builder = builder.baseline(baseline);
    }

    builder
        .with_source(CpuTelemetrySource::default())
        .with_source(MemoryTelemetrySource::default())
        .with_heuristic(CpuSaturationHeuristic::default())
        .with_heuristic(MemoryPressureHeuristic::default())
        .with_responder(NoopResponder::default())
        .build()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pipeline_runs_collection_cycle() {
        let mut core = build_default_core(None, false);
        let report = core
            .run_cycle()
            .expect("pipeline run should succeed with default sources");

        assert!(
            report.telemetry.len() >= 2,
            "expected cpu and memory telemetry"
        );
        assert_eq!(
            report.responses.len(),
            1,
            "noop responder emits a single response outcome"
        );
    }
}
