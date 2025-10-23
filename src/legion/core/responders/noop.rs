use crate::legion::core::framework::{
    Finding, FindingSeverity, FrameworkError, ResponseAction, ResponseContext, ResponseModule,
    ResponseOutcome, ResponseStatus,
};

#[derive(Debug, Default, Clone)]
pub struct NoopResponder;

impl ResponseModule for NoopResponder {
    fn id(&self) -> &'static str {
        "responder/noop"
    }

    fn respond(
        &mut self,
        _context: &ResponseContext<'_>,
        _findings: &[Finding],
    ) -> Result<Vec<ResponseOutcome>, FrameworkError> {
        Ok(vec![ResponseOutcome {
            action: ResponseAction {
                name: "noop".to_string(),
                severity: FindingSeverity::Informational,
                description: Some("No automatic response configured".to_string()),
            },
            status: ResponseStatus::Skipped,
            notes: None,
        }])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::legion::core::framework::{TelemetryCategory, TelemetryPayload, TelemetryRecord};

    #[test]
    fn noop_responder_skips_actions() {
        let mut responder = NoopResponder;
        let telemetry = vec![TelemetryRecord::new(
            "test",
            TelemetryCategory::System,
            TelemetryPayload::Text("ok".to_string()),
        )];
        let context = ResponseContext {
            allow_automatic: false,
            baseline: None,
            telemetry: &telemetry,
        };
        let outcomes = responder
            .respond(&context, &[])
            .expect("responder should succeed");
        assert_eq!(outcomes.len(), 1);
        assert_eq!(outcomes[0].status, ResponseStatus::Skipped);
    }
}
