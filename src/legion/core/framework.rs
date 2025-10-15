#![allow(dead_code)]

use std::collections::HashMap;
use std::fmt;
use std::time::{Duration, Instant, SystemTime};

/// Enumeration of telemetry categories delivered by Legion collectors.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TelemetryCategory {
    System,
    Process,
    Network,
    Filesystem,
    Authentication,
    Kernel,
    Container,
    ThreatIntel,
    Resource,
    Custom(String),
}

/// Structured payload for a telemetry record.
#[derive(Clone, Debug, PartialEq)]
pub enum TelemetryPayload {
    KeyValue(HashMap<String, String>),
    Metric {
        name: String,
        value: f64,
        unit: Option<String>,
    },
    Text(String),
    Binary(Vec<u8>),
    DatabaseStatus {
        status: String,
        baselines: i64,
        anomalies: i64,
        latest_age: Option<f64>,
        size_mb: f64,
    },
}

/// Atomic telemetry datum gathered during a monitoring pass.
#[derive(Clone, Debug, PartialEq)]
pub struct TelemetryRecord {
    pub source: &'static str,
    pub category: TelemetryCategory,
    pub timestamp: SystemTime,
    pub payload: TelemetryPayload,
    pub labels: Vec<String>,
}

impl TelemetryRecord {
    pub fn new(
        source: &'static str,
        category: TelemetryCategory,
        payload: TelemetryPayload,
    ) -> Self {
        Self {
            source,
            category,
            timestamp: SystemTime::now(),
            payload,
            labels: Vec::new(),
        }
    }

    pub fn with_labels(mut self, labels: Vec<String>) -> Self {
        self.labels = labels;
        self
    }
}

/// Severity assigned to a heuristic or signature finding.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum FindingSeverity {
    Informational,
    Low,
    Medium,
    High,
    Critical,
}

/// Result emitted by a heuristic module prior to consolidation.
#[derive(Clone, Debug, PartialEq)]
pub struct HeuristicFinding {
    pub module: &'static str,
    pub code: String,
    pub summary: String,
    pub detail: Option<String>,
    pub severity: FindingSeverity,
    pub tags: Vec<String>,
}

/// Result emitted by a signature module prior to consolidation.
#[derive(Clone, Debug, PartialEq)]
pub struct SignatureMatch {
    pub provider: &'static str,
    pub signature_id: String,
    pub summary: String,
    pub detail: Option<String>,
    pub severity: FindingSeverity,
    pub indicators: Vec<String>,
}

/// Unified finding type consumed by response engines and external clients.
#[derive(Clone, Debug, PartialEq)]
pub struct Finding {
    pub origin: FindingOrigin,
    pub severity: FindingSeverity,
    pub summary: String,
    pub detail: Option<String>,
    pub tags: Vec<String>,
}

impl Finding {
    fn from_heuristic(finding: HeuristicFinding) -> Self {
        let HeuristicFinding {
            module,
            code,
            summary,
            detail,
            severity,
            tags,
        } = finding;
        Self {
            origin: FindingOrigin::Heuristic { module, code },
            severity,
            summary,
            detail,
            tags,
        }
    }

    fn from_signature(matched: SignatureMatch) -> Self {
        let SignatureMatch {
            provider,
            signature_id,
            summary,
            detail,
            severity,
            indicators,
        } = matched;
        Self {
            origin: FindingOrigin::Signature {
                provider,
                signature_id,
                indicators,
            },
            severity,
            summary,
            detail,
            tags: Vec::new(),
        }
    }
}

/// Distinguishes the source of a finding for auditing and response policy.
#[derive(Clone, Debug, PartialEq)]
pub enum FindingOrigin {
    Heuristic {
        module: &'static str,
        code: String,
    },
    Signature {
        provider: &'static str,
        signature_id: String,
        indicators: Vec<String>,
    },
}

/// Result produced by a response module after evaluating findings.
#[derive(Clone, Debug, PartialEq)]
pub struct ResponseOutcome {
    pub action: ResponseAction,
    pub status: ResponseStatus,
    pub notes: Option<String>,
}

/// Descriptor for an automated or manual response action.
#[derive(Clone, Debug, PartialEq)]
pub struct ResponseAction {
    pub name: String,
    pub severity: FindingSeverity,
    pub description: Option<String>,
}

/// Execution result emitted by response engines.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResponseStatus {
    Executed,
    Skipped,
    Deferred,
}

/// Lightweight snapshot of baseline metadata supplied to modules.
#[derive(Clone, Debug, PartialEq)]
pub struct BaselineSnapshot {
    pub created_at: SystemTime,
    pub version: u64,
    pub tags: Vec<String>,
}

/// Context provided to telemetry collectors during sequential execution.
pub struct CollectionContext<'a> {
    pub baseline: Option<&'a BaselineSnapshot>,
}

/// Context provided to heuristic and signature modules.
pub struct AnalysisContext<'a> {
    pub baseline: Option<&'a BaselineSnapshot>,
    pub telemetry: &'a [TelemetryRecord],
}

/// Context provided to response modules.
pub struct ResponseContext<'a> {
    pub allow_automatic: bool,
    pub baseline: Option<&'a BaselineSnapshot>,
    pub telemetry: &'a [TelemetryRecord],
}

/// Unified error type for framework orchestration.
#[derive(Debug)]
pub enum FrameworkError {
    Collection { source: String, message: String },
    Analysis { module: String, message: String },
    Response { module: String, message: String },
}

impl FrameworkError {
    pub fn collection<S1: Into<String>, S2: Into<String>>(source: S1, message: S2) -> Self {
        Self::Collection {
            source: source.into(),
            message: message.into(),
        }
    }

    pub fn analysis<S1: Into<String>, S2: Into<String>>(module: S1, message: S2) -> Self {
        Self::Analysis {
            module: module.into(),
            message: message.into(),
        }
    }

    pub fn response<S1: Into<String>, S2: Into<String>>(module: S1, message: S2) -> Self {
        Self::Response {
            module: module.into(),
            message: message.into(),
        }
    }
}

impl fmt::Display for FrameworkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FrameworkError::Collection { source, message } => {
                write!(f, "Collection error in {}: {}", source, message)
            }
            FrameworkError::Analysis { module, message } => {
                write!(f, "Analysis error in {}: {}", module, message)
            }
            FrameworkError::Response { module, message } => {
                write!(f, "Response error in {}: {}", module, message)
            }
        }
    }
}

impl std::error::Error for FrameworkError {}

/// Contract for sequential telemetry collectors.
pub trait TelemetrySource {
    fn id(&self) -> &'static str;
    fn collect(
        &mut self,
        context: &CollectionContext<'_>,
    ) -> Result<Vec<TelemetryRecord>, FrameworkError>;
}

/// Contract for heuristic analyzers.
pub trait HeuristicModule {
    fn id(&self) -> &'static str;
    fn evaluate(
        &mut self,
        context: &AnalysisContext<'_>,
    ) -> Result<Vec<HeuristicFinding>, FrameworkError>;
}

/// Contract for signature and indicator engines.
pub trait SignatureModule {
    fn id(&self) -> &'static str;
    fn match_indicators(
        &mut self,
        context: &AnalysisContext<'_>,
    ) -> Result<Vec<SignatureMatch>, FrameworkError>;
}

/// Contract for response orchestration.
pub trait ResponseModule {
    fn id(&self) -> &'static str;
    fn respond(
        &mut self,
        context: &ResponseContext<'_>,
        findings: &[Finding],
    ) -> Result<Vec<ResponseOutcome>, FrameworkError>;
}

/// Report describing a completed monitoring cycle.
#[derive(Clone, Debug, PartialEq)]
pub struct LegionCycleReport {
    pub telemetry: Vec<TelemetryRecord>,
    pub findings: Vec<Finding>,
    pub responses: Vec<ResponseOutcome>,
    pub duration: Duration,
}

/// Core sequential orchestrator for Legion monitoring cycles.
pub struct LegionCore {
    baseline: Option<BaselineSnapshot>,
    allow_automatic_response: bool,
    sources: Vec<Box<dyn TelemetrySource + 'static>>,
    heuristics: Vec<Box<dyn HeuristicModule + 'static>>,
    signatures: Vec<Box<dyn SignatureModule + 'static>>,
    responders: Vec<Box<dyn ResponseModule + 'static>>,
}

impl LegionCore {
    pub fn builder() -> LegionCoreBuilder {
        LegionCoreBuilder::default()
    }

    pub fn baseline(&self) -> Option<&BaselineSnapshot> {
        self.baseline.as_ref()
    }

    pub fn replace_baseline(&mut self, baseline: BaselineSnapshot) {
        self.baseline = Some(baseline);
    }

    pub fn clear_baseline(&mut self) {
        self.baseline = None;
    }

    pub fn run_cycle(&mut self) -> Result<LegionCycleReport, FrameworkError> {
        let start = Instant::now();
        let collection_context = CollectionContext {
            baseline: self.baseline.as_ref(),
        };
        let mut telemetry: Vec<TelemetryRecord> = Vec::new();

        for source in &mut self.sources {
            let records = source.collect(&collection_context)?;
            telemetry.extend(records);
        }

        let mut findings: Vec<Finding> = Vec::new();
        {
            let analysis_context = AnalysisContext {
                baseline: self.baseline.as_ref(),
                telemetry: &telemetry,
            };

            for module in &mut self.heuristics {
                let outputs = module.evaluate(&analysis_context)?;
                findings.extend(outputs.into_iter().map(Finding::from_heuristic));
            }

            for module in &mut self.signatures {
                let matches = module.match_indicators(&analysis_context)?;
                findings.extend(matches.into_iter().map(Finding::from_signature));
            }
        }

        let mut responses: Vec<ResponseOutcome> = Vec::new();
        {
            let response_context = ResponseContext {
                allow_automatic: self.allow_automatic_response,
                baseline: self.baseline.as_ref(),
                telemetry: &telemetry,
            };

            for responder in &mut self.responders {
                let outcomes = responder.respond(&response_context, &findings)?;
                responses.extend(outcomes);
            }
        }

        let duration = start.elapsed();

        Ok(LegionCycleReport {
            telemetry,
            findings,
            responses,
            duration,
        })
    }
}

impl fmt::Debug for LegionCore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LegionCore")
            .field("baseline", &self.baseline)
            .field("allow_automatic_response", &self.allow_automatic_response)
            .field("sources", &self.sources.len())
            .field("heuristics", &self.heuristics.len())
            .field("signatures", &self.signatures.len())
            .field("responders", &self.responders.len())
            .finish()
    }
}

/// Builder for the LegionCore orchestrator.
#[derive(Default)]
pub struct LegionCoreBuilder {
    baseline: Option<BaselineSnapshot>,
    allow_automatic_response: bool,
    sources: Vec<Box<dyn TelemetrySource + 'static>>,
    heuristics: Vec<Box<dyn HeuristicModule + 'static>>,
    signatures: Vec<Box<dyn SignatureModule + 'static>>,
    responders: Vec<Box<dyn ResponseModule + 'static>>,
}

impl LegionCoreBuilder {
    pub fn baseline(mut self, baseline: BaselineSnapshot) -> Self {
        self.baseline = Some(baseline);
        self
    }

    pub fn allow_automatic_response(mut self, allow: bool) -> Self {
        self.allow_automatic_response = allow;
        self
    }

    pub fn with_source<T>(mut self, source: T) -> Self
    where
        T: TelemetrySource + 'static,
    {
        self.sources.push(Box::new(source));
        self
    }

    pub fn with_heuristic<T>(mut self, module: T) -> Self
    where
        T: HeuristicModule + 'static,
    {
        self.heuristics.push(Box::new(module));
        self
    }

    pub fn with_signature<T>(mut self, module: T) -> Self
    where
        T: SignatureModule + 'static,
    {
        self.signatures.push(Box::new(module));
        self
    }

    pub fn with_responder<T>(mut self, module: T) -> Self
    where
        T: ResponseModule + 'static,
    {
        self.responders.push(Box::new(module));
        self
    }

    pub fn build(self) -> LegionCore {
        LegionCore {
            baseline: self.baseline,
            allow_automatic_response: self.allow_automatic_response,
            sources: self.sources,
            heuristics: self.heuristics,
            signatures: self.signatures,
            responders: self.responders,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::rc::Rc;

    struct TestSource {
        log: Rc<RefCell<Vec<&'static str>>>,
    }

    impl TestSource {
        fn new(log: Rc<RefCell<Vec<&'static str>>>) -> Self {
            Self { log }
        }
    }

    impl TelemetrySource for TestSource {
        fn id(&self) -> &'static str {
            "test-source"
        }

        fn collect(
            &mut self,
            _context: &CollectionContext<'_>,
        ) -> Result<Vec<TelemetryRecord>, FrameworkError> {
            self.log.borrow_mut().push("collect");
            Ok(vec![TelemetryRecord::new(
                "test-source",
                TelemetryCategory::System,
                TelemetryPayload::Text("ok".to_string()),
            )])
        }
    }

    struct TestHeuristic {
        log: Rc<RefCell<Vec<&'static str>>>,
    }

    impl TestHeuristic {
        fn new(log: Rc<RefCell<Vec<&'static str>>>) -> Self {
            Self { log }
        }
    }

    impl HeuristicModule for TestHeuristic {
        fn id(&self) -> &'static str {
            "test-heuristic"
        }

        fn evaluate(
            &mut self,
            _context: &AnalysisContext<'_>,
        ) -> Result<Vec<HeuristicFinding>, FrameworkError> {
            self.log.borrow_mut().push("heuristic");
            Ok(vec![HeuristicFinding {
                module: "test-heuristic",
                code: "H001".to_string(),
                summary: "Test heuristic finding".to_string(),
                detail: None,
                severity: FindingSeverity::Medium,
                tags: vec!["test".to_string()],
            }])
        }
    }

    struct TestSignature {
        log: Rc<RefCell<Vec<&'static str>>>,
    }

    impl TestSignature {
        fn new(log: Rc<RefCell<Vec<&'static str>>>) -> Self {
            Self { log }
        }
    }

    impl SignatureModule for TestSignature {
        fn id(&self) -> &'static str {
            "test-signature"
        }

        fn match_indicators(
            &mut self,
            _context: &AnalysisContext<'_>,
        ) -> Result<Vec<SignatureMatch>, FrameworkError> {
            self.log.borrow_mut().push("signature");
            Ok(vec![SignatureMatch {
                provider: "test-signature",
                signature_id: "S001".to_string(),
                summary: "Test signature match".to_string(),
                detail: None,
                severity: FindingSeverity::High,
                indicators: vec!["indicator".to_string()],
            }])
        }
    }

    struct TestResponder {
        log: Rc<RefCell<Vec<&'static str>>>,
    }

    impl TestResponder {
        fn new(log: Rc<RefCell<Vec<&'static str>>>) -> Self {
            Self { log }
        }
    }

    impl ResponseModule for TestResponder {
        fn id(&self) -> &'static str {
            "test-responder"
        }

        fn respond(
            &mut self,
            _context: &ResponseContext<'_>,
            _findings: &[Finding],
        ) -> Result<Vec<ResponseOutcome>, FrameworkError> {
            self.log.borrow_mut().push("response");
            Ok(vec![ResponseOutcome {
                action: ResponseAction {
                    name: "test-action".to_string(),
                    severity: FindingSeverity::High,
                    description: Some("Test response".to_string()),
                },
                status: ResponseStatus::Executed,
                notes: None,
            }])
        }
    }

    #[test]
    fn executes_pipeline_in_sequence() {
        let log = Rc::new(RefCell::new(Vec::new()));

        let mut core = LegionCore::builder()
            .allow_automatic_response(true)
            .with_source(TestSource::new(log.clone()))
            .with_heuristic(TestHeuristic::new(log.clone()))
            .with_signature(TestSignature::new(log.clone()))
            .with_responder(TestResponder::new(log.clone()))
            .build();

        let report = core.run_cycle().expect("pipeline should succeed");

        assert_eq!(report.telemetry.len(), 1);
        assert_eq!(report.findings.len(), 2);
        assert_eq!(report.responses.len(), 1);

        let execution_log = log.borrow();
        assert_eq!(
            execution_log.as_slice(),
            &["collect", "heuristic", "signature", "response"]
        );
    }
}
