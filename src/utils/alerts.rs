//! Shared alert emission for the HARDN alert channel.
//!
//! Alerts are appended as JSON lines to `/var/log/hardn/alerts.jsonl`.
//! `hardn-gui` tails this file and shows alerts in a dedicated panel,
//! deduplicating repeats of the same condition by the `key` field.
//!
//! Producers:
//! - `hardn-monitor` (service down / restart success / restart failure)
//! - `hardn legion` daemon (risk threshold breaches, automated response)
//!
//! The protocol field set is intentionally small: `ts`, `severity`,
//! `source`, `message`, `key`. Severities used today: `info`, `warning`,
//! `error`, `critical`.

use chrono::Utc;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

/// Default path for the alert sink. Producers can override via
/// `emit_alert_to` if they need a different location (e.g. tests).
pub const DEFAULT_ALERTS_PATH: &str = "/var/log/hardn/alerts.jsonl";

/// Build one JSON-lines payload. Pure function so callers can test
/// formatting without touching disk.
pub fn build_alert_payload(
    ts: &str,
    severity: &str,
    source: &str,
    message: &str,
    key: &str,
) -> String {
    serde_json::json!({
        "ts": ts,
        "severity": severity,
        "source": source,
        "message": message,
        "key": key,
    })
    .to_string()
}

/// Append one alert to `path`. Creates parent directory and the file
/// if missing. Errors are swallowed so the alert path never affects the
/// caller's control flow.
pub fn emit_alert_to(path: &Path, severity: &str, source: &str, message: &str, key: &str) {
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let ts = Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let payload = build_alert_payload(&ts, severity, source, message, key);
    if let Ok(mut f) = fs::OpenOptions::new().create(true).append(true).open(path) {
        let _ = writeln!(f, "{}", payload);
    }
}

/// Convenience wrapper that emits to the default `/var/log/hardn/alerts.jsonl`.
pub fn emit_alert(severity: &str, source: &str, message: &str, key: &str) {
    emit_alert_to(
        &PathBuf::from(DEFAULT_ALERTS_PATH),
        severity,
        source,
        message,
        key,
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payload_is_valid_json_with_expected_fields() {
        let s = build_alert_payload(
            "2026-05-24T00:00:00Z",
            "warning",
            "hardn-monitor",
            "hardn.service is stopped",
            "svc-down:hardn.service",
        );
        let v: serde_json::Value = serde_json::from_str(&s).expect("must parse");
        assert_eq!(v["ts"], "2026-05-24T00:00:00Z");
        assert_eq!(v["severity"], "warning");
        assert_eq!(v["source"], "hardn-monitor");
        assert_eq!(v["message"], "hardn.service is stopped");
        assert_eq!(v["key"], "svc-down:hardn.service");
    }

    #[test]
    fn payload_escapes_quotes_and_newlines() {
        let s = build_alert_payload("t", "info", "src", "line with \"quote\" and\nnewline", "k");
        let v: serde_json::Value = serde_json::from_str(&s).expect("must parse");
        assert_eq!(v["message"], "line with \"quote\" and\nnewline");
    }

    #[test]
    fn emit_alert_to_writes_one_jsonl_record() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("alerts.jsonl");
        emit_alert_to(&path, "error", "test", "boom", "k1");
        emit_alert_to(&path, "warning", "test", "weak", "k2");
        let contents = fs::read_to_string(&path).expect("read alerts file");
        let lines: Vec<&str> = contents.lines().collect();
        assert_eq!(lines.len(), 2);
        let v0: serde_json::Value = serde_json::from_str(lines[0]).expect("line 0 json");
        let v1: serde_json::Value = serde_json::from_str(lines[1]).expect("line 1 json");
        assert_eq!(v0["severity"], "error");
        assert_eq!(v1["severity"], "warning");
    }
}
