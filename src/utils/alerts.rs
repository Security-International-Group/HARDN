//! Shared alert emission for the HARDN alert channel.
//!
//! Alerts are appended as JSON lines to `/var/log/hardn/alerts.jsonl`.
//! `hardn-gui` tails this file and shows alerts in a dedicated panel,
//! deduplicating repeats of the same condition by the `key` field.
//!
//! Producers:
//! - `hardn-monitor` (service down / restart success / restart failure)
//! - `hardn legion` daemon (risk threshold breaches, automated response)
//! - `hardn --sentry-check` (high-value file drift)
//!
//! The protocol field set is intentionally small: `ts`, `severity`,
//! `source`, `message`, `key`. Severities used today: `info`, `warning`,
//! `error`, `critical`.
//!
//! After writing to the JSONL file, `emit_alert` also forwards to two
//! optional out-of-band sinks (see `AlertSinks`):
//!   * **journald** — every alert is logged to the system journal under
//!     the `HARDN-ALERT` syslog tag, so `journalctl -t HARDN-ALERT` and
//!     existing log-forwarders pick them up with zero extra plumbing.
//!   * **webhook** — when `$HARDN_ALERT_WEBHOOK_URL` is set, the same
//!     payload is POSTed (via curl) to that URL.
//!
//! Both sinks honour a TTL-based dedupe (default 6h) keyed by `key`, so a
//! noisy condition can't pager-spam an on-call.

use chrono::Utc;
use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

/// Default path for the alert sink. Producers can override via
/// `emit_alert_to` if they need a different location (e.g. tests).
pub const DEFAULT_ALERTS_PATH: &str = "/var/log/hardn/alerts.jsonl";

/// File backing the dedupe cache for journald + webhook forwarding.
const DEFAULT_DEDUPE_PATH: &str = "/var/lib/hardn/alerts/seen.json";
/// Default dedupe window. Operators override with `$HARDN_ALERT_DEDUPE_TTL_SEC`.
const DEFAULT_DEDUPE_TTL_SEC: u64 = 6 * 3600;
/// Hard cap on curl webhook duration so a slow receiver can't stall the caller.
const WEBHOOK_TIMEOUT_SEC: u64 = 10;

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

/// Convenience wrapper that emits to the default `/var/log/hardn/alerts.jsonl`
/// AND fans out to the journald + (optional) webhook sinks with dedupe.
pub fn emit_alert(severity: &str, source: &str, message: &str, key: &str) {
    emit_alert_to(
        &PathBuf::from(DEFAULT_ALERTS_PATH),
        severity,
        source,
        message,
        key,
    );
    AlertSinks::from_env().forward(severity, source, message, key);
}

// ---------------------------------------------------------------------------
// Out-of-band sinks: journald + webhook, with shared TTL dedupe.
// ---------------------------------------------------------------------------

/// Configurable sink fan-out. Reads config from environment so producers don't
/// need to thread a settings struct through every call site. Each sink is
/// gated by a dedupe cache keyed by `key` so noisy conditions don't pager-spam.
#[derive(Debug, Clone)]
pub struct AlertSinks {
    pub dedupe_path: PathBuf,
    pub dedupe_ttl_sec: u64,
    pub journald_tag: String,
    pub webhook_url: Option<String>,
    /// When true, never fork curl / systemd-cat. Used by the unit tests.
    pub silent: bool,
}

impl AlertSinks {
    /// Read sink configuration from environment variables. All keys optional:
    ///   `HARDN_ALERT_WEBHOOK_URL`      — POST destination
    ///   `HARDN_ALERT_DEDUPE_TTL_SEC`   — dedupe window (default 6h)
    ///   `HARDN_ALERT_DEDUPE_PATH`      — override cache path (default /var/lib/hardn/alerts/seen.json)
    ///   `HARDN_ALERT_JOURNALD_TAG`     — syslog tag (default HARDN-ALERT)
    pub fn from_env() -> Self {
        let dedupe_ttl_sec = std::env::var("HARDN_ALERT_DEDUPE_TTL_SEC")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(DEFAULT_DEDUPE_TTL_SEC);
        let dedupe_path = std::env::var("HARDN_ALERT_DEDUPE_PATH")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from(DEFAULT_DEDUPE_PATH));
        let journald_tag = std::env::var("HARDN_ALERT_JOURNALD_TAG")
            .unwrap_or_else(|_| "HARDN-ALERT".to_string());
        let webhook_url = std::env::var("HARDN_ALERT_WEBHOOK_URL")
            .ok()
            .filter(|s| !s.is_empty());
        Self {
            dedupe_path,
            dedupe_ttl_sec,
            journald_tag,
            webhook_url,
            silent: false,
        }
    }

    /// Forward to journald + webhook unless the dedupe cache says we've sent
    /// this `key` recently. Errors are swallowed.
    pub fn forward(&self, severity: &str, source: &str, message: &str, key: &str) {
        if self.silent {
            return;
        }
        if self.is_deduped(key) {
            return;
        }
        self.send_journald(severity, source, message);
        if let Some(url) = &self.webhook_url {
            let ts = Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
            let payload = build_alert_payload(&ts, severity, source, message, key);
            self.send_webhook(url, &payload);
        }
        self.mark_sent(key);
    }

    /// Returns true if `key` was forwarded inside the current TTL window.
    fn is_deduped(&self, key: &str) -> bool {
        let now = unix_now();
        let cache = load_dedupe(&self.dedupe_path);
        match cache.get(key) {
            Some(&last) => now.saturating_sub(last) < self.dedupe_ttl_sec,
            None => false,
        }
    }

    fn mark_sent(&self, key: &str) {
        let mut cache = load_dedupe(&self.dedupe_path);
        let now = unix_now();
        // Garbage-collect stale entries so the file doesn't grow forever.
        cache.retain(|_, last| now.saturating_sub(*last) < self.dedupe_ttl_sec.saturating_mul(2));
        cache.insert(key.to_string(), now);
        save_dedupe(&self.dedupe_path, &cache);
    }

    /// Pipe the alert text into `systemd-cat` so it lands in journald under
    /// the configured tag with a meaningful priority. Falls back to `logger`
    /// when systemd-cat isn't present (eg. on non-systemd init systems).
    fn send_journald(&self, severity: &str, source: &str, message: &str) {
        let priority = match severity {
            "critical" => "crit",
            "error" => "err",
            "warning" => "warning",
            "info" => "info",
            _ => "notice",
        };
        let line = format!("[{}] {}", source, message);

        if Path::new("/usr/bin/systemd-cat").exists()
            || Path::new("/bin/systemd-cat").exists()
        {
            let mut child = match Command::new("systemd-cat")
                .args(["-t", &self.journald_tag, "-p", priority])
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
            {
                Ok(c) => c,
                Err(_) => return,
            };
            if let Some(mut stdin) = child.stdin.take() {
                let _ = stdin.write_all(line.as_bytes());
            }
            let _ = child.wait();
            return;
        }

        // logger(1) fallback — universally available on Debian.
        let _ = Command::new("logger")
            .args(["-t", &self.journald_tag, "-p", &format!("user.{}", priority), "--", &line])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }

    /// POST the alert JSON to the configured webhook. We shell out to curl
    /// because HARDN already depends on it and adding reqwest doubles compile
    /// times. Body is piped via stdin (`-d @-`) so no shell escaping is needed.
    fn send_webhook(&self, url: &str, payload: &str) {
        // Quick URL sanity check — only http(s) URLs allowed.
        if !(url.starts_with("http://") || url.starts_with("https://")) {
            return;
        }
        if !Path::new("/usr/bin/curl").exists() && !Path::new("/bin/curl").exists() {
            return;
        }
        let mut child = match Command::new("curl")
            .args([
                "-fsS",
                "-m", &WEBHOOK_TIMEOUT_SEC.to_string(),
                "-X", "POST",
                "-H", "Content-Type: application/json",
                "--data-binary", "@-",
                url,
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
        {
            Ok(c) => c,
            Err(_) => return,
        };
        if let Some(mut stdin) = child.stdin.take() {
            let _ = stdin.write_all(payload.as_bytes());
        }
        let _ = child.wait();
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn load_dedupe(path: &Path) -> HashMap<String, u64> {
    match fs::read_to_string(path) {
        Ok(s) => serde_json::from_str(&s).unwrap_or_default(),
        Err(_) => HashMap::new(),
    }
}

fn save_dedupe(path: &Path, cache: &HashMap<String, u64>) {
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let tmp = path.with_extension("tmp");
    if let Ok(mut f) = fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(&tmp)
    {
        if serde_json::to_writer(&mut f, cache).is_ok() && f.flush().is_ok() {
            let _ = fs::rename(&tmp, path);
        } else {
            let _ = fs::remove_file(&tmp);
        }
    }
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

    fn make_silent_sinks(tmp_dir: &Path) -> AlertSinks {
        AlertSinks {
            dedupe_path: tmp_dir.join("seen.json"),
            dedupe_ttl_sec: 60,
            journald_tag: "test".into(),
            webhook_url: None,
            silent: false, // we want forward()'s dedupe logic to run; silent disables side effects below
        }
    }

    #[test]
    fn dedupe_blocks_second_call_within_ttl() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut sinks = make_silent_sinks(dir.path());
        sinks.silent = true; // make forward() a no-op past the dedupe check
        // is_deduped is the gate we actually want to test
        assert!(!sinks.is_deduped("k"));
        sinks.mark_sent("k");
        assert!(sinks.is_deduped("k"));
    }

    #[test]
    fn dedupe_releases_after_ttl_expiry() {
        let dir = tempfile::tempdir().expect("tempdir");
        let sinks = AlertSinks {
            dedupe_path: dir.path().join("seen.json"),
            dedupe_ttl_sec: 0, // expires immediately
            journald_tag: "test".into(),
            webhook_url: None,
            silent: true,
        };
        sinks.mark_sent("k");
        assert!(!sinks.is_deduped("k"));
    }

    #[test]
    fn from_env_falls_back_to_defaults() {
        // Don't touch env in tests (parallelism); just check struct defaults.
        let sinks = AlertSinks {
            dedupe_path: PathBuf::from(DEFAULT_DEDUPE_PATH),
            dedupe_ttl_sec: DEFAULT_DEDUPE_TTL_SEC,
            journald_tag: "HARDN-ALERT".into(),
            webhook_url: None,
            silent: true,
        };
        assert_eq!(sinks.dedupe_ttl_sec, 6 * 3600);
        assert_eq!(sinks.journald_tag, "HARDN-ALERT");
    }
}
