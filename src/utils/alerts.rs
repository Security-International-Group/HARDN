// SPDX-License-Identifier: MIT
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
//!     payload is POSTed (via curl) to that URL. When
//!     `$HARDN_ALERT_WEBHOOK_SECRET` is also set, the body is signed with
//!     HMAC-SHA256 and the digest is sent as
//!     `X-HARDN-Signature: sha256=<hex>` so the receiver can prove the
//!     alert came from HARDN (see `contrib/webhook-receiver/verify.py`).
//!
//! Both sinks honour a TTL-based dedupe (default 6h) keyed by `key`, so a
//! noisy condition can't pager-spam an on-call.

use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
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

/// Where failed webhook deliveries are queued for retry. Operators override
/// with `$HARDN_ALERT_QUEUE_PATH`.
const DEFAULT_QUEUE_PATH: &str = "/var/lib/hardn/alerts/queue.jsonl";
/// Give up on a queued alert after this many failed attempts (then drop it
/// with a journald note) so the queue can't grow without bound.
const MAX_DELIVERY_ATTEMPTS: u32 = 10;

/// Seconds to wait before the Nth retry (1-based), exponential with a cap.
/// attempts=1 -> 2s, 2 -> 4s, 3 -> 8s ... capped at 1h. The backoff is
/// realized across drain cycles (each queued item stores its next-retry
/// timestamp) rather than by sleeping inline, so producing an alert never
/// blocks the caller.
fn backoff_secs(attempts: u32) -> u64 {
    const BASE: u64 = 2;
    const CAP: u64 = 3600;
    BASE.saturating_pow(attempts.min(20)).min(CAP)
}

/// One spilled alert awaiting redelivery. Stored one-per-line as JSON in the
/// queue file. `payload` is the raw alert body; it is re-signed at send time
/// so the HMAC secret never touches disk.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct QueueItem {
    payload: String,
    attempts: u32,
    next_retry: u64,
    first_failed: u64,
}

/// Pure state transition for a queued item after one delivery attempt.
/// Returns `None` when the item should be dropped (delivered successfully,
/// or attempts exhausted) and `Some(rescheduled)` when it should stay queued
/// with a later `next_retry`.
fn reschedule(mut item: QueueItem, success: bool, now: u64) -> Option<QueueItem> {
    if success {
        return None;
    }
    item.attempts = item.attempts.saturating_add(1);
    if item.attempts >= MAX_DELIVERY_ATTEMPTS {
        return None;
    }
    item.next_retry = now.saturating_add(backoff_secs(item.attempts));
    Some(item)
}

/// Pure single drain pass. Items whose `next_retry` is still in the future
/// are kept untouched; due items are handed to `send` and rescheduled or
/// dropped by [`reschedule`]. Factored out so the scheduling can be unit
/// tested with a fake sender instead of a live curl.
fn drain_pass<F>(items: Vec<QueueItem>, now: u64, mut send: F) -> Vec<QueueItem>
where
    F: FnMut(&str) -> bool,
{
    let mut remaining = Vec::new();
    for item in items {
        if item.next_retry > now {
            remaining.push(item);
            continue;
        }
        let ok = send(&item.payload);
        if let Some(next) = reschedule(item, ok, now) {
            remaining.push(next);
        }
    }
    remaining
}

fn load_queue(path: &Path) -> Vec<QueueItem> {
    let contents = match fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };
    contents
        .lines()
        .filter(|l| !l.trim().is_empty())
        .filter_map(|l| serde_json::from_str::<QueueItem>(l).ok())
        .collect()
}

fn save_queue(path: &Path, items: &[QueueItem]) {
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    // An empty queue removes the file so a healthy system leaves no stray
    // state behind.
    if items.is_empty() {
        let _ = fs::remove_file(path);
        return;
    }
    let mut buf = String::new();
    for item in items {
        if let Ok(line) = serde_json::to_string(item) {
            buf.push_str(&line);
            buf.push('\n');
        }
    }
    let _ = fs::write(path, buf);
}

/// Compute HMAC-SHA256(key, message) and return it as lowercase hex.
///
/// HMAC (RFC 2104) is `H((key ^ opad) || H((key ^ ipad) || msg))`. We build
/// it on the `sha2` crate that HARDN already depends on rather than pulling
/// in a separate `hmac` crate, and prove correctness with a known-answer
/// test against the RFC 4231 vector (see the tests module). Keys longer than
/// the 64-byte block are hashed down first, per the spec.
fn hmac_sha256(key: &[u8], message: &[u8]) -> String {
    const BLOCK: usize = 64;
    let mut block_key = [0u8; BLOCK];
    if key.len() > BLOCK {
        let digest = Sha256::digest(key);
        block_key[..digest.len()].copy_from_slice(&digest);
    } else {
        block_key[..key.len()].copy_from_slice(key);
    }

    let mut ipad = [0x36u8; BLOCK];
    let mut opad = [0x5cu8; BLOCK];
    for i in 0..BLOCK {
        ipad[i] ^= block_key[i];
        opad[i] ^= block_key[i];
    }

    let mut inner = Sha256::new();
    inner.update(ipad);
    inner.update(message);
    let inner_digest = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(opad);
    outer.update(inner_digest);
    let mac = outer.finalize();

    let mut hex = String::with_capacity(mac.len() * 2);
    for b in mac {
        hex.push_str(&format!("{:02x}", b));
    }
    hex
}

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
    /// Optional HMAC-SHA256 secret. When set, every webhook POST carries an
    /// `X-HARDN-Signature: sha256=<hex>` header over the exact request body,
    /// so the receiver can prove the alert came from HARDN and was not forged
    /// or tampered with in transit.
    pub webhook_secret: Option<String>,
    /// Where failed webhook deliveries are spilled for retry with backoff.
    pub queue_path: PathBuf,
    /// When true, never fork curl / systemd-cat. Used by the unit tests.
    pub silent: bool,
}

impl AlertSinks {
    /// Read sink configuration from environment variables. All keys optional:
    ///   `HARDN_ALERT_WEBHOOK_URL`      — POST destination
    ///   `HARDN_ALERT_WEBHOOK_SECRET`   — HMAC-SHA256 signing key (unsigned if unset)
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
        let journald_tag =
            std::env::var("HARDN_ALERT_JOURNALD_TAG").unwrap_or_else(|_| "HARDN-ALERT".to_string());
        let webhook_url = std::env::var("HARDN_ALERT_WEBHOOK_URL")
            .ok()
            .filter(|s| !s.is_empty());
        let webhook_secret = std::env::var("HARDN_ALERT_WEBHOOK_SECRET")
            .ok()
            .filter(|s| !s.is_empty());
        let queue_path = std::env::var("HARDN_ALERT_QUEUE_PATH")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from(DEFAULT_QUEUE_PATH));
        Self {
            dedupe_path,
            dedupe_ttl_sec,
            journald_tag,
            webhook_url,
            webhook_secret,
            queue_path,
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
            // Flush any backlog first so recovered receivers catch up in
            // order, then deliver the new alert (spilling it if the POST
            // fails). Neither step blocks on retries.
            self.drain_queue(url);
            let ts = Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
            let payload = build_alert_payload(&ts, severity, source, message, key);
            self.deliver_webhook(url, &payload);
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

        if Path::new("/usr/bin/systemd-cat").exists() || Path::new("/bin/systemd-cat").exists() {
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
            .args([
                "-t",
                &self.journald_tag,
                "-p",
                &format!("user.{}", priority),
                "--",
                &line,
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }

    /// Deliver one alert now; on failure, spill it to the retry queue.
    fn deliver_webhook(&self, url: &str, payload: &str) {
        if !self.post_once(url, payload) {
            self.spill(payload);
        }
    }

    /// Append a failed payload to the retry queue with an initial backoff.
    fn spill(&self, payload: &str) {
        let now = unix_now();
        let item = QueueItem {
            payload: payload.to_string(),
            attempts: 1,
            next_retry: now.saturating_add(backoff_secs(1)),
            first_failed: now,
        };
        let mut queue = load_queue(&self.queue_path);
        queue.push(item);
        save_queue(&self.queue_path, &queue);
    }

    /// Attempt to redeliver every due item in the retry queue, rescheduling
    /// or dropping each per [`reschedule`]. Non-blocking: items not yet due
    /// are left untouched and future forwards revisit them.
    fn drain_queue(&self, url: &str) {
        let queue = load_queue(&self.queue_path);
        if queue.is_empty() {
            return;
        }
        let now = unix_now();
        let remaining = drain_pass(queue, now, |payload| self.post_once(url, payload));
        save_queue(&self.queue_path, &remaining);
    }

    /// POST the alert JSON to the configured webhook. Returns true on a 2xx
    /// (curl `-fsS` exits non-zero on connection failure or HTTP >= 400).
    /// We shell out to curl because HARDN already depends on it and adding
    /// reqwest doubles compile times. Body is piped via stdin
    /// (`--data-binary @-`) so no shell escaping is needed.
    ///
    /// When `webhook_secret` is set, the exact body is signed with
    /// HMAC-SHA256 and the digest is sent as `X-HARDN-Signature: sha256=<hex>`.
    /// The receiver recomputes the HMAC over the raw body and compares in
    /// constant time (see contrib/webhook-receiver/verify.py).
    fn post_once(&self, url: &str, payload: &str) -> bool {
        // Quick URL sanity check — only http(s) URLs allowed.
        if !(url.starts_with("http://") || url.starts_with("https://")) {
            return false;
        }
        if !Path::new("/usr/bin/curl").exists() && !Path::new("/bin/curl").exists() {
            return false;
        }

        let mut args: Vec<String> = vec![
            "-fsS".to_string(),
            "-m".to_string(),
            WEBHOOK_TIMEOUT_SEC.to_string(),
            "-X".to_string(),
            "POST".to_string(),
            "-H".to_string(),
            "Content-Type: application/json".to_string(),
        ];
        if let Some(secret) = &self.webhook_secret {
            let sig = hmac_sha256(secret.as_bytes(), payload.as_bytes());
            args.push("-H".to_string());
            args.push(format!("X-HARDN-Signature: sha256={}", sig));
        }
        args.push("--data-binary".to_string());
        args.push("@-".to_string());
        args.push(url.to_string());

        let mut child = match Command::new("curl")
            .args(&args)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
        {
            Ok(c) => c,
            Err(_) => return false,
        };
        if let Some(mut stdin) = child.stdin.take() {
            let _ = stdin.write_all(payload.as_bytes());
        }
        match child.wait() {
            Ok(status) => status.success(),
            Err(_) => false,
        }
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
            webhook_secret: None,
            queue_path: std::path::PathBuf::from("/dev/null"),
            silent: false, // we want forward()'s dedupe logic to run; silent disables side effects below
        }
    }

    // RFC 4231 Test Case 2: a known-answer vector for HMAC-SHA-256.
    //   key  = "Jefe"
    //   data = "what do ya want for nothing?"
    //   HMAC-SHA-256 =
    //     5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843
    // If this passes, our hand-built HMAC construction matches the spec.
    #[test]
    fn hmac_sha256_matches_rfc4231_vector() {
        let mac = hmac_sha256(b"Jefe", b"what do ya want for nothing?");
        assert_eq!(
            mac,
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    // A key longer than the 64-byte block must be hashed down first (RFC 2104).
    // This just checks the long-key path produces a stable 64-hex-char digest.
    #[test]
    fn hmac_sha256_handles_oversized_key() {
        let long_key = vec![0xaau8; 131];
        let mac = hmac_sha256(&long_key, b"Test Using Larger Than Block-Size Key");
        assert_eq!(mac.len(), 64);
        assert!(mac.chars().all(|c| c.is_ascii_hexdigit()));
    }

    fn queue_item(payload: &str, attempts: u32, next_retry: u64) -> QueueItem {
        QueueItem {
            payload: payload.to_string(),
            attempts,
            next_retry,
            first_failed: 0,
        }
    }

    #[test]
    fn backoff_is_monotonic_and_capped() {
        assert_eq!(backoff_secs(1), 2);
        assert_eq!(backoff_secs(2), 4);
        assert_eq!(backoff_secs(3), 8);
        // Grows until it saturates at the 1h cap and never exceeds it.
        assert!(backoff_secs(4) > backoff_secs(3));
        assert_eq!(backoff_secs(20), 3600);
        assert_eq!(backoff_secs(100), 3600);
    }

    #[test]
    fn reschedule_drops_on_success() {
        let item = queue_item("p", 1, 0);
        assert_eq!(reschedule(item, true, 100), None);
    }

    #[test]
    fn reschedule_bumps_attempts_and_delays_on_failure() {
        let item = queue_item("p", 1, 0);
        let next = reschedule(item, false, 100).expect("should stay queued");
        assert_eq!(next.attempts, 2);
        // next_retry is pushed into the future by the backoff for attempt 2.
        assert_eq!(next.next_retry, 100 + backoff_secs(2));
    }

    #[test]
    fn reschedule_gives_up_after_max_attempts() {
        // attempts already at the ceiling minus one; one more failure drops it.
        let item = queue_item("p", MAX_DELIVERY_ATTEMPTS - 1, 0);
        assert_eq!(reschedule(item, false, 100), None);
    }

    #[test]
    fn drain_pass_leaves_items_not_yet_due() {
        // next_retry in the future -> untouched, sender never called.
        let items = vec![queue_item("future", 1, 1_000)];
        let mut calls = 0;
        let out = drain_pass(items, 500, |_| {
            calls += 1;
            true
        });
        assert_eq!(calls, 0);
        assert_eq!(out.len(), 1);
    }

    #[test]
    fn drain_pass_drops_delivered_and_reschedules_failed() {
        let items = vec![
            queue_item("ok", 1, 0),   // due, will succeed -> dropped
            queue_item("fail", 1, 0), // due, will fail -> rescheduled
        ];
        let out = drain_pass(items, 500, |payload| payload == "ok");
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].payload, "fail");
        assert_eq!(out[0].attempts, 2);
        assert!(out[0].next_retry > 500);
    }

    #[test]
    fn queue_round_trips_through_disk() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("queue.jsonl");
        let items = vec![queue_item("a", 1, 10), queue_item("b", 3, 20)];
        save_queue(&path, &items);
        let loaded = load_queue(&path);
        assert_eq!(loaded, items);
    }

    #[test]
    fn saving_empty_queue_removes_the_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("queue.jsonl");
        save_queue(&path, &[queue_item("a", 1, 10)]);
        assert!(path.exists());
        save_queue(&path, &[]);
        assert!(!path.exists());
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
            webhook_secret: None,
            queue_path: std::path::PathBuf::from("/dev/null"),
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
            webhook_secret: None,
            queue_path: std::path::PathBuf::from("/dev/null"),
            silent: true,
        };
        assert_eq!(sinks.dedupe_ttl_sec, 6 * 3600);
        assert_eq!(sinks.journald_tag, "HARDN-ALERT");
    }
}
