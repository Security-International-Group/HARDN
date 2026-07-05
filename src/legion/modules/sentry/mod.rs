//! Sentry: high-value file drift detector ("tattletale phase 1").
//!
//! Watches a small, hand-picked list of files that an attacker would have to
//! touch to establish persistence on a typical Linux host:
//!
//! * `/etc/passwd`, `/etc/shadow`   — new accounts, locked-account changes
//! * `/etc/sudoers`, `/etc/sudoers.d/*` — privilege grants
//! * `/root/.ssh/authorized_keys`, `/home/*/.ssh/authorized_keys` — SSH backdoor
//! * `/etc/cron.{d,daily,hourly,weekly,monthly}/*`, `/var/spool/cron/*`
//!     — scheduled task persistence
//! * `/etc/systemd/system/*.{service,timer}`,
//!   `/etc/systemd/system/*.{service,timer}.d/*.conf` — service persistence
//!
//! On the first run we just persist a baseline of sha256(path) → digest into
//! `/var/lib/hardn/sentry/baseline.json`. On every subsequent run we recompute
//! and diff against the baseline; any added/removed/changed entry produces an
//! `emit_alert(...)` call so it lands in `alerts.jsonl` AND fans out to the
//! journald + webhook sinks (with dedupe — see `crate::utils::alerts`).
//!
//! Public entry point: [`run_check`]. Designed to be invoked once-per-run by
//! the cron orchestrator (`hardn --sentry-check`) so it stays decoupled from
//! the LEGION long-running daemon — failure to run it can never crash legion,
//! and the user can `hardn --sentry-check` on demand to baseline before/after
//! changes.

use crate::utils::emit_alert;
use chrono::Utc;
use glob::glob;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

/// Where the persisted baseline lives. Overridden in tests via [`SentryConfig`].
pub const DEFAULT_BASELINE_PATH: &str = "/var/lib/hardn/sentry/baseline.json";

/// Categories used to assign severity and the alert "source" string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Category {
    AuthorizedKeys,
    Sudoers,
    PasswdShadow,
    Cron,
    Systemd,
}

impl Category {
    pub fn label(self) -> &'static str {
        match self {
            Category::AuthorizedKeys => "authorized_keys",
            Category::Sudoers => "sudoers",
            Category::PasswdShadow => "passwd_shadow",
            Category::Cron => "cron",
            Category::Systemd => "systemd",
        }
    }
}

/// One watched location: either an exact path or a glob pattern.
#[derive(Debug, Clone)]
pub struct WatchSpec {
    pub category: Category,
    pub patterns: Vec<&'static str>,
}

/// Built-in watch set. Phase 1 is deliberately small — every entry here has a
/// high signal-to-noise ratio. Wider coverage is a follow-up phase.
pub fn default_watches() -> Vec<WatchSpec> {
    vec![
        WatchSpec {
            category: Category::PasswdShadow,
            patterns: vec!["/etc/passwd", "/etc/shadow", "/etc/gshadow", "/etc/group"],
        },
        WatchSpec {
            category: Category::Sudoers,
            patterns: vec!["/etc/sudoers", "/etc/sudoers.d/*"],
        },
        WatchSpec {
            category: Category::AuthorizedKeys,
            patterns: vec![
                "/root/.ssh/authorized_keys",
                "/root/.ssh/authorized_keys2",
                "/home/*/.ssh/authorized_keys",
                "/home/*/.ssh/authorized_keys2",
            ],
        },
        WatchSpec {
            category: Category::Cron,
            patterns: vec![
                "/etc/crontab",
                "/etc/cron.d/*",
                "/etc/cron.hourly/*",
                "/etc/cron.daily/*",
                "/etc/cron.weekly/*",
                "/etc/cron.monthly/*",
                "/var/spool/cron/*",
                "/var/spool/cron/crontabs/*",
            ],
        },
        WatchSpec {
            category: Category::Systemd,
            patterns: vec![
                "/etc/systemd/system/*.service",
                "/etc/systemd/system/*.timer",
                "/etc/systemd/system/*.socket",
                "/etc/systemd/system/*.path",
                "/etc/systemd/system/*.d/*.conf",
            ],
        },
    ]
}

/// Optional override knobs for tests. Production uses [`default()`].
#[derive(Debug, Clone)]
pub struct SentryConfig {
    pub baseline_path: PathBuf,
    pub watches: Vec<WatchSpec>,
}

impl Default for SentryConfig {
    fn default() -> Self {
        Self {
            baseline_path: PathBuf::from(DEFAULT_BASELINE_PATH),
            watches: default_watches(),
        }
    }
}

/// On-disk shape of the baseline. Keys are absolute paths; values are
/// `(category_label, sha256_hex)` — the label is stored so a future
/// refactor that drops or renames a category can still surface stale
/// entries on the next run.
#[derive(Debug, Default, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct Baseline {
    pub created_at: String,
    pub entries: BTreeMap<String, BaselineEntry>,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct BaselineEntry {
    pub category: String,
    pub sha256: String,
}

/// Summary returned by [`run_check`] so the CLI can print something useful.
#[derive(Debug, Default, Serialize, Clone, PartialEq, Eq)]
pub struct SentryReport {
    pub first_run: bool,
    pub watched_files: usize,
    pub added: Vec<String>,
    pub removed: Vec<String>,
    pub changed: Vec<String>,
}

impl SentryReport {
    pub fn total_changes(&self) -> usize {
        self.added.len() + self.removed.len() + self.changed.len()
    }
}

/// Hash a file's contents. Returns None on read errors (permission denied,
/// dangling symlink, etc.) — the caller treats "unreadable" as "absent" which
/// is the right behaviour for a sentry: an attacker who chmod 000's a watched
/// file deserves a "removed" alert.
fn sha256_of(path: &Path) -> Option<String> {
    let mut f = fs::File::open(path).ok()?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 8192];
    loop {
        match f.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => hasher.update(&buf[..n]),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => return None,
        }
    }
    Some(format!("{:x}", hasher.finalize()))
}

/// Expand the watch patterns against the filesystem, returning a flat
/// `path -> (category, sha256)` map.
pub fn snapshot(watches: &[WatchSpec]) -> BTreeMap<String, BaselineEntry> {
    let mut out = BTreeMap::new();
    for spec in watches {
        for pat in &spec.patterns {
            let iter = match glob(pat) {
                Ok(it) => it,
                Err(_) => continue,
            };
            for entry in iter.flatten() {
                if entry.is_file() {
                    if let Some(hex) = sha256_of(&entry) {
                        out.insert(
                            entry.display().to_string(),
                            BaselineEntry {
                                category: spec.category.label().to_string(),
                                sha256: hex,
                            },
                        );
                    }
                }
            }
        }
    }
    out
}

fn load_baseline(path: &Path) -> Option<Baseline> {
    let s = fs::read_to_string(path).ok()?;
    serde_json::from_str(&s).ok()
}

fn save_baseline(path: &Path, baseline: &Baseline) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension("tmp");
    let s = serde_json::to_string_pretty(baseline)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    fs::write(&tmp, s)?;
    fs::rename(&tmp, path)
}

/// Diff current snapshot against baseline; produce the (added, removed, changed) tuple.
pub fn diff(
    baseline: &BTreeMap<String, BaselineEntry>,
    current: &BTreeMap<String, BaselineEntry>,
) -> (Vec<String>, Vec<String>, Vec<String>) {
    let mut added = Vec::new();
    let mut removed = Vec::new();
    let mut changed = Vec::new();
    for (path, entry) in current {
        match baseline.get(path) {
            None => added.push(path.clone()),
            Some(prev) if prev.sha256 != entry.sha256 => changed.push(path.clone()),
            _ => {}
        }
    }
    for path in baseline.keys() {
        if !current.contains_key(path) {
            removed.push(path.clone());
        }
    }
    (added, removed, changed)
}

/// Run one sentry pass. On first run, writes baseline and reports
/// `first_run=true`. On subsequent runs, diffs against baseline, fires an
/// alert per changed entry, and refreshes the baseline.
pub fn run_check() -> SentryReport {
    run_with_config(&SentryConfig::default(), |sev, src, msg, key| {
        emit_alert(sev, src, msg, key);
    })
}

/// Test seam: same logic, but the alert callback and config are injectable.
pub fn run_with_config<F>(cfg: &SentryConfig, mut alert: F) -> SentryReport
where
    F: FnMut(&str, &str, &str, &str),
{
    let current = snapshot(&cfg.watches);
    let mut report = SentryReport {
        watched_files: current.len(),
        ..SentryReport::default()
    };

    let new_baseline = Baseline {
        created_at: Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        entries: current.clone(),
    };

    match load_baseline(&cfg.baseline_path) {
        None => {
            // First run — just persist the baseline.
            report.first_run = true;
            let _ = save_baseline(&cfg.baseline_path, &new_baseline);
            return report;
        }
        Some(prev) => {
            let (added, removed, changed) = diff(&prev.entries, &current);
            report.added = added.clone();
            report.removed = removed.clone();
            report.changed = changed.clone();

            for path in &added {
                fire_alert(&mut alert, &current, path, "added");
            }
            for path in &changed {
                fire_alert(&mut alert, &current, path, "changed");
            }
            for path in &removed {
                fire_alert(&mut alert, &prev.entries, path, "removed");
            }
            let _ = save_baseline(&cfg.baseline_path, &new_baseline);
        }
    }

    report
}

fn fire_alert<F>(alert: &mut F, entries: &BTreeMap<String, BaselineEntry>, path: &str, verb: &str)
where
    F: FnMut(&str, &str, &str, &str),
{
    let category_label = entries
        .get(path)
        .map(|e| e.category.as_str())
        .unwrap_or("unknown");
    let severity = match category_label {
        "authorized_keys" | "sudoers" => "critical",
        _ => "warning",
    };
    let source = format!("sentry/{}", category_label);
    let message = format!("{} {} watched file: {}", category_label, verb, path);
    // Dedupe key: per-category + per-path + per-verb. A file that ping-pongs
    // (added then removed then added) is treated as fresh news each cycle.
    let key = format!("sentry:{}:{}:{}", category_label, verb, path);
    alert(severity, &source, &message, &key);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    fn dummy_config(tmp: &Path) -> SentryConfig {
        SentryConfig {
            baseline_path: tmp.join("baseline.json"),
            watches: vec![WatchSpec {
                category: Category::Sudoers,
                patterns: vec![],
            }],
        }
    }

    #[test]
    fn first_run_writes_baseline_and_alerts_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = dummy_config(dir.path());
        let alerts: RefCell<Vec<String>> = RefCell::new(vec![]);
        let report = run_with_config(&cfg, |sev, _, msg, _| {
            alerts.borrow_mut().push(format!("{}: {}", sev, msg));
        });
        assert!(report.first_run);
        assert_eq!(alerts.borrow().len(), 0);
        assert!(cfg.baseline_path.exists());
    }

    #[test]
    fn change_emits_alert_with_correct_severity() {
        let dir = tempfile::tempdir().unwrap();
        let sudoers = dir.path().join("sudoers");
        fs::write(&sudoers, "alice ALL=(ALL) NOPASSWD: ALL\n").unwrap();

        // Pre-populate baseline manually so the test doesn't depend on glob
        let mut entries = BTreeMap::new();
        entries.insert(
            sudoers.display().to_string(),
            BaselineEntry {
                category: "sudoers".into(),
                sha256: sha256_of(&sudoers).unwrap(),
            },
        );
        let baseline = Baseline {
            created_at: "test".into(),
            entries,
        };
        let baseline_path = dir.path().join("baseline.json");
        save_baseline(&baseline_path, &baseline).unwrap();

        // Mutate the file.
        fs::write(
            &sudoers,
            "alice ALL=(ALL) NOPASSWD: ALL\nbob ALL=(ALL) NOPASSWD: ALL\n",
        )
        .unwrap();

        // Run with a synthetic watch list pointing at the temp dir.
        let watch_pat = format!("{}/sudoers", dir.path().display());
        let watches = vec![WatchSpec {
            category: Category::Sudoers,
            patterns: vec![Box::leak(watch_pat.into_boxed_str())],
        }];
        let cfg = SentryConfig {
            baseline_path: baseline_path.clone(),
            watches,
        };

        let alerts: RefCell<Vec<(String, String, String)>> = RefCell::new(vec![]);
        let report = run_with_config(&cfg, |sev, src, msg, _| {
            alerts
                .borrow_mut()
                .push((sev.into(), src.into(), msg.into()));
        });

        assert!(!report.first_run);
        assert_eq!(report.changed.len(), 1);
        assert_eq!(alerts.borrow().len(), 1);
        let (sev, src, _msg) = &alerts.borrow()[0];
        assert_eq!(sev, "critical");
        assert_eq!(src, "sentry/sudoers");
    }

    #[test]
    fn diff_reports_added_removed_changed() {
        let mut prev = BTreeMap::new();
        prev.insert(
            "/a".into(),
            BaselineEntry {
                category: "x".into(),
                sha256: "1".into(),
            },
        );
        prev.insert(
            "/b".into(),
            BaselineEntry {
                category: "x".into(),
                sha256: "2".into(),
            },
        );
        let mut cur = BTreeMap::new();
        cur.insert(
            "/a".into(),
            BaselineEntry {
                category: "x".into(),
                sha256: "1".into(),
            },
        );
        cur.insert(
            "/c".into(),
            BaselineEntry {
                category: "x".into(),
                sha256: "3".into(),
            },
        );
        let (added, removed, changed) = diff(&prev, &cur);
        assert_eq!(added, vec!["/c"]);
        assert_eq!(removed, vec!["/b"]);
        assert!(changed.is_empty());
    }
}
