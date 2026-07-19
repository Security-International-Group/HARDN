// SPDX-License-Identifier: MIT
//! Tamper-evident, append-only audit log (threat T3).
//!
//! Every privileged or mutating action appends one JSONL record whose hash
//! chains to the previous record: `hash = SHA-256(prev | seq | ts | actor |
//! action | detail)`. Editing or dropping any record breaks the chain, which
//! `verify()` detects. The file is created mode 0600 under the state dir.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};

const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Serialize, Deserialize, Clone)]
pub struct Entry {
    pub seq: u64,
    pub ts: String,
    pub actor: String,
    pub action: String,
    pub detail: String,
    pub prev: String,
    pub hash: String,
}

static LOCK: OnceLock<Mutex<()>> = OnceLock::new();

fn guard() -> &'static Mutex<()> {
    LOCK.get_or_init(|| Mutex::new(()))
}

fn path() -> PathBuf {
    crate::api::auth::state_dir().join("audit-log.jsonl")
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

fn hash_entry(seq: u64, ts: &str, actor: &str, action: &str, detail: &str, prev: &str) -> String {
    let payload = format!("{prev}|{seq}|{ts}|{actor}|{action}|{detail}");
    sha256_hex(payload.as_bytes())
}

pub fn read_all() -> Vec<Entry> {
    fs::read_to_string(path())
        .ok()
        .map(|s| {
            s.lines()
                .filter_map(|l| serde_json::from_str(l).ok())
                .collect()
        })
        .unwrap_or_default()
}

/// Append a record, chaining it to the current head. Serialized by a mutex so
/// concurrent requests cannot interleave and fork the chain.
pub fn append(actor: &str, action: &str, detail: &str) -> Entry {
    let _g = guard().lock().unwrap_or_else(|e| e.into_inner());
    let entries = read_all();
    let seq = entries.len() as u64 + 1;
    let prev = entries
        .last()
        .map(|e| e.hash.clone())
        .unwrap_or_else(|| GENESIS.to_string());
    let ts = chrono::Utc::now().to_rfc3339();
    let hash = hash_entry(seq, &ts, actor, action, detail, &prev);
    let entry = Entry {
        seq,
        ts,
        actor: actor.to_string(),
        action: action.to_string(),
        detail: detail.to_string(),
        prev,
        hash,
    };
    let p = path();
    if let Some(dir) = p.parent() {
        let _ = fs::create_dir_all(dir);
    }
    if let Ok(mut f) = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(&p)
        && let Ok(line) = serde_json::to_string(&entry)
    {
        let _ = writeln!(f, "{line}");
    }
    entry
}

/// Recompute the chain and confirm sequence, links, and hashes are intact.
pub fn verify() -> (bool, usize) {
    let entries = read_all();
    let mut prev = GENESIS.to_string();
    for (i, e) in entries.iter().enumerate() {
        if e.seq != (i as u64) + 1 || e.prev != prev {
            return (false, entries.len());
        }
        if hash_entry(e.seq, &e.ts, &e.actor, &e.action, &e.detail, &e.prev) != e.hash {
            return (false, entries.len());
        }
        prev = e.hash.clone();
    }
    (true, entries.len())
}

pub fn chain_head() -> String {
    read_all()
        .last()
        .map(|e| e.hash.clone())
        .unwrap_or_else(|| GENESIS.to_string())
}
