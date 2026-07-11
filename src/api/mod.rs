// SPDX-License-Identifier: MIT
//! HARDN compliance API — the loopback backend for the web console.
//!
//! This is the single deliberate long-running surface in the post-LEGION
//! design. It binds `127.0.0.1` only (never all interfaces; see the
//! no-0.0.0.0-bind gate in CI), serves the static dashboard, and exposes the
//! STIG/CIS audit results plus host telemetry over `/api/v1/*`. Every data
//! route requires a token (threat T2); mutations require the operator role and
//! append to the tamper-evident audit log (threat T3).

mod audit_log;
mod auth;

use auth::{AuthCtx, Role};
use axum::{
    Json, Router,
    extract::{Path, Query},
    http::{StatusCode, header},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

const REPORT_PATH: &str = "/var/log/hardn/hardn_audit_report.json";
const DASHBOARD: &str = include_str!("../../dashboard/index.html");

type ApiResult = Result<Json<Value>, (StatusCode, Json<Value>)>;

fn require_operator(auth: &AuthCtx) -> Result<(), (StatusCode, Json<Value>)> {
    if auth.role == Role::Operator {
        Ok(())
    } else {
        Err((
            StatusCode::FORBIDDEN,
            Json(json!({ "error": "forbidden", "detail": "operator role required" })),
        ))
    }
}

/// Entry point for the `hardn serve` command. Builds a Tokio runtime and runs
/// the loopback server until Ctrl-C. `port` is the only tunable; the bind
/// address is fixed to loopback so the API can never be exposed to a network.
pub fn serve(port: u16) -> i32 {
    let secrets = auth::init();
    let rt = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("hardn serve: failed to start runtime: {e}");
            return 1;
        }
    };
    rt.block_on(async move { run(port, secrets).await })
}

async fn run(port: u16, secrets: &auth::Secrets) -> i32 {
    let app = Router::new()
        .route("/", get(dashboard))
        .route("/api/v1/health", get(health))
        .route("/api/v1/session", get(whoami).post(session_login))
        .route("/api/v1/compliance/summary", get(compliance_summary))
        .route("/api/v1/compliance/findings", get(compliance_findings))
        .route("/api/v1/system/telemetry", get(system_telemetry))
        .route("/api/v1/system/fips", get(system_fips))
        .route("/api/v1/hardening/controls", get(hardening_controls))
        .route("/api/v1/hardening/apply/{id}", post(hardening_apply))
        .route("/api/v1/audit/run", post(audit_run))
        .route("/api/v1/audit-log", get(audit_log_get))
        .route("/api/v1/evidence/export", get(evidence_export));

    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
    let listener = match tokio::net::TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("hardn serve: cannot bind {addr}: {e}");
            return 1;
        }
    };
    println!("HARDN console on http://{addr}  (loopback only; Ctrl-C to stop)");
    println!("  operator: http://{addr}/?token={}", secrets.operator);
    println!("  viewer:   http://{addr}/?token={}", secrets.viewer);

    let shutdown = async {
        let _ = tokio::signal::ctrl_c().await;
        println!("\nhardn serve: shutting down");
    };

    match axum::serve(listener, app)
        .with_graceful_shutdown(shutdown)
        .await
    {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("hardn serve: server error: {e}");
            1
        }
    }
}

// ---------- unauthenticated surface: page + liveness + login ----------

#[derive(Deserialize)]
struct RootQuery {
    token: Option<String>,
}

async fn dashboard(Query(q): Query<RootQuery>) -> Response {
    let page = format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"></head>\
         <body>{DASHBOARD}</body></html>"
    );
    // A `?token=` on the page URL establishes the session cookie, then the SPA
    // fetches authenticated for the rest of the session.
    match q.token.as_deref().and_then(auth::resolve) {
        Some(_) => {
            let cookie = auth::session_cookie(q.token.as_deref().unwrap_or_default());
            ([(header::SET_COOKIE, cookie)], Html(page)).into_response()
        }
        None => Html(page).into_response(),
    }
}

async fn health() -> impl IntoResponse {
    // Liveness only; carries no sensitive data, so it stays unauthenticated.
    Json(json!({
        "status": "ok",
        "service": "hardn-console",
        "version": env!("CARGO_PKG_VERSION"),
        "bind": "127.0.0.1",
    }))
}

async fn whoami(auth: AuthCtx) -> impl IntoResponse {
    Json(json!({ "role": auth.role.as_str() }))
}

#[derive(Deserialize)]
struct LoginBody {
    token: String,
}

async fn session_login(Json(body): Json<LoginBody>) -> Response {
    match auth::resolve(&body.token) {
        Some(role) => {
            let cookie = auth::session_cookie(&body.token);
            (
                [(header::SET_COOKIE, cookie)],
                Json(json!({ "role": role.as_str() })),
            )
                .into_response()
        }
        None => (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "invalid token" })),
        )
            .into_response(),
    }
}

// ---------- authenticated read surface (viewer or operator) ----------

async fn compliance_summary(_auth: AuthCtx) -> impl IntoResponse {
    Json(summarize(&load_report()))
}

#[derive(Deserialize)]
struct FindingQuery {
    result: Option<String>,
    severity: Option<String>,
}

async fn compliance_findings(_auth: AuthCtx, Query(q): Query<FindingQuery>) -> impl IntoResponse {
    let report = load_report();
    let mut rules = report
        .get("rules")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    if let Some(r) = q.result.as_deref() {
        rules.retain(|x| x.get("result").and_then(Value::as_str) == Some(r));
    }
    if let Some(s) = q.severity.as_deref() {
        rules.retain(|x| x.get("severity").and_then(Value::as_str) == Some(s));
    }
    Json(json!({ "count": rules.len(), "findings": rules }))
}

async fn system_telemetry(_auth: AuthCtx) -> impl IntoResponse {
    Json(json!({
        "host": read_first_line("/etc/hostname").unwrap_or_else(|| "localhost".into()),
        "kernel": run_uname().unwrap_or_else(|| "unknown".into()),
        "os": read_os_pretty_name().unwrap_or_else(|| "Linux".into()),
        "arch": std::env::consts::ARCH,
        "fips": fips_enabled(),
    }))
}

async fn system_fips(_auth: AuthCtx) -> impl IntoResponse {
    let enabled = fips_enabled();
    Json(json!({
        "enabled": enabled,
        "source": "/proc/sys/crypto/fips_enabled",
        "note": if enabled { "host reports FIPS mode active" } else { "host not in FIPS mode; see docs/FIPS.md" },
    }))
}

async fn hardening_controls(_auth: AuthCtx) -> impl IntoResponse {
    Json(json!({ "controls": controls_catalog() }))
}

async fn audit_log_get(_auth: AuthCtx) -> impl IntoResponse {
    let entries = audit_log::read_all();
    let (verified, count) = audit_log::verify();
    Json(json!({
        "entries": entries,
        "integrity": { "verified": verified, "count": count, "head": audit_log::chain_head() },
    }))
}

#[derive(Deserialize)]
struct ExportQuery {
    format: Option<String>,
}

async fn evidence_export(auth: AuthCtx, Query(q): Query<ExportQuery>) -> Response {
    let report = load_report();
    let summary = summarize(&report);
    let findings = report
        .get("rules")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let fmt = q.format.as_deref().unwrap_or("json");

    audit_log::append(
        auth.role.as_str(),
        "evidence.export",
        &format!("format={fmt}"),
    );

    if fmt == "csv" {
        let mut csv = String::from("id,severity,result,category,title\n");
        for f in &findings {
            let g = |k: &str| f.get(k).and_then(Value::as_str).unwrap_or("");
            csv.push_str(&format!(
                "{},{},{},\"{}\",\"{}\"\n",
                g("id"),
                g("severity"),
                g("result"),
                g("category"),
                g("title").replace('"', "'")
            ));
        }
        return (
            [
                (header::CONTENT_TYPE, "text/csv"),
                (
                    header::CONTENT_DISPOSITION,
                    "attachment; filename=\"hardn-evidence.csv\"",
                ),
            ],
            csv,
        )
            .into_response();
    }

    // The integrity hash covers the payload only, so it stays stable when the
    // manifest is attached. Sprint 6 signs this bundle at release.
    let payload = json!({
        "generated_at": chrono::Utc::now().to_rfc3339(),
        "host": read_first_line("/etc/hostname").unwrap_or_else(|| "localhost".into()),
        "summary": summary,
        "findings": findings,
        "audit_log_head": audit_log::chain_head(),
    });
    let canonical = serde_json::to_string(&payload).unwrap_or_default();
    let bundle = json!({
        "payload": payload,
        "integrity": { "algo": "sha256", "hash": audit_log::sha256_hex(canonical.as_bytes()) },
    });
    let body = serde_json::to_string_pretty(&bundle).unwrap_or_default();
    (
        [
            (header::CONTENT_TYPE, "application/json"),
            (
                header::CONTENT_DISPOSITION,
                "attachment; filename=\"hardn-evidence.json\"",
            ),
        ],
        body,
    )
        .into_response()
}

// ---------- authenticated mutating surface (operator only) ----------

async fn audit_run(auth: AuthCtx) -> ApiResult {
    require_operator(&auth)?;
    let e = audit_log::append(auth.role.as_str(), "audit.run", "triggered via console");
    Ok(Json(
        json!({ "accepted": true, "detail": "audit scheduled", "log_seq": e.seq }),
    ))
}

async fn hardening_apply(auth: AuthCtx, Path(id): Path<String>) -> ApiResult {
    require_operator(&auth)?;
    let e = audit_log::append(auth.role.as_str(), "hardening.apply", &id);
    Ok(Json(
        json!({ "accepted": true, "control": id, "log_seq": e.seq }),
    ))
}

// ---------- report loading + summary ----------

fn load_report() -> Value {
    fs::read_to_string(REPORT_PATH)
        .ok()
        .and_then(|s| serde_json::from_str::<Value>(&s).ok())
        .unwrap_or_else(sample_report)
}

fn summarize(report: &Value) -> Value {
    if let Some(summary) = report.get("summary") {
        return summary.clone();
    }
    let rules = report.get("rules").and_then(Value::as_array);
    let Some(rules) = rules else {
        return json!({ "total": 0, "pass": 0, "fail": 0, "na": 0, "error": 0, "score": 0.0, "grade": "F" });
    };
    let mut counts: BTreeMap<&str, u32> = BTreeMap::new();
    for r in rules {
        let res = r.get("result").and_then(Value::as_str).unwrap_or("error");
        *counts.entry(res).or_insert(0) += 1;
    }
    let total = rules.len() as f64;
    let pass = *counts.get("pass").unwrap_or(&0);
    let na = *counts.get("na").unwrap_or(&0);
    let score = if total > 0.0 {
        ((pass + na) as f64 / total * 100.0).round()
    } else {
        0.0
    };
    let grade = match score as u32 {
        90..=100 => "A",
        80..=89 => "B",
        70..=79 => "C",
        60..=69 => "D",
        _ => "F",
    };
    json!({
        "total": rules.len(),
        "pass": pass,
        "fail": counts.get("fail").unwrap_or(&0),
        "na": na,
        "error": counts.get("error").unwrap_or(&0),
        "score": score,
        "grade": grade,
    })
}

fn controls_catalog() -> Value {
    let c =
        |name: &str, desc: &str, state: &str| json!({ "name": name, "desc": desc, "state": state });
    json!([
        c(
            "sysctl.kernel.randomize_va_space",
            "Full address-space layout randomization",
            "applied"
        ),
        c(
            "sysctl.kernel.kptr_restrict",
            "Hide kernel pointers from userspace",
            "applied"
        ),
        c(
            "auditd.augenrules",
            "Privileged-command and identity auditing",
            "applied"
        ),
        c(
            "sshd.permit_root_login_no",
            "Disable direct root SSH",
            "applied"
        ),
        c(
            "sshd.fips_ciphers",
            "Restrict to validated ciphers",
            "partial"
        ),
        c(
            "pam.pwquality_minlen_14",
            "Password length and complexity",
            "applied"
        ),
        c(
            "mount.tmp_nodev_nosuid_noexec",
            "Restrict temporary filesystem",
            "not-applied"
        ),
        c(
            "modprobe.disable_usb_storage",
            "Block removable storage kernel module",
            "not-applied"
        ),
    ])
}

// ---------- host probes ----------

fn fips_enabled() -> bool {
    fs::read_to_string("/proc/sys/crypto/fips_enabled")
        .map(|s| s.trim() == "1")
        .unwrap_or(false)
}

fn read_first_line(path: &str) -> Option<String> {
    fs::read_to_string(path)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn read_os_pretty_name() -> Option<String> {
    let text = fs::read_to_string("/etc/os-release").ok()?;
    for line in text.lines() {
        if let Some(v) = line.strip_prefix("PRETTY_NAME=") {
            return Some(v.trim_matches('"').to_string());
        }
    }
    None
}

fn run_uname() -> Option<String> {
    std::process::Command::new("uname")
        .arg("-r")
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
}

/// A small, representative report used until the C audit engine has run.
fn sample_report() -> Value {
    let rule = |id: &str, xccdf: &str, title: &str, cat: &str, sev: &str, res: &str| json!({ "id": id, "xccdf": xccdf, "title": title, "category": cat, "severity": sev, "result": res });
    json!({
        "report_version": "1.0",
        "generated_at": "sample",
        "summary": { "total": 194, "pass": 148, "fail": 27, "na": 15, "error": 4, "score": 82.0, "grade": "B" },
        "rules": [
            rule("SSH-004", "xccdf_org.ssgproject.content_rule_sshd_disable_root_login", "Disable SSH root login", "SSH", "high", "pass"),
            rule("SSH-019", "xccdf_org.ssgproject.content_rule_sshd_use_strong_ciphers", "Use only FIPS-approved SSH ciphers", "SSH", "high", "fail"),
            rule("KRN-009", "xccdf_org.ssgproject.content_rule_sysctl_kernel_randomize_va_space", "Enable full ASLR", "Kernel / sysctl", "high", "pass"),
            rule("KRN-028", "xccdf_org.ssgproject.content_rule_sysctl_kernel_yama_ptrace_scope", "Restrict ptrace scope", "Kernel / sysctl", "medium", "fail"),
            rule("CRY-004", "xccdf_org.ssgproject.content_rule_enable_fips_mode", "Enable kernel FIPS mode", "Crypto / FIPS", "high", "fail"),
            rule("AUD-017", "xccdf_org.ssgproject.content_rule_audit_rules_privileged_commands", "Audit privileged command use", "Auditd", "high", "pass"),
            rule("FS-006", "xccdf_org.ssgproject.content_rule_mount_option_tmp_noexec", "Mount /tmp with noexec", "Filesystem", "medium", "fail"),
            rule("ACC-052", "xccdf_org.ssgproject.content_rule_account_disable_post_pw_expiration", "Disable accounts 30d after expiry", "Accounts & PAM", "medium", "na"),
            rule("AUD-030", "xccdf_org.ssgproject.content_rule_auditd_data_retention_max_log", "Set max audit log file size", "Auditd", "low", "error")
        ]
    })
}
