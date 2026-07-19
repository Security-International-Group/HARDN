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
use std::env;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::process::Command;

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
        .route("/api/v1/hardening/revert/{id}", post(hardening_revert))
        .route("/api/v1/system/uninstall", post(system_uninstall))
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
    match tokio::task::spawn_blocking(run_engine).await {
        Ok(Ok(n)) => {
            let e = audit_log::append(
                auth.role.as_str(),
                "audit.run",
                &format!("engine run, {n} rules"),
            );
            Ok(Json(
                json!({ "accepted": true, "rules": n, "log_seq": e.seq }),
            ))
        }
        Ok(Err(msg)) => {
            audit_log::append(
                auth.role.as_str(),
                "audit.run",
                &format!("engine error: {msg}"),
            );
            Ok(Json(json!({ "accepted": false, "detail": msg })))
        }
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": format!("task join error: {e}") })),
        )),
    }
}

async fn hardening_apply(auth: AuthCtx, Path(id): Path<String>) -> ApiResult {
    require_operator(&auth)?;
    let id2 = id.clone();
    match tokio::task::spawn_blocking(move || run_apply(&id2)).await {
        Ok(Ok(detail)) => {
            let e = audit_log::append(
                auth.role.as_str(),
                "hardening.apply",
                &format!("{id}: {detail}"),
            );
            Ok(Json(
                json!({ "accepted": true, "control": id, "detail": detail, "log_seq": e.seq }),
            ))
        }
        Ok(Err(err)) => {
            audit_log::append(
                auth.role.as_str(),
                "hardening.apply.failed",
                &format!("{id}: {err}"),
            );
            Ok(Json(
                json!({ "accepted": false, "control": id, "error": err }),
            ))
        }
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": format!("task join error: {e}") })),
        )),
    }
}

async fn hardening_revert(auth: AuthCtx, Path(id): Path<String>) -> ApiResult {
    require_operator(&auth)?;
    let id2 = id.clone();
    match tokio::task::spawn_blocking(move || run_revert(&id2)).await {
        Ok(Ok(detail)) => {
            let e = audit_log::append(
                auth.role.as_str(),
                "hardening.revert",
                &format!("{id}: {detail}"),
            );
            Ok(Json(
                json!({ "accepted": true, "control": id, "detail": detail, "log_seq": e.seq }),
            ))
        }
        Ok(Err(err)) => {
            audit_log::append(
                auth.role.as_str(),
                "hardening.revert.failed",
                &format!("{id}: {err}"),
            );
            Ok(Json(
                json!({ "accepted": false, "control": id, "error": err }),
            ))
        }
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": format!("task join error: {e}") })),
        )),
    }
}

async fn system_uninstall(auth: AuthCtx) -> ApiResult {
    require_operator(&auth)?;
    match tokio::task::spawn_blocking(run_uninstall).await {
        Ok(Ok(detail)) => {
            let e = audit_log::append(auth.role.as_str(), "system.uninstall", &detail);
            Ok(Json(
                json!({ "accepted": true, "detail": detail, "log_seq": e.seq }),
            ))
        }
        Ok(Err(err)) => {
            audit_log::append(auth.role.as_str(), "system.uninstall.failed", &err);
            Ok(Json(json!({ "accepted": false, "error": err })))
        }
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": format!("task join error: {e}") })),
        )),
    }
}

// ---------- report loading + summary ----------

fn report_path() -> PathBuf {
    env::var("HARDN_REPORT_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(REPORT_PATH))
}

fn load_report() -> Value {
    match fs::read_to_string(report_path())
        .ok()
        .and_then(|s| serde_json::from_str::<Value>(&s).ok())
    {
        Some(raw) => normalize(raw),
        None => sample_report(),
    }
}

/// Map the C engine's report (`status`, xccdf `id`) into the console's
/// canonical shape (`result`, short `id` + full `xccdf`) and synthesize short
/// per-category rule codes. Already-canonical input passes through unchanged.
fn normalize(raw: Value) -> Value {
    let rules = raw
        .get("rules")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut counters: BTreeMap<String, u32> = BTreeMap::new();
    let mut out = Vec::with_capacity(rules.len());
    for r in rules {
        let xccdf = r
            .get("xccdf")
            .or_else(|| r.get("id"))
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let cat = r
            .get("category")
            .and_then(Value::as_str)
            .unwrap_or("misc")
            .to_string();
        let status = r
            .get("result")
            .or_else(|| r.get("status"))
            .and_then(Value::as_str)
            .unwrap_or("error");
        let result = match status {
            "not_applicable" | "notapplicable" => "na",
            s => s,
        };
        let counter = counters.entry(cat.clone()).or_insert(0);
        *counter += 1;
        let idx = *counter;
        let prefix: String = cat
            .chars()
            .filter(|c| c.is_ascii_alphanumeric())
            .take(4)
            .collect::<String>()
            .to_uppercase();
        let prefix = if prefix.is_empty() {
            "RULE".to_string()
        } else {
            prefix
        };
        out.push(json!({
            "id": format!("{prefix}-{idx:03}"),
            "xccdf": xccdf,
            "title": r.get("title").cloned().unwrap_or_else(|| json!("")),
            "category": cat,
            "severity": r.get("severity").cloned().unwrap_or_else(|| json!("medium")),
            "result": result,
            "evidence": r.get("evidence").cloned().unwrap_or_else(|| json!("")),
        }));
    }
    json!({
        "report_version": raw.get("report_version").cloned().unwrap_or_else(|| json!("1.0")),
        "rules": out,
    })
}

/// Locate the compiled C audit engine.
fn find_engine() -> Option<PathBuf> {
    if let Ok(p) = env::var("HARDN_AUDIT_BIN") {
        let pb = PathBuf::from(p);
        if pb.is_file() {
            return Some(pb);
        }
    }
    for c in [
        "target/release/hardn-audit",
        "/usr/lib/hardn/hardn-audit",
        "/usr/libexec/hardn/hardn-audit",
    ] {
        let pb = PathBuf::from(c);
        if pb.is_file() {
            return Some(pb);
        }
    }
    None
}

/// Run the audit engine and persist its report. Returns the rule count.
fn run_engine() -> Result<usize, String> {
    let bin = find_engine().ok_or_else(|| "hardn-audit binary not found".to_string())?;
    let out = std::process::Command::new(&bin)
        .output()
        .map_err(|e| format!("failed to run engine: {e}"))?;
    if !out.status.success() {
        return Err(format!("engine exited with {}", out.status));
    }
    let path = report_path();
    if let Some(dir) = path.parent() {
        let _ = fs::create_dir_all(dir);
    }
    fs::write(&path, &out.stdout).map_err(|e| format!("cannot write report: {e}"))?;
    let v: Value =
        serde_json::from_slice(&out.stdout).map_err(|e| format!("engine output not JSON: {e}"))?;
    Ok(v.get("rules")
        .and_then(Value::as_array)
        .map(|a| a.len())
        .unwrap_or(0))
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

/// Detect the live state of each hardening control by probing the host
/// (sysctl values, running services, sshd config, FIPS). This is a real audit
/// of the running OS, not a static catalog.
enum Risk {
    Safe,
    Moderate,
    Disruptive,
}

impl Risk {
    fn as_str(&self) -> &'static str {
        match self {
            Risk::Safe => "safe",
            Risk::Moderate => "moderate",
            Risk::Disruptive => "disruptive",
        }
    }
}

enum Kind {
    Sysctl {
        key: &'static str,
        want: &'static str,
        partial: Option<&'static str>,
    },
    Service {
        unit: &'static str,
    },
    SshdRootLogin,
    Fips,
}

struct Control {
    id: &'static str,
    desc: &'static str,
    risk: Risk,
    plan: &'static str,
    revert_plan: &'static str,
    kind: Kind,
}

/// The full control catalogue. `plan`/`revert_plan` are shown in the UI before
/// anything runs; `risk` drives the confirmation prompt. Sysctl controls are
/// safe and reversible; the console records the prior value before changing it.
const CONTROLS: &[Control] = &[
    Control {
        id: "kernel.randomize_va_space",
        desc: "Full address-space layout randomization",
        risk: Risk::Safe,
        plan: "sysctl kernel.randomize_va_space=2 (runtime + /etc/sysctl.d/90-hardn.conf)",
        revert_plan: "restore the previous sysctl value",
        kind: Kind::Sysctl {
            key: "kernel.randomize_va_space",
            want: "2",
            partial: Some("1"),
        },
    },
    Control {
        id: "kernel.kptr_restrict",
        desc: "Hide kernel pointers from userspace",
        risk: Risk::Safe,
        plan: "sysctl kernel.kptr_restrict=2",
        revert_plan: "restore the previous value",
        kind: Kind::Sysctl {
            key: "kernel.kptr_restrict",
            want: "2",
            partial: Some("1"),
        },
    },
    Control {
        id: "kernel.dmesg_restrict",
        desc: "Restrict dmesg to privileged users",
        risk: Risk::Safe,
        plan: "sysctl kernel.dmesg_restrict=1",
        revert_plan: "restore the previous value",
        kind: Kind::Sysctl {
            key: "kernel.dmesg_restrict",
            want: "1",
            partial: None,
        },
    },
    Control {
        id: "net.ipv4.rp_filter",
        desc: "Reverse-path source validation",
        risk: Risk::Safe,
        plan: "sysctl net.ipv4.conf.all.rp_filter=1",
        revert_plan: "restore the previous value",
        kind: Kind::Sysctl {
            key: "net.ipv4.conf.all.rp_filter",
            want: "1",
            partial: Some("2"),
        },
    },
    Control {
        id: "service.auditd",
        desc: "Audit daemon running",
        risk: Risk::Moderate,
        plan: "systemctl enable --now auditd",
        revert_plan: "systemctl disable --now auditd",
        kind: Kind::Service { unit: "auditd" },
    },
    Control {
        id: "service.apparmor",
        desc: "AppArmor mandatory access control active",
        risk: Risk::Moderate,
        plan: "systemctl enable --now apparmor",
        revert_plan: "systemctl disable --now apparmor",
        kind: Kind::Service { unit: "apparmor" },
    },
    Control {
        id: "service.ufw",
        desc: "Host firewall active",
        risk: Risk::Disruptive,
        plan: "ufw --force enable (default deny incoming; make sure SSH is allowed)",
        revert_plan: "ufw disable",
        kind: Kind::Service { unit: "ufw" },
    },
    Control {
        id: "service.fail2ban",
        desc: "Brute-force protection active",
        risk: Risk::Moderate,
        plan: "systemctl enable --now fail2ban",
        revert_plan: "systemctl disable --now fail2ban",
        kind: Kind::Service { unit: "fail2ban" },
    },
    Control {
        id: "sshd.permit_root_login_no",
        desc: "Disable direct root SSH login",
        risk: Risk::Disruptive,
        plan: "write 'PermitRootLogin no' to sshd_config.d/10-hardn.conf and reload ssh",
        revert_plan: "remove the drop-in and reload ssh",
        kind: Kind::SshdRootLogin,
    },
    Control {
        id: "host.fips_mode",
        desc: "Kernel FIPS mode enabled",
        risk: Risk::Disruptive,
        plan: "fips-mode-setup --enable (reboot required; Ubuntu uses Ubuntu Pro)",
        revert_plan: "not auto-revertible (fips-mode-setup --disable + reboot)",
        kind: Kind::Fips,
    },
];

fn find_control(id: &str) -> Option<&'static Control> {
    CONTROLS.iter().find(|c| c.id == id)
}

fn detect(kind: &Kind) -> &'static str {
    match kind {
        Kind::Sysctl { key, want, partial } => {
            let want = *want;
            let partial = *partial;
            let path = format!("/proc/sys/{}", key.replace('.', "/"));
            match proc_val(&path).as_deref() {
                Some(v) if v == want => "applied",
                Some(v) if partial == Some(v) => "partial",
                _ => "not-applied",
            }
        }
        Kind::Service { unit } => yn(service_active(unit)),
        Kind::SshdRootLogin => yn(sshd_root_login_no()),
        Kind::Fips => yn(fips_enabled()),
    }
}

fn sshd_root_login_no() -> bool {
    let mut txt = fs::read_to_string("/etc/ssh/sshd_config").unwrap_or_default();
    if let Ok(rd) = fs::read_dir("/etc/ssh/sshd_config.d") {
        for e in rd.flatten() {
            if let Ok(s) = fs::read_to_string(e.path()) {
                txt.push('\n');
                txt.push_str(&s);
            }
        }
    }
    txt.lines().any(|l| {
        let l = l.trim();
        l.starts_with("PermitRootLogin") && l.split_whitespace().nth(1) == Some("no")
    })
}

fn controls_catalog() -> Value {
    Value::Array(
        CONTROLS
            .iter()
            .map(|c| {
                json!({
                    "name": c.id,
                    "desc": c.desc,
                    "state": detect(&c.kind),
                    "risk": c.risk.as_str(),
                    "plan": c.plan,
                    "revert_plan": c.revert_plan,
                })
            })
            .collect(),
    )
}

fn yn(applied: bool) -> &'static str {
    if applied { "applied" } else { "not-applied" }
}

fn proc_val(path: &str) -> Option<String> {
    fs::read_to_string(path)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn service_active(name: &str) -> bool {
    std::process::Command::new("systemctl")
        .args(["is-active", name])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "active")
        .unwrap_or(false)
}

// ---------- control enforcement ----------

/// Apply or revert a control. When the console runs unprivileged, the scoped
/// `hardn __enforce/__revert <id>` helper is invoked via `sudo -n` so only that
/// narrow action escalates; the web server itself never runs as root.
fn run_apply(id: &str) -> Result<String, String> {
    run_privileged(id, true)
}

fn run_revert(id: &str) -> Result<String, String> {
    run_privileged(id, false)
}

fn run_privileged(id: &str, apply: bool) -> Result<String, String> {
    if is_root() {
        return if apply {
            enforce_control(id)
        } else {
            revert_control(id)
        };
    }
    let exe = std::env::current_exe().map_err(|e| format!("cannot locate hardn binary: {e}"))?;
    let verb = if apply { "__enforce" } else { "__revert" };
    let out = Command::new("sudo")
        .arg("-n")
        .arg(&exe)
        .arg(verb)
        .arg(id)
        .output()
        .map_err(|e| format!("sudo: {e}"))?;
    let so = String::from_utf8_lossy(&out.stdout).trim().to_string();
    let se = String::from_utf8_lossy(&out.stderr).trim().to_string();
    if out.status.success() {
        Ok(if so.is_empty() { "done".into() } else { so })
    } else if se.contains("password is required") || se.starts_with("sudo:") {
        Err("needs privilege: install /etc/sudoers.d/hardn-console (see docs/CONSOLE.md) or run the console as root".into())
    } else if !se.is_empty() {
        Err(se)
    } else if !so.is_empty() {
        Err(so)
    } else {
        Err("enforcement failed".into())
    }
}

/// Root-side apply. Records the prior sysctl value before changing it so the
/// action can be reverted.
fn enforce_control(id: &str) -> Result<String, String> {
    let c = find_control(id).ok_or_else(|| format!("unknown control '{id}'"))?;
    match &c.kind {
        Kind::Sysctl { key, want, .. } => {
            let path = format!("/proc/sys/{}", key.replace('.', "/"));
            if let Some(cur) = proc_val(&path) {
                save_backup(id, &cur);
            }
            set_sysctl(key, want)
        }
        Kind::Service { unit } => enable_service(unit),
        Kind::SshdRootLogin => set_sshd("PermitRootLogin", "no"),
        Kind::Fips => enable_fips(),
    }
}

/// Root-side revert. Restores the backed-up value or removes the drop-in.
fn revert_control(id: &str) -> Result<String, String> {
    let c = find_control(id).ok_or_else(|| format!("unknown control '{id}'"))?;
    match &c.kind {
        Kind::Sysctl { key, .. } => match take_backup(id) {
            Some(prev) => {
                let out = Command::new("sysctl")
                    .arg("-w")
                    .arg(format!("{key}={prev}"))
                    .output()
                    .map_err(|e| format!("sysctl: {e}"))?;
                if !out.status.success() {
                    return Err(format!(
                        "sysctl failed: {}",
                        String::from_utf8_lossy(&out.stderr).trim()
                    ));
                }
                remove_dropin_line("/etc/sysctl.d/90-hardn.conf", key);
                Ok(format!("reverted {key} to {prev}"))
            }
            None => {
                Err("no saved value to revert to (control was not applied via the console)".into())
            }
        },
        Kind::Service { unit } => disable_service(unit),
        Kind::SshdRootLogin => remove_sshd_dropin(),
        Kind::Fips => {
            Err("FIPS cannot be auto-reverted; run fips-mode-setup --disable and reboot".into())
        }
    }
}

/// CLI entry for the scoped enforcement helper (`hardn __enforce|__revert <id>`).
pub fn enforce_cli(id: &str, apply: bool) -> i32 {
    if !is_root() {
        eprintln!(
            "hardn {} must run as root",
            if apply { "__enforce" } else { "__revert" }
        );
        return 1;
    }
    match if apply {
        enforce_control(id)
    } else {
        revert_control(id)
    } {
        Ok(msg) => {
            println!("{msg}");
            0
        }
        Err(e) => {
            eprintln!("{e}");
            1
        }
    }
}

fn run_uninstall() -> Result<String, String> {
    if is_root() {
        return do_uninstall();
    }
    let exe = std::env::current_exe().map_err(|e| format!("cannot locate hardn binary: {e}"))?;
    let out = Command::new("sudo")
        .arg("-n")
        .arg(&exe)
        .arg("__uninstall")
        .output()
        .map_err(|e| format!("sudo: {e}"))?;
    let so = String::from_utf8_lossy(&out.stdout).trim().to_string();
    let se = String::from_utf8_lossy(&out.stderr).trim().to_string();
    if out.status.success() {
        Ok(if so.is_empty() {
            "uninstalled".into()
        } else {
            so
        })
    } else if se.contains("password is required") || se.starts_with("sudo:") {
        Err("needs privilege: install /etc/sudoers.d/hardn-console (see docs/CONSOLE.md) or run the console as root".into())
    } else {
        Err(if !se.is_empty() { se } else { so })
    }
}

/// Undo HARDN's footprint: revert every console-applied control, remove the
/// HARDN drop-ins, then run the packaged uninstaller if present.
fn do_uninstall() -> Result<String, String> {
    let mut msgs: Vec<String> = Vec::new();
    let ids: Vec<String> = load_backups()
        .as_object()
        .map(|o| o.keys().cloned().collect())
        .unwrap_or_default();
    for id in ids {
        if let Ok(m) = revert_control(&id) {
            msgs.push(m);
        }
    }
    let _ = fs::remove_file("/etc/sysctl.d/90-hardn.conf");
    let _ = fs::remove_file("/etc/ssh/sshd_config.d/10-hardn.conf");
    msgs.push("removed HARDN sysctl + sshd drop-ins".into());
    for p in [
        "/usr/share/hardn/scripts/hardn-uninstall.sh",
        "/usr/local/share/hardn/scripts/hardn-uninstall.sh",
    ] {
        if std::path::Path::new(p).exists() {
            match Command::new("bash").arg(p).arg("--yes").output() {
                Ok(o) if o.status.success() => msgs.push(format!("ran {p}")),
                Ok(o) => msgs.push(format!("{p} exited {}", o.status)),
                Err(e) => msgs.push(format!("{p}: {e}")),
            }
        }
    }
    Ok(msgs.join("; "))
}

pub fn uninstall_cli() -> i32 {
    if !is_root() {
        eprintln!("hardn __uninstall must run as root");
        return 1;
    }
    match do_uninstall() {
        Ok(m) => {
            println!("{m}");
            0
        }
        Err(e) => {
            eprintln!("{e}");
            1
        }
    }
}

fn backup_path() -> PathBuf {
    auth::state_dir().join("control-backups.json")
}

fn load_backups() -> Value {
    fs::read_to_string(backup_path())
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_else(|| json!({}))
}

fn save_backup(id: &str, val: &str) {
    let mut b = load_backups();
    if let Some(o) = b.as_object_mut() {
        o.entry(id.to_string()).or_insert_with(|| json!(val));
    }
    let p = backup_path();
    if let Some(dir) = p.parent() {
        let _ = fs::create_dir_all(dir);
    }
    if let Ok(s) = serde_json::to_string(&b) {
        let _ = fs::write(&p, s);
    }
}

fn take_backup(id: &str) -> Option<String> {
    let mut b = load_backups();
    let v = b.as_object_mut().and_then(|o| o.remove(id));
    if let Ok(s) = serde_json::to_string(&b) {
        let _ = fs::write(backup_path(), s);
    }
    v.and_then(|x| x.as_str().map(|s| s.to_string()))
}

fn is_root() -> bool {
    fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("Uid:"))
                .and_then(|l| l.split_whitespace().nth(1).map(|u| u == "0"))
        })
        .unwrap_or(false)
}

fn have(bin: &str) -> bool {
    Command::new("sh")
        .arg("-c")
        .arg(format!("command -v {bin}"))
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn append_dropin(path: &str, line: &str) -> Result<(), String> {
    use std::io::Write;
    if let Some(dir) = std::path::Path::new(path).parent() {
        let _ = fs::create_dir_all(dir);
    }
    let mut f = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|e| format!("write {path}: {e}"))?;
    f.write_all(line.as_bytes()).map_err(|e| e.to_string())
}

fn set_sysctl(key: &str, val: &str) -> Result<String, String> {
    let out = Command::new("sysctl")
        .arg("-w")
        .arg(format!("{key}={val}"))
        .output()
        .map_err(|e| format!("sysctl: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "sysctl failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    append_dropin("/etc/sysctl.d/90-hardn.conf", &format!("{key} = {val}\n"))?;
    Ok(format!(
        "set {key}={val} (runtime + /etc/sysctl.d/90-hardn.conf)"
    ))
}

fn enable_service(name: &str) -> Result<String, String> {
    if name == "ufw" {
        let out = Command::new("ufw")
            .args(["--force", "enable"])
            .output()
            .map_err(|e| format!("ufw: {e}"))?;
        if !out.status.success() {
            return Err(format!(
                "ufw failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            ));
        }
        return Ok("ufw enabled (default deny incoming)".into());
    }
    let out = Command::new("systemctl")
        .args(["enable", "--now", name])
        .output()
        .map_err(|e| format!("systemctl: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "systemctl failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(format!("{name} enabled and started"))
}

fn set_sshd(directive: &str, val: &str) -> Result<String, String> {
    let path = "/etc/ssh/sshd_config.d/10-hardn.conf";
    append_dropin(path, &format!("{directive} {val}\n"))?;
    let reloaded = Command::new("systemctl")
        .args(["reload", "ssh"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    Ok(format!(
        "wrote '{directive} {val}' to {path}{}",
        if reloaded {
            "; reloaded ssh"
        } else {
            "; reload ssh to apply"
        }
    ))
}

fn disable_service(name: &str) -> Result<String, String> {
    if name == "ufw" {
        let out = Command::new("ufw")
            .arg("disable")
            .output()
            .map_err(|e| format!("ufw: {e}"))?;
        if !out.status.success() {
            return Err(format!(
                "ufw failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            ));
        }
        return Ok("ufw disabled".into());
    }
    let out = Command::new("systemctl")
        .args(["disable", "--now", name])
        .output()
        .map_err(|e| format!("systemctl: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "systemctl failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(format!("{name} disabled and stopped"))
}

fn remove_sshd_dropin() -> Result<String, String> {
    let path = "/etc/ssh/sshd_config.d/10-hardn.conf";
    remove_dropin_line(path, "PermitRootLogin");
    let _ = Command::new("systemctl").args(["reload", "ssh"]).output();
    Ok(format!("removed HARDN directive from {path}; reloaded ssh"))
}

fn remove_dropin_line(path: &str, key: &str) {
    if let Ok(s) = fs::read_to_string(path) {
        let kept: String = s
            .lines()
            .filter(|l| !l.trim_start().starts_with(key))
            .map(|l| format!("{l}\n"))
            .collect();
        let _ = fs::write(path, kept);
    }
}

fn enable_fips() -> Result<String, String> {
    if have("fips-mode-setup") {
        let out = Command::new("fips-mode-setup")
            .arg("--enable")
            .output()
            .map_err(|e| format!("fips-mode-setup: {e}"))?;
        if !out.status.success() {
            return Err(format!(
                "fips-mode-setup failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            ));
        }
        return Ok("FIPS mode enabled; reboot required (see docs/FIPS.md)".into());
    }
    if have("pro") {
        return Err(
            "on Ubuntu, enable FIPS via Ubuntu Pro: sudo pro enable fips-updates, then reboot (see docs/FIPS.md)".into(),
        );
    }
    Err("no FIPS enablement tool found (fips-mode-setup / pro); see docs/FIPS.md".into())
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
