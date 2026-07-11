# HARDN Rebuild — Sprint Plan

**Owner:** DevSecOps (Tim Burns)
**Program window:** Sprint 0 + 6 delivery sprints (2 weeks each ≈ 14 weeks)
**Status:** Draft v1 — 2026-07-10

---

## 1. Product vision

HARDN becomes a **CLI-first Linux hardening + STIG/CIS compliance tool** with a **local, read-mostly web dashboard**. No LEGION runtime engine, no GTK desktop app, no continuous-monitoring daemon. One binary hardens the host and runs a 194-rule SCAP/XCCDF audit; a thin loopback REST service exposes the results to a sharp React dashboard. Ships as a signed, reproducible Debian package with an SBOM. Crypto is FIPS-validated where the surface allows. The SDLC itself is the SOC2 evidence.

The dashboard aesthetic is **operational, not consumer**: dense, dark, monospace-accented, multi-tab, keyboard-driven. Think a SOC console, not a marketing site. Deliberately no AI-generated visual language and no AI-tell copy.

---

## 2. Target architecture

```
┌──────────────────────────────────────────────────────────────┐
│  hardn (single Rust binary, CLI)                              │
│   ├─ setup/     host hardening drop-ins (auditd, sysctl, …)   │
│   ├─ audit  →   invokes C engine (hardn_audit.c, 194 rules)   │
│   │            emits /var/log/hardn/hardn_audit_report.json   │
│   ├─ cron/      scheduled audit + report rotation             │
│   └─ serve  →   compliance REST API (axum, loopback only)     │
└───────────────┬──────────────────────────────────────────────┘
                │  GET/POST /api/v1/*   (127.0.0.1 or unix socket)
                │  local token or mTLS; no 0.0.0.0 bind, ever
┌───────────────▼──────────────────────────────────────────────┐
│  Dashboard (React SPA, static bundle served by the API)       │
│   Tabs: Posture · Findings · Telemetry · Controls · Evidence  │
└──────────────────────────────────────────────────────────────┘
```

**Reconciling "no daemon" with "web dashboard":** the LEGION monitoring daemon is gone for good. What replaces it is a **read-mostly compliance API** — it serves already-computed audit JSON, exposes system telemetry, and runs audits *on demand*. It is socket-activated, binds loopback/unix-socket only, and does no continuous hunting. This is the single deliberate daemon we keep, and it exists only to back the dashboard.

**Components inherited (keep):** C audit engine + SCAP rules, `src/setup` hardening, `src/core` (config/cron/types), `src/execution`, `src/utils` (paths/logging/path_security), CLI dispatch in `main.rs`.

**Removed (LEGION excision, mostly staged already):** `src/legion/` (40 files), all daemon binaries, GTK GUI, `utils/alerts.rs` webhook/HMAC layer, `hardn-monitor`, Python API.

**New (greenfield):** `src/api/` (axum service), `dashboard/` (React), `debian/` packaging, release + SBOM CI.

---

## 3. Compliance strategy

### SOC2 (Type II is a process outcome, not a feature)
Two tracks run in parallel:

- **Product controls** the app must implement to *be* auditable:
  - Structured, append-only audit log of every privileged action (`who / what / when / result`), tamper-evident (hash-chained).
  - AuthN + coarse RBAC on the dashboard/API (viewer vs. operator); no anonymous access even on loopback.
  - Encryption in transit (TLS or unix-socket + peer creds); no plaintext control channel.
  - Evidence export: point-in-time compliance snapshot as signed JSON/CSV for auditors.
  - Secrets never in code/logs; config via env/keyring.
- **Process controls** the SDLC must enforce (these produce the SOC2 evidence):
  - Branch protection, mandatory PR review, signed commits, linear history.
  - CI security gates: SAST (CodeQL — already present), dependency review, secrets scan, `cargo audit`/`cargo deny`, license check.
  - SBOM (CycloneDX) generated and attached to every release; SLSA-style build provenance.
  - Change management traceable: every change ties to an issue; CHANGELOG maintained.

### FIPS ("if possible" — scoped honestly, two layers)
Full-OS FIPS 140-3 is a *host/kernel* posture. HARDN is a compliance tool, so it **targets and verifies** a FIPS host rather than shipping one. Two layers:

**Layer A — app crypto (we own this):**
- **FIPS 140-3 validated module** for all crypto the app performs: replace the `sha2` crate and any hand-rolled HMAC with **`aws-lc-rs` (FIPS feature)**. Any TLS via **`rustls` + `aws-lc-rs`** FIPS mode.
- A documented "FIPS mode" build flag + startup self-check that only validated primitives are reachable.
- Deliverable: **"FIPS-ready crypto surface,"** with a written boundary. We do not claim host FIPS compliance for the app.

**Layer B — host FIPS posture (we detect + report):**
- Debian 12 has no official FIPS 140-3 kernel module, but it supports kernel **FIPS mode** via `fips-mode-setup` (`crypto-policies` pkg → `fips=1` → `/proc/sys/crypto/fips_enabled`), plus an addable **OpenSSL 3 FIPS 140-2 provider** (community-built; note 140-2 is on the CMVP historical list).
- HARDN reads `/proc/sys/crypto/fips_enabled` and adds a **host-FIPS compliance check** (STIG/CIS-style) surfaced on the dashboard — a natural data point for the audit engine.
- `docs/FIPS.md` ships a "run HARDN on a FIPS-mode Debian 12 host" recipe **with the known caveats**: enabling `fips=1` breaks `apt`/`libgcrypt` (MD5 exception removed → `apt-get update` fatal error) and Docker install on Bookworm; 140-2 provider is sunset vs 140-3.

---

## 4. Definition of Done (applies to every ticket)

A ticket is done only when:
1. Code reviewed via PR, CI green (fmt, clippy `-D warnings`, tests, SAST, dep-review, secrets scan).
2. Tests added/updated; meaningful coverage on new logic; integration test if it crosses a boundary.
3. No new `unsafe` without justification; no new `0.0.0.0` bind; no new hand-rolled crypto.
4. Docs updated (README/CHANGELOG/API contract) where user- or auditor-visible.
5. Verified by exercising the real path (run the CLI / hit the endpoint / load the tab), not just unit tests.
6. Threat-model delta considered for anything touching auth, network, or privileged execution.

---

## 5. Epics

| ID | Epic | Outcome |
|----|------|---------|
| **E1** | LEGION excision + build recovery | Repo builds clean, CLI-only, zero LEGION/GTK residue |
| **E2** | Compliance REST API | Loopback axum service exposing audit + telemetry, authenticated |
| **E3** | React dashboard | Multi-tab SOC console consuming the API, every data point live |
| **E4** | SOC2 controls + SDLC gates | Product + process controls implemented and evidenced |
| **E5** | FIPS-ready crypto | Validated crypto module, documented FIPS boundary |
| **E6** | Debian packaging + release | Signed, reproducible `.deb` (+ optional AppImage), SBOM, provenance |
| **E7** | Data + REST verification | Every data point and endpoint proven end-to-end |

---

## 6. Sprint breakdown

### Sprint 0 — Foundations & recovery (1 week)
**Goal:** durable repo, green build, SDLC scaffolding, threat model. Nothing new is built until the base is sound.

- **S0-1 (P0)** Move the excision work off `/tmp`. Fork/clone HARDN to a durable path, push the `strip-legion` branch to origin. *AC: branch exists on GitHub, CI runs on it.*
- **S0-2 (P0)** Finish LEGION excision (E1): complete `main.rs` surgery (remove `run_legion()` + LEGION service-mgmt fns; 4 real code refs + string literals), delete orphaned `utils/alerts.rs`, drop `gtk4/glib/gio/vte4/comfy-table` from Cargo.toml, remove the dead `axum` orphan *only if* we defer the API (we do not — keep axum). *AC: `cargo build --release` succeeds with the zig toolchain; `hardn --help` shows no legion/gui/daemon subcommands.*
- **S0-3 (P0)** Redo the three interrupted sweeps (packaging, docs/CI, tests) so no LEGION strings remain anywhere. *AC: `grep -ri legion` returns only historical CHANGELOG entries.*
- **S0-4** Branch protection on `main`: required reviews, required checks, signed commits, linear history.
- **S0-5** CI security gate baseline: add `cargo audit`, `cargo deny`, secrets scan (gitleaks), dependency-review; keep CodeQL. *AC: all gates run on PR and block on failure.*
- **S0-6** Threat model v1 (data flows, trust boundaries, the loopback API surface, privileged-execution paths). One page, in `docs/THREAT-MODEL.md`.
- **S0-7** SBOM baseline: generate CycloneDX for the Rust + C deps. *AC: `sbom.json` produced in CI.*

**Security gate:** repo cannot merge to `main` without green security CI. Exit criterion for Sprint 0.

---

### Sprint 1 — Compliance REST API core (E2)
**Goal:** the loopback API serves real audit data. This is the "confirm data points + REST connections" backbone.

- **S1-1** Revive `hardn-apid` as `src/api/` — axum on `127.0.0.1` (configurable) or unix socket, **never 0.0.0.0**. Wire `hardn serve` subcommand.
- **S1-2** Report reader: parse `/var/log/hardn/hardn_audit_report.json` into typed structs (rule id, xccdf id, title, result, severity, remediation).
- **S1-3** Endpoints (read):
  - `GET /api/v1/health`
  - `GET /api/v1/compliance/summary` (score, pass/fail/NA counts, last-run ts)
  - `GET /api/v1/compliance/findings?result=&severity=&page=`
  - `GET /api/v1/compliance/findings/{rule_id}` (detail + remediation)
- **S1-4** Telemetry endpoint: `GET /api/v1/system/telemetry` (hostname, OS, kernel, uptime, load/mem/disk) and `GET /api/v1/system/services` (reuse `ServiceStatus`).
- **S1-5** On-demand audit: `POST /api/v1/audit/run` (async job) + `GET /api/v1/audit/runs` (history). Runs the C engine, streams status.
- **S1-6** OpenAPI 3 spec generated from the handlers; committed as `docs/openapi.yaml` (the REST contract of record).

**Security gate:** every endpoint requires auth (S2 delivers real auth; here use a bootstrap local token). No endpoint mutates host state except `audit/run`, which is rate-limited and audit-logged.

---

### Sprint 2 — Auth, audit log, hardening & evidence endpoints (E2 + E4)
**Goal:** the API is SOC2-shaped: authenticated, every action logged, evidence exportable.

- **S2-1** AuthN: local token (keyring-stored) or mTLS over loopback; session handling for the SPA. Viewer vs. operator RBAC.
- **S2-2** Tamper-evident audit log: hash-chained append-only JSONL of every privileged/mutating call. `GET /api/v1/audit-log`.
- **S2-3** Hardening controls endpoints: `GET /api/v1/hardening/controls` (which drop-ins applied + current state), `POST /api/v1/hardening/apply/{control}` (operator only, audit-logged).
- **S2-4** Evidence export: `GET /api/v1/evidence/export?format=json|csv` — signed point-in-time compliance snapshot for auditors.
- **S2-5** Structured logging everywhere (tracing), no secrets in logs, log rotation aligned with `/var/log/hardn`.

**Security gate:** pen-test the auth boundary; confirm no unauthenticated data leak, no privilege escalation via the operator endpoints.

---

### Sprint 3 — React dashboard shell + Posture & Findings tabs (E3)
**Goal:** the SOC console renders live compliance data. Sharp, dense, dark, keyboard-first.

- **S3-1** Scaffold `dashboard/` (Vite + React + TypeScript). Design system: dark, monospace-accented, high-density grid; no component-library "default SaaS" look. Accessible (WCAG AA contrast), light/dark aware.
- **S3-2** App shell: multi-tab layout, command palette (⌘K), keyboard nav, typed API client generated from `openapi.yaml`.
- **S3-3** **Posture tab**: overall score gauge, pass/fail/NA breakdown, trend since last run, severity heatmap. (Follow dataviz palette rules — no rainbow, colorblind-safe.)
- **S3-4** **Findings tab**: virtualized table of all 194 rules, filter by result/severity/category, drill-down drawer with remediation + xccdf id + evidence.
- **S3-5** Empty/error/loading states for every panel; no silent failures.

**Security gate:** CSP locked down, no external asset loads, dependencies scanned; bundle is fully self-contained for offline/air-gapped hosts.

---

### Sprint 4 — Telemetry, Controls, Evidence tabs + run flow (E3 + E7)
**Goal:** every remaining data point is live and every REST connection is exercised from the UI.

- **S4-1** **Telemetry tab**: host/kernel/uptime, resource meters, service status grid.
- **S4-2** **Controls tab**: hardening drop-ins with applied/not-applied state; operator can apply/re-apply (guarded, confirms, audit-logged).
- **S4-3** **Evidence tab**: browse audit-log, export signed evidence bundle, view run history.
- **S4-4** **Run audit** flow: trigger from UI, live progress, refresh on completion.
- **S4-5** E2E test suite (Playwright) driving every tab against a real backend on a throwaway host/container. This is the formal "confirm all data points + REST connections work" deliverable (E7).

**Security gate:** E2E suite is a required CI check; a broken data point or endpoint fails the build.

---

### Sprint 5 — FIPS-ready crypto + hardening pass (E5)
**Goal:** all crypto goes through a validated module; documented FIPS boundary.

- **S5-1** Replace `sha2` + any hand-rolled HMAC with `aws-lc-rs` (FIPS feature) or OpenSSL 3 FIPS provider.
- **S5-2** All TLS (evidence signing, optional remote export) via `rustls + aws-lc-rs` FIPS mode.
- **S5-3** `--fips` build/runtime flag; startup self-check that only validated primitives are reachable.
- **S5-4** `docs/FIPS.md`: exact boundary, module version, what is and is not covered — plus the **host FIPS-mode Debian 12 recipe** (`fips-mode-setup` + OpenSSL 3 FIPS provider) and its caveats (apt/libgcrypt MD5 breakage, 140-2 sunset).
- **S5-5** Dependency diet: minimize crate surface (removing GTK already cut ~4 heavy deps); re-run `cargo deny` and SBOM.
- **S5-6** Host-FIPS compliance check: read `/proc/sys/crypto/fips_enabled`, add a STIG/CIS-style rule to the audit engine, surface **host FIPS posture** as a dashboard data point + `GET /api/v1/system/fips`.

**Security gate:** crypto inventory review; confirm no non-validated crypto path in a FIPS build.

---

### Sprint 6 — Debian packaging, release pipeline, GA (E6)
**Goal:** signed, reproducible `.deb` bundling engine + binary + dashboard; full release provenance.

- **S6-1** `debian/` packaging: `control`, `rules`, `postinst`/`prerm` (create `hardn` user, install socket-activated systemd unit for the loopback API only), conffiles. Bundle the static React build.
- **S6-2** Reproducible build: pinned toolchain, `SOURCE_DATE_EPOCH`, verify byte-identical rebuilds.
- **S6-3** Release workflow: build `.deb` (+ optional AppImage for the dashboard), sign (dpkg-sig / minisign), generate CycloneDX SBOM + SLSA provenance, attach to GitHub Release.
- **S6-4** Fresh-host install/upgrade/uninstall test in CI (container): `.deb` installs, service comes up on loopback, dashboard loads, audit runs, clean removal.
- **S6-5** Version alignment + supply-chain hygiene: kill the `demo` fixture-IOC path in release builds, confirm no `0.0.0.0`, close the 1.1.0→1.2.92 gap noted in the assessment.
- **S6-6** Docs: install guide, operator guide, SOC2 control mapping, CHANGELOG for GA.

**Security gate:** release is blocked unless signed + SBOM + provenance present and the fresh-host test passes. This is the GA exit criterion.

---

## 7. REST contract — data points to verify (E7 checklist)

| Endpoint | Data point | Source |
|----------|-----------|--------|
| `GET /api/v1/health` | liveness | api |
| `GET /api/v1/compliance/summary` | score, pass/fail/NA, last-run | audit JSON |
| `GET /api/v1/compliance/findings` | 194 rules, filterable | audit JSON |
| `GET /api/v1/compliance/findings/{id}` | rule detail + remediation | audit JSON + rules_source |
| `POST /api/v1/audit/run` | trigger audit | C engine |
| `GET /api/v1/audit/runs` | run history | audit log |
| `GET /api/v1/system/telemetry` | host/kernel/uptime/resources | system |
| `GET /api/v1/system/services` | service statuses | `ServiceStatus` |
| `GET /api/v1/system/fips` | host FIPS posture | `/proc/sys/crypto/fips_enabled` |
| `GET /api/v1/hardening/controls` | drop-in state | `src/setup` |
| `POST /api/v1/hardening/apply/{c}` | apply control (operator) | `src/setup` |
| `GET /api/v1/audit-log` | tamper-evident action log | audit log |
| `GET /api/v1/evidence/export` | signed compliance snapshot | composed |

Every row must be proven by a Playwright E2E assertion before GA.

---

## 8. Decisions (locked 2026-07-10) & risks

- **D1 — Dashboard backend: DECIDED → loopback REST API.** Revive `hardn-apid` (axum) as the single deliberate daemon, loopback/unix-socket only, socket-activated. Supports on-demand audit runs + live telemetry. (Static-SPA alternative rejected.)
- **D2 — FIPS: DECIDED → FIPS-ready crypto surface.** App-level only, all crypto via a FIPS-validated module (aws-lc-rs FIPS), `--fips` flag + documented boundary. No host/kernel FIPS claim. Drop hand-rolled HMAC.
- **D3 — Auth: DECIDED → local token + RBAC at GA, mTLS follow-up.** Keyring-stored token, viewer/operator roles for GA; mTLS as a post-GA hardening item.
- **D4 — AppImage: DEFAULT → `.deb` for GA, AppImage optional.** Not blocking; revisit in Sprint 6.
- **R1** — C audit engine (`hardn_audit.c`) is 3.6k lines and the compliance heart; treat any change as high-risk, fuzz + golden-output tested.
- **R2** — Reproducible `.deb` builds are finicky; budget buffer in Sprint 6.
- **R3** — This machine has no system `cc`; CI and dev must use the zig `.local-tools` toolchain or a pinned container.
- **R1** — C audit engine (`hardn_audit.c`) is 3.6k lines and the compliance heart; treat any change to it as high-risk, fuzz + golden-output tested.
- **R2** — Reproducible `.deb` builds are finicky; budget buffer in Sprint 6.
- **R3** — This machine has no system `cc`; CI and dev must use the zig `.local-tools` toolchain or a pinned container.

---

## 9. Immediate next actions (this week, Sprint 0)

1. Push `strip-legion` to origin off a durable checkout (S0-1).
2. Finish `main.rs` surgery + cut GTK deps; get `cargo build --release` green (S0-2).
3. Redo the packaging/docs/tests LEGION sweeps (S0-3).
4. Land the CI security-gate baseline + branch protection (S0-4/5).
5. Confirm **D1–D4** so Sprint 1 starts unblocked.
