# HARDN Threat Model (v1)

**Status:** v1 · **Scope:** HARDN (CLI hardening + STIG/CIS audit + loopback compliance console)

This is a living document. Update it whenever a change touches privileged execution, the network surface, authentication, or the audit/evidence data path (see Definition of Done in the sprint plan).

---

## 1. System description

HARDN is a locally-installed Debian security tool with three surfaces:

1. **`hardn` CLI** (Rust) - runs as root to apply hardening drop-ins (`src/setup`) and to invoke the STIG/CIS audit engine.
2. **`hardn-audit`** (C, `src/audit/hardn_audit.c`) - evaluates 194 SCAP/XCCDF rules and emits JSON to `/var/log/hardn/hardn_audit_report.json`.
3. **Compliance console** (`hardn serve`) - a loopback-only axum service (`127.0.0.1`, default port 8000) serving audit results, live control state, and a hash-chained evidence log to a browser on the same host.

There is **no continuous-monitoring daemon, no outbound network beaconing, and no GTK GUI**.

## 2. Assets

| Asset | Why it matters |
|-------|----------------|
| Root execution context of the CLI | Full host compromise if abused |
| Audit report + evidence (`/var/log/hardn`, `/var/lib/hardn`) | Integrity of compliance claims; SOC2 evidence |
| Hardening drop-ins (auditd/sysctl/sshd/sudoers/fail2ban) | Weakening these degrades host security |
| The console auth token / local credential | Gate to the console + operator actions |
| Release artifacts (`.deb`, SBOM) | Supply-chain integrity for every downstream host |

## 3. Trust boundaries

```
 [ untrusted network ] ── (no inbound; loopback API only) ──►  X
 [ local unprivileged user ] ──► CLI (needs sudo) ──► [ root context ]
 [ local user / SPA ] ──► 127.0.0.1 / unix socket ──► Compliance API ──► audit JSON (read)
 [ GitHub / CI ] ──► signed release ──► [ operator's apt ] ──► host
```

Boundaries that matter: **unprivileged→root** (the sudo gate on the CLI), **network→host** (the API must never bind `0.0.0.0`), and **CI→host** (release provenance).

## 4. Threats & mitigations (STRIDE-oriented)

| # | Threat | Vector | Mitigation | Sprint |
|---|--------|--------|-----------|--------|
| T1 | **Network exposure** of the API | Binding `0.0.0.0`, open firewall port | Loopback/unix-socket only; CI grep-gate forbids `0.0.0.0`; no ufw port opened by default | 1, S0-gate |
| T2 | **Unauthenticated data/action** on the API | Missing authn on `/api/*` | Local token + viewer/operator RBAC; every mutating call audit-logged | 2 |
| T3 | **Tampering with audit evidence** | Editing report JSON to fake compliance | Hash-chained append-only audit log; signed evidence export | 2 |
| T4 | **Privilege escalation via operator endpoints** | `POST /hardening/apply` abused | Operator-role gate, confirmation, rate-limit, audit-log, no shell interpolation of inputs | 2 |
| T5 | **Command injection** in privileged execution | Untrusted input into `Command`/`bash -c` | No string-built shells with external input; `path_security` validation; args passed as arrays | ongoing |
| T6 | **Supply-chain compromise** | Malicious/vulnerable crate or transitive dep | `cargo audit` + `cargo deny` gate, dependency-review, SBOM, pinned toolchain, minimal dep set (26→10) | S0-5/7 |
| T7 | **Secret leakage** | Token/key committed or logged | gitleaks CI gate; secrets via keyring/env; structured logging scrubs secrets | S0-5, 2 |
| T8 | **Fake threat intelligence** | Fixture IOCs shipped as real data | `demo` feature + fixture-IOC path removed entirely | done (S0) |
| T9 | **Unsigned/tampered release** | MITM or malicious `.deb` | Signed `.deb` (minisign/dpkg-sig) + SLSA provenance + reproducible build; fresh-host install test | 6 |
| T10 | **Weak crypto** | Hand-rolled HMAC / non-validated primitives | Hand-rolled HMAC removed with LEGION; crypto via FIPS-validated `aws-lc-rs` | 5 (T10 partly done) |
| T11 | **DoS via on-demand audit** | Spamming `POST /audit/run` | Rate-limit + single-flight the audit job | 1/2 |

## 5. Residual risks / assumptions

- The host root account and kernel are trusted; HARDN does not defend against an already-root attacker (it *reports* posture, e.g. host FIPS mode).
- The C audit engine (`hardn_audit.c`, ~3.6k lines) is high-value and high-risk; changes require golden-output + fuzz testing (sprint-plan R1).
- Loopback is treated as a trust boundary, but a local multi-user host means "loopback" is not "single trusted user" - hence T2's authn requirement even on 127.0.0.1.

## 6. Out of scope (v1)

Host-level FIPS certification, kernel self-protection, physical access, and defense against a compromised apt mirror beyond signature/provenance verification.
