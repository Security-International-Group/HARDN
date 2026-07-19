![HARDN Logo](docs/assets/IMG_1233.jpeg)

# HARDN
**Linux security hardening and STIG/CIS compliance**

<p align="center">
  <a href="https://www.debian.org/"><img src="https://img.shields.io/badge/debian-12%20%7C%2013-8B0000?logo=debian&logoColor=white" alt="Debian" /></a>
  <a href="https://ubuntu.com/"><img src="https://img.shields.io/badge/ubuntu-22.04%20%7C%2024.04-E95420?logo=ubuntu&logoColor=white" alt="Ubuntu" /></a>
  <img src="https://img.shields.io/badge/license-MIT-blue" alt="MIT" />
</p>

HARDN is a CLI-first security tool for Debian-based Linux. It hardens a fresh
install, runs a 194-rule SCAP/XCCDF compliance audit, and serves a local web
console for reviewing posture, findings, and evidence. It runs as a single
binary with no continuous-monitoring daemon and no desktop application.

## Features

- **Automated hardening.** One-command lockdown of SSH, auditd, sysctl,
  AppArmor, fail2ban, AIDE and related controls, with environment-aware safety
  (it will not lock you out of a cloud VM that has no registered key).
- **STIG/CIS compliance audit.** A SCAP/XCCDF engine (`hardn-audit`) evaluates
  194 rules and writes a JSON report - rule id, title, category, severity,
  status, and evidence - to `/var/log/hardn/hardn_audit_report.json`.
- **Local compliance console.** `hardn serve` starts a loopback web console: a
  posture score, a findings queue with filters and drill-down, live host
  telemetry, real hardening-control state, and a tamper-evident evidence log.
- **Role-based access.** Operator and viewer tokens; anonymous access is refused
  even on loopback (`127.0.0.1` only, never a network interface).
- **Tamper-evident evidence.** Every operator action is recorded in a
  hash-chained audit log; evidence can be exported as a SHA-256-sealed bundle.
- **Supply-chain hygiene.** 13 direct dependencies, all used; CI runs
  `cargo audit`, `cargo deny`, gitleaks, dependency review, and produces a
  CycloneDX SBOM per build.

## Quick start

```bash
# Build the CLI and the audit engine
cargo build --release
cc -std=c11 -O2 src/audit/hardn_audit.c -o target/release/hardn-audit

# Run a compliance audit (writes the report)
sudo hardn audit          # or: sudo hardn --security-report

# Launch the local console
hardn serve               # http://127.0.0.1:8000
```

`hardn serve` prints an **operator** and a **viewer** URL, each with a one-time
token. Open the operator URL in a browser on the same machine; the token
establishes a session cookie and the console loads with live data.

## The console

The console is served by a loopback-only axum API. It is the single deliberate
long-running surface in HARDN; it never binds a network interface.

| Endpoint | Purpose |
|----------|---------|
| `GET /api/v1/health` | liveness |
| `GET /api/v1/compliance/summary` | weighted score, pass/fail/na/error counts |
| `GET /api/v1/compliance/findings` | rule findings, filter by `result` + `severity` |
| `GET /api/v1/system/telemetry` | host, kernel, OS, arch, FIPS |
| `GET /api/v1/system/fips` | FIPS mode from `/proc/sys/crypto/fips_enabled` |
| `GET /api/v1/hardening/controls` | live control state (sysctl, services, sshd) |
| `POST /api/v1/hardening/apply/{id}` | apply a control (operator) |
| `POST /api/v1/hardening/revert/{id}` | revert a control to its prior state (operator) |
| `POST /api/v1/system/uninstall` | revert all changes and remove HARDN (operator) |
| `POST /api/v1/audit/run` | run the audit engine (operator) |
| `GET /api/v1/audit-log` | hash-chained audit log + integrity |
| `GET /api/v1/evidence/export` | signed evidence bundle (`format=json\|csv`) |

Full reference: [docs/CONSOLE.md](docs/CONSOLE.md).

## Security

- **Loopback only.** The console binds `127.0.0.1`, enforced in code and by a CI
  gate that fails the build on any bind-all pattern.
- **Authenticated.** Reads require a viewer token; mutations require operator.
- **Auditable.** Privileged actions are hash-chained; the chain is verified on
  read and detects tampering.

Threat model: [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md). CI gates and branch
protection: [docs/CI-SECURITY.md](docs/CI-SECURITY.md).

## Build

HARDN builds with a stable Rust toolchain (pinned in `rust-toolchain.toml`) and
a C compiler for the audit engine. On a machine without a system compiler, point
`cc`/`c++` at a zig-based wrapper. See `Makefile` for the packaged build.

## License

MIT. See [LICENSE](LICENSE).
