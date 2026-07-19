![HARDN Logo](assets/IMG_1233.jpeg)
# HARDN, Linux Security Hardening and STIG/CIS Compliance

## Overview

HARDN is an open-source security hardening and compliance tool for Debian-based
Linux. It hardens a fresh install, runs a STIG/CIS-aligned SCAP/XCCDF audit, and
serves a local web console for reviewing posture, findings, and evidence. It
ships as a single binary with no continuous-monitoring daemon and no desktop
application.

## What HARDN Is

### Core components

- **Automated hardening**: STIG- and CIS-leaning scripts that lock down SSH,
  auditd, sysctl, kernel modules, AppArmor, fail2ban, and related controls.
- **Environment-aware**: auto-detects bare-metal, cloud (AWS, GCP, Azure,
  DigitalOcean, Oracle, Alibaba), VMs, and containers, then adjusts which steps
  it applies. Containers skip module ops; cloud VMs keep IPv6 SLAAC intact;
  container hosts keep `unprivileged_userns_clone` at the kernel default so
  rootless workloads keep working.
- **Compliance audit**: a C-based SCAP/XCCDF engine (`hardn-audit`) evaluates
  194 rules and writes a JSON report (rule id, title, category, severity,
  status, evidence) to `/var/log/hardn/hardn_audit_report.json`.
- **Compliance console**: `hardn serve` starts a loopback-only web console
  (axum REST API) with a posture score, a filterable findings queue, live host
  telemetry, real hardening-control state, and a tamper-evident evidence log.
  It binds `127.0.0.1` only and never a network interface.
- **Cron safety**: every scheduled job runs under `flock` so a manual run and a
  scheduled run cannot collide. Suricata rule updates stage, validate, then
  atomically swap into place.
- **Interactive service manager**: menu-driven control of services, modules,
  tools, and reports (`hardn-service-manager`).

## Architecture

```
+-----------------------------------------------------------+
|                    HARDN                                   |
+-----------------------------------------------------------+
|   +-------------+  +-------------+  +-------------+        |
|   | Service     |  | Compliance  |  | Compliance  |        |
|   | Manager     |  | Audit       |  | Console     |        |
|   | (interactive|  | (SCAP/XCCDF |  | (loopback   |        |
|   |  CLI)       |  |  C engine)  |  |  axum API)  |        |
|   +-------------+  +-------------+  +-------------+        |
+-----------------------------------------------------------+
|  +-------------+  +-------------------------------+        |
|  | Hardening   |  | Control detection + enforce   |        |
|  | Scripts     |  | (sysctl / service / sshd /    |        |
|  |             |  |  FIPS, with revert)           |        |
|  +-------------+  +-------------------------------+        |
+-----------------------------------------------------------+
|                 Debian Linux System                       |
+-----------------------------------------------------------+
```

## Key Features

### Hardening

- STIG-leaning baseline (PAM, login.defs, sudoers, journald, rsyslog, modprobe,
  sysctl).
- Network hardening: UFW + iptables `HARDN-LOCKDOWN` chain. Cloud metadata IPs
  are allowlisted on cloud hosts.
- Filesystem and mount hygiene: `fs.protected_*`, world-writable audit, a
  file-permission table for `/etc/{passwd,shadow,sudoers,*}`.

### Audit

- SCAP/XCCDF compliance audit against 194 STIG/CIS rules, emitted as JSON.
- File and system integrity checks (AIDE).

### Console

- Loopback-only axum API (`127.0.0.1`, default port 8000), enforced in code and
  by a CI gate that fails on any bind-all pattern.
- Operator and viewer tokens; anonymous access is refused even on loopback.
- Every operator action is recorded in a hash-chained audit log; the chain is
  verified on read and detects tampering. Evidence exports as a SHA-256-sealed
  bundle.
- Live control detection probes the running host (sysctl values, active
  services, `sshd_config`, FIPS mode). Applying a control changes real host
  state and saves a backup so **Revert** restores the prior value; the web
  server stays unprivileged and only a scoped helper escalates through a
  sudoers rule.

### Interfaces

- Interactive console (`hardn-service-manager`).
- Loopback compliance console (`hardn serve`).
- CLI subcommands (`hardn --help`).

## Quick Start

### Install and launch

```bash
git clone https://github.com/Security-International-Group/HARDN.git
cd HARDN
sudo make build
sudo make hardn
```

`make build` produces the Debian package; `make hardn` installs it and opens the
interactive service manager.

### Basic usage

```bash
sudo hardn --help              # full command list
sudo hardn --status            # current service state
sudo hardn audit               # run the compliance audit (alias: --security-report)
hardn serve                    # start the loopback console (http://127.0.0.1:8000)
sudo hardn run-module hardening
sudo hardn run-tool   fail2ban
```

`run-module` and `run-tool` return exit 127 when the script does not exist
(POSIX "command not found"), so cron and CI can tell a typo from a real failure.

## Components

### HARDN service manager

Primary interactive interface. Provides menu-driven service control, live status
dashboards, log viewing, and configuration management.

### Compliance audit engine

A C-based SCAP/XCCDF engine (`src/audit/`) that evaluates 194 STIG/CIS rules
against the live system and emits a JSON report (rule id, title, status,
evidence, severity). See [Audit engine internals](hardn-audit.md).

### Compliance console

The loopback axum API behind `hardn serve`. Serves the posture score, findings
queue, host telemetry, live control state, control apply/revert, the
hash-chained audit log, and evidence export. Full reference:
[CONSOLE.md](CONSOLE.md).

### Observability stack (optional)

`tools/prometheus.sh` installs Prometheus and `prometheus-node-exporter` from
Debian main and writes a scrape job for the host node exporter at
`localhost:9100`. `tools/grafana.sh` installs Grafana (default port 3000) and
provisions a Prometheus data source so host telemetry is wired in on first boot.

```bash
sudo hardn run-tool prometheus && sudo hardn run-tool grafana
```

Then browse to `http://<host>:3000` (admin / admin, change immediately).

### Hardening modules

Automated security-configuration modules under `/usr/share/hardn/modules/`. The
orchestrator delegates auditd-specific rule loading to
`/usr/share/hardn/tools/auditd.sh` so there is one writer per rule file.

## Security Benefits

- STIG/CIS hardening applied at install and re-applied on demand.
- On-demand compliance audit with a signed evidence trail.
- SSH key-based authentication (with lockout-safety fallback on cloud).
- File and system integrity checks (AIDE).
- UFW + iptables firewall posture with cloud-metadata carve-outs.
- Loopback-only, authenticated, tamper-evident compliance console.

## Community and Support

HARDN is developed by **Security International Group (SIG)**. Documentation lives
under `docs/`; use GitHub issues for bugs and feature requests, and see
`CONTRIBUTING.md` for contribution guidelines.

### Resources

- [Service manager guide](hardn-service-manager.md)
- [Compliance console reference](CONSOLE.md)
- [Audit engine internals](hardn-audit.md)
- [Security posture summary](security-posture.md)
- [Threat model](THREAT-MODEL.md)

## License

HARDN is released under the MIT License.

---

**Repository**: [GitHub](https://github.com/Security-International-Group/HARDN)
