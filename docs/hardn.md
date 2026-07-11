![HARDN Logo](assets/IMG_1233.jpeg)
# HARDN, Linux Security Hardening and Extended Detection Response

## Overview

HARDN is an open-source security hardening and compliance toolkit for
Debian-based Linux. It automates the security-configuration process, runs a
STIG/CIS-aligned SCAP/XCCDF audit, and gives operators a single place to
manage it all from the CLI.

## What HARDN Is

### Core security components

- **Automated hardening**: STIG- and CIS-leaning hardening scripts that lock
  down SSH, auditd, sysctl, kernel modules, AppArmor, fail2ban, and friends.
- **Environment-aware**: auto-detects bare-metal, cloud (AWS, GCP, Azure,
  DigitalOcean, Oracle, Alibaba), VMs, and containers, then adjusts which
  steps it applies. Containers skip module ops; cloud VMs keep IPv6 SLAAC
  intact; container hosts keep `unprivileged_userns_clone` at the kernel
  default so rootless workloads keep working.
- **SENTRY drift detection**: a sha256 baseline diff of high-value files
  (`/etc/passwd`, `/etc/shadow`, `/etc/sudoers`, `authorized_keys`,
  `/etc/cron.*`, `/etc/systemd/system/*`). Drift fires one alert per
  added, removed, or changed entry.
- **Alert fanout**: alerts land in `/var/log/hardn/alerts.jsonl` and also
  fan out to journald (always) and an optional webhook (set
  `HARDN_ALERT_WEBHOOK_URL`). Shared TTL dedupe stops repeat alerts from
  paging the on-call.
- **Cron safety**: every scheduled job runs under `flock` so a manual run
  and a scheduled run cannot collide. Suricata rule updates stage, validate,
  then atomically swap into place.
- **Service management**: systemd service orchestration and monitoring.
- **REST API**: optional HTTP endpoint for remote reporting and management.
- **Interactive interface**: service manager with live status display.

### Audit & reporting features

- **Compliance audit**: a SCAP/XCCDF engine evaluates STIG/CIS rules and
  emits a JSON report (rule id, title, status, evidence, severity).
- **SENTRY drift detection**: a daily sha256 baseline diff of high-value
  files, wired into the unified alert channel.
- **Service health**: live status of every HARDN service.
- **Log aggregation**: alerts.jsonl plus journald is the single channel.

### Management tools

- **Interactive service manager**: menu-driven control of services,
  modules, tools, and reports.
- **Command-line interface**: full CLI for automation and scripting.
- **REST API**: programmatic access for integration with other security
  tools.

## Architecture

```
+-----------------------------------------------------------+
|                    HARDN Security Framework               |
+-----------------------------------------------------------+
|   +-------------+  +-------------+  +-------------+       |
|   | Service     |  | Compliance  |  | REST API    |       |
|   | Manager     |  | Audit       |  | Service     |       |
|   | (Interactive|  | (SCAP/XCCDF)|  | (Remote     |       |
|   | Interface)  |  |             |  | Access)     |       |
|   +-------------+  +-------------+  +-------------+       |
+-----------------------------------------------------------+
|  +-------------+  +-------------+  +-------------+        |
|  | Hardening   |  | SENTRY      |  | System      |        |
|  | Scripts     |  | Drift Diff  |  | Reporting   |        |
|  +-------------+  +-------------+  +-------------+        |
+-----------------------------------------------------------+
|                 Debian Linux System                       |
+-----------------------------------------------------------+
```

## Key Features

### Hardening

- STIG-leaning baseline (PAM, login.defs, sudoers, journald, rsyslog,
  modprobe, sysctl).
- Network hardening: UFW + iptables `HARDN-LOCKDOWN` chain. Cloud
  metadata IPs are allowlisted on cloud hosts.
- Filesystem and mount hygiene: `fs.protected_*`, world-writable audit,
  file-permission table for `/etc/{passwd,shadow,sudoers,*}`.

### Audit and drift detection

- SCAP/XCCDF compliance audit against STIG/CIS rules, emitted as JSON.
- SENTRY daily file-drift diff of high-value persistence files, fed into
  the unified alert channel.
- File and system integrity checks (AIDE).

### Service management

- Full lifecycle through `systemctl` and `hardn-service-manager`.
- Service dependencies handled by `systemd`.
- Service restart and recovery via `Restart=on-failure` in unit files.

### Interfaces

- Interactive console (`hardn-service-manager`).
- REST API on port 8000 (key-based bearer auth).
- CLI subcommands (`hardn --help`).

## Quick Start

### Install and launch

```bash
git clone https://github.com/Security-International-Group/HARDN.git
cd HARDN
sudo make build
sudo make hardn
```

`make build` produces the Debian package; `make hardn` installs it and
opens the interactive service manager.

### Basic usage

```bash
sudo hardn --help              # full command list
sudo hardn --status            # current service state
sudo hardn --security-report   # one-shot security assessment
sudo hardn run-module hardening
sudo hardn run-tool   fail2ban
```

`run-module` and `run-tool` return exit 127 when the script does not exist
(POSIX "command not found"), so cron and CI can tell a typo from a real
failure.

## Components

### HARDN service manager

Primary interactive interface. Provides:

- Menu-driven service control
- Live status dashboards
- Log viewing and analysis
- Configuration management

### Compliance audit engine

A C-based SCAP/XCCDF engine (`src/audit/`) that:

- Evaluates STIG/CIS rules against the live system
- Emits a JSON report (rule id, title, status, evidence, severity)
- Feeds SENTRY file-baseline drift into the unified alert channel

### HARDN API service

REST API for remote management and monitoring:

- System health metrics
- Service status
- Remote command execution (limited command set)
- Integration with external tools
- `GET /metrics` exposes HARDN telemetry in Prometheus text format
  (service up/down, alert counts, SENTRY drift, cron job state,
  baseline age). Unauthenticated; scoped by the UFW + iptables
  `HARDN-LOCKDOWN` chain via `HARDN_API_ALLOWED_CIDRS`.

### Observability stack

`tools/prometheus.sh` installs Prometheus and `prometheus-node-exporter`
from Debian main, then drops a HARDN scrape config at
`/etc/prometheus/prometheus.d/hardn-scrape.yml` pointed at
`localhost:8000/metrics` and the node exporter on `localhost:9100`.

`tools/grafana.sh` installs Grafana on `HARDN_GRAFANA_PORT` (default 3000)
and provisions a default Prometheus data source at
`/etc/grafana/provisioning/datasources/hardn-prometheus.yaml`. Grafana
boots with HARDN telemetry already wired in.

Bring the stack up on a fresh host:

```bash
sudo hardn run-tool prometheus && sudo hardn run-tool grafana
```

Then browse to `http://<host>:3000` (admin / admin, change immediately).
The HARDN Prometheus data source is pre-configured.

### Hardening modules

Automated security-configuration modules under
`/usr/share/hardn/modules/`. The orchestrator delegates auditd-specific
rule loading to `/usr/share/hardn/tools/auditd.sh` so there is one writer
per rule file.

## Security Benefits

### Proactive protection

- STIG/CIS hardening applied at install and re-applied on demand.
- Daily compliance audit and SENTRY baseline diff.
- SENTRY baseline-diff catches persistence-vector tampering between
  scheduled scans.

### Operational security

- SSH key-based authentication (with lockout-safety fallback on cloud).
- Audit logging tuned for the available `/var/log` space.
- File and system integrity checks (AIDE).
- UFW + iptables firewall posture with cloud-metadata carve-outs.

### Incident response

- Alerts in `/var/log/hardn/alerts.jsonl` plus journald plus optional
  webhook.
- Per-key TTL dedupe so a noisy condition does not spam.
- Self-healing service restart through systemd.
- Forensic data preserved in `/var/lib/hardn/`.

## Community and Support

### Who we are

HARDN is developed by **Security International Group (SIG)**, a
community-driven organisation focused on advancing cybersecurity through
open-source solutions.

### Getting help

- Documentation: guides and API references under `docs/`.
- Issue tracking: GitHub issues for bug reports and feature requests.
- Contributing: open contribution guidelines under `CONTRIBUTING.md`.

### Resources

- [Service manager guide](hardn-service-manager.md)
- [HARDN API](hardn-api.md)
- [Audit engine internals](hardn-audit.md)
- [Security posture summary](security-posture.md)

## License and Contributing

HARDN is released under the MIT License, encouraging community
contributions and commercial use. Contributions from security researchers,
developers, and system administrators are welcome.

## Roadmap

### Current

- Interactive service manager
- SCAP/XCCDF compliance audit engine
- REST API service
- Automated hardening scripts
- SENTRY file-baseline drift detection
- Alert fanout to journald + webhook
- Environment-aware hardening for cloud, VM, and container surfaces

### Upcoming

- Web-based dashboard
- Expanded compliance rule coverage
- Multi-system management
- Additional SENTRY watch sources (AIDE results, package lists)

---

**Website**: [Security International Group](https://securityinternationalgroup.org)
**Repository**: [GitHub](https://github.com/Security-International-Group/HARDN)
