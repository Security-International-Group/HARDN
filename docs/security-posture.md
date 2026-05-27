![HARDN Logo](assets/IMG_1233.jpeg)
# HARDN Security Posture Overview

## Purpose

This document provides a consolidated view of the security controls implemented across the HARDN platform, including baseline hardening, monitoring, response automation, and recent updates to developer tooling access.

## Architecture Summary

- **Hardening Layer (`usr/share/hardn/modules/hardening.sh`)**: opinionated system lockdown that configures authentication, logging, networking, kernel parameters, and service hardening.
- **Monitoring & Orchestration (`src/legion/`)**: Legion service orchestrates baseline capture, drift detection, risk scoring, banner display, and automated response plans.
- **Service Manager (`src/hardn-service-manager/`)**: supervises HARDN services with secure defaults, ensuring health checks and controlled restarts.
- **Agent & CLI (`src/hardn-monitor.rs`, `scripts/`)**: provide operator touchpoints with consistent logging (`[INFO]`, `[WARN]`, etc.) through the `safe_println!` abstraction.

## Core Security Controls

### Baseline Hardening

- Enforces strong password policy (aging, complexity, reuse limits) and account inactivity (`chage --inactive 30`).
- Configures SSH for key-only authentication, disables root login, tightens ciphers/MACs, and displays an authorization banner.
- Locks down key filesystem paths (e.g., `/etc/shadow`, `/etc/ssh/sshd_config`, `/boot/grub/grub.cfg`) with strict ownership and permissions.
- Establishes persistent journaling, remote syslog forwarding, sudo logging, and world-writable directory audits.
- Tunes network parameters for resilient TCP behavior (reduced SYN retries, htcp congestion control, fast FIN timeouts).

### Compiler Access Policy (Updated)

- Default policy remains **restrictive**: compiler binaries owned by `root:hardncompilers` with `0750` permissions, preventing untrusted users from invoking native toolchains.
- `hardening.sh` now provisions the `hardncompilers` group automatically and supports `HARDN_COMPILER_ALLOWED_USERS`; sudoers can whitelist themselves in a single run without loosening global permissions.
- Alternate policies:
  - `allow`/`permissive`: sets compiler binaries to `0755` (world-executable) for development or CI needs.
  - `disable`/`off`: leaves existing permissions untouched, useful when external configuration management handles compiler lockdown.
- Recommendation: keep the group membership minimal and audited via `getent group hardncompilers`.

### Monitoring & Detection Enhancements

- **Baseline Drift Detection**: Legion compares current processes and listening ports against stored baselines, summarizing additions and missing entries in reports and snapshots.
- **Risk Scoring Engine**: Component-level factors recorded for anomaly, threat intel, behavioral, network, process, file integrity, system health, and temporal trends. Reports render explanations alongside numeric scores for transparency.
- **Domain-Aware Script Scoring**: Aggregates script results per domain, elevating anomaly scores when hardening checks emit warnings/failures.
- **Security Platform Health**: Tracks Grafana, Wazuh, and other platform services. Records warnings, inactive states, and time of last alert.
- **HIDS Resilience**: OSSEC tooling now auto-falls back to Wazuh packages when the legacy `ossec-hids` feed is unavailable and sends status logs to stderr so automation can detect failures cleanly.

### Environment-aware Hardening

- A pre-flight detector (`tools/env-detect.sh`) classifies the host as
  bare-metal, VM, container, or cloud (AWS, GCP, Azure, DigitalOcean,
  Oracle, Alibaba) before any rule is applied. The result is printed as a
  one-line banner at the start of every hardening run.
- Cloud and VM hosts retain `accept_ra` so IPv6 SLAAC keeps working.
- Container workload hosts (Docker, Podman, LXD, k8s state present, or
  `HARDN_CONTAINER_HOST=1`) skip `unprivileged_userns_clone=0`,
  `unprivileged_bpf_disabled=1`, and `bpf_jit_harden=2` so rootless
  workloads (Podman, Firejail, Chrome sandbox, bpftrace, Cilium) continue
  to function. Operators can force the strict values back on with
  `HARDN_STRICT_USERNS=1` and `HARDN_STRICT_BPF=1`.
- The cloud metadata IP (169.254.169.254, plus 168.63.129.16 on Azure) is
  explicitly allowlisted in UFW and the iptables `HARDN-LOCKDOWN` chain
  on cloud hosts.
- SSH hardening will not flip `PasswordAuthentication` to `no` when no
  public keys exist on a cloud or VM host (prevents permanent remote
  lockout). Overrides: `HARDN_FORCE_DISABLE_PASSWORD_AUTH=1`,
  `HARDN_KEEP_PASSWORD_AUTH=1`.

### Audit Rules

- Single writer: `/etc/audit/rules.d/99-hardn-hardening.rules` is owned by
  `tools/auditd.sh`. The previous duplicate writer in
  `modules/hardening.sh` has been removed.
- Buffer size and `disk_full_action` scale to free space on `/var/log`.
  Small cloud root disks degrade to `SYSLOG` instead of halting the kernel.
- All execve and module-load rules are paired across `arch=b64` and
  `arch=b32`, so 32-bit compat syscalls cannot evade.
- Auditd setup exits cleanly inside containers (audit subsystem belongs
  to the host kernel).

### File-Baseline Drift (SENTRY)

- Daily sha256 baseline diff of the high-value persistence files:
  `/etc/passwd`, `/etc/shadow`, `/etc/sudoers{,.d/*}`,
  `authorized_keys` for root and every UID >= 1000, `/etc/crontab`,
  `/etc/cron.*`, `/var/spool/cron/*`, `/etc/systemd/system/*.{service,timer,socket,path}`.
- Added/removed/changed files fire one alert each. Sudoers and
  authorized_keys drift = `critical`; other categories = `warning`.
- Alerts share the dedupe + journald + webhook fanout (see Reporting &
  Response).

### Reporting & Response

- Enhanced report output includes component factor tables, contributing
  factors, threat indicator breakdowns, detected issues, and baseline
  drift summary.
- JSON mode mirrors the console output for machine ingestion.
- Reactive response plans classify suspicious processes (Malicious /
  Suspicious / Unknown) and recommend block / quarantine / monitor actions
  with severity and rationale.
- Automated response engine remains gated behind `response_enabled`;
  manual review encouraged when disabled.
- Unified alert channel: `emit_alert()` writes to
  `/var/log/hardn/alerts.jsonl` and fans out to journald (always) and an
  optional webhook (`HARDN_ALERT_WEBHOOK_URL`). Per-key TTL dedupe
  (default 6 h, override `HARDN_ALERT_DEDUPE_TTL_SEC`) prevents
  pager-spam.

### Observability Stack

- `hardn-api` exposes `GET /metrics` in Prometheus text format. Series
  cover service up/down, alert counts by severity, SENTRY drift by verb
  and category, cron last-run timestamps and success flags, SENTRY
  baseline age, and LEGION baseline presence. Unauthenticated; relies on
  the UFW + iptables `HARDN-LOCKDOWN` chain scoped via
  `HARDN_API_ALLOWED_CIDRS` for access control.
- `tools/prometheus.sh` installs Prometheus + `prometheus-node-exporter`
  from Debian main and writes a HARDN scrape drop-in pointed at the
  `/metrics` endpoint plus the node exporter. Skipped in unprivileged
  containers.
- `tools/grafana.sh` installs Grafana on `HARDN_GRAFANA_PORT` (default
  3000) and provisions a default Prometheus data source so the dashboard
  boots wired in. UFW rule is added when UFW is active.

## Operational Considerations

- **Policy Files**: `/etc/hardn/compiler-policy.conf` controls compiler stance; ensure infrastructure-as-code or configuration management sets it explicitly.
- **Dangerous Defaults Check**: Re-run `hardening.sh` after OS upgrades or golden-image refreshes to reapply file permissions and logging targets.
- **Credential Rotation**: Align password aging with organizational policy; adjust `PASS_MAX_DAYS` and `remember=5` thresholds as requirements evolve.
- **Baseline Updates**: Schedule baseline snapshots after legitimate infrastructure changes to avoid persistent drift alerts.
- **Console Automation Controls**: The Makefile exposes `HARDN_AUTO_CONSOLE=1` to opt in to automatic console launch after builds and `HARDN_NO_CONSOLE=1` to suppress it entirely, preventing unattended installs from hanging.

## Security Posture Summary

| Layer | Control Themes | Status |
| --- | --- | --- |
| System Hardening | Authentication, logging, file permissions, network tuning | ✔ Active (via `hardening.sh`) |
| Compiler Restriction | Group-based least privilege with optional relaxations | ✔ Restrict by default (updated) |
| Monitoring & Detection | Baseline drift, risk scoring, threat indicators | ✔ Enhanced with factor explanations |
| Response & Reporting | Structured dashboards, JSON output, reactive plans | ✔ Automated + manual workflows |
| Governance | Configurable policies, auditable state, documented outputs | ✔ Supported (this document) |

## Next Steps

1. Review `hardn` service manager docs for operational runbooks (`docs/hardn-service-manager.md`).
2. Maintain the `hardncompilers` group membership via IAM/HR processes.
3. Integrate risk reports with downstream SIEM/dashboard tooling using JSON exports.
4. Schedule periodic tabletop exercises to validate automated response recommendations.
