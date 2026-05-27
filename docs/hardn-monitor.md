![HARDN Logo](assets/IMG_1233.jpeg)
# HARDN Monitoring System

## Overview

HARDN includes a monitoring system that provides real-time security event tracking, service management, and threat detection. Multiple monitoring components feed into a single interactive interface.

## Core Components

### LEGION Security Monitoring Daemon

The LEGION daemon (`legion-daemon.service`) provides continuous security monitoring with the following capabilities:

- **Syslog Monitoring**: Real-time analysis of system logs for security events
- **Journal Monitoring**: systemd journal monitoring for service and system events
- **Network Monitoring**: Network traffic analysis and anomaly detection
- **Threat Intelligence**: Integration with threat intelligence feeds and IOC (Indicators of Compromise) processing
- **Active Monitoring**: Continuous background monitoring with automated response capabilities

### Service Monitoring

HARDN monitors and manages multiple systemd services:

- `hardn.service` - Main HARDN security service
- `hardn-api.service` - REST API service for external integrations
- `legion-daemon.service` - LEGION security monitoring daemon
- `hardn-monitor.service` - Monitoring coordination service

### Interactive Service Manager

The `hardn-service-manager.sh` script provides a menu-driven interface for:

- **Service Status Monitoring**: Real-time display of service states with color-coded indicators
- **Service Management**: Start, stop, restart, enable, and disable services
- **Log Viewing**: Interactive log monitoring for individual services or all services simultaneously
- **Module Execution**: Run security hardening modules and tools
- **LEGION Control**: Manage LEGION monitoring operations and view security reports

## Monitoring Feeds

### Log Data Sources

The monitoring system aggregates log data from multiple sources:

1. **LEGION Daemon Logs**: Security events, threat detections, and monitoring alerts
2. **HARDN Service Logs**: Core service operations and hardening activities
3. **HARDN API Logs**: API requests, responses, and integration activities
4. **System Journal**: systemd service logs and system-level events

### IOC and Error Monitoring

- **Indicators of Compromise (IOC)**: Automated detection and processing of known threat indicators
- **Error Monitoring**: Per-component error tracking across all HARDN services
- **Update Monitoring**: Tracking of security updates and system changes
- **Collective Feed Source**: Unified log aggregation for centralized monitoring

## Alert Channel and Fanout

Every alert producer (`hardn-monitor`, the LEGION daemon, `hardn --sentry-check`)
writes one JSON-lines record into `/var/log/hardn/alerts.jsonl`:

```json
{"ts":"2026-05-25T18:30:42Z","severity":"critical","source":"sentry/sudoers","message":"sudoers added watched file: /etc/sudoers.d/badop","key":"sentry:sudoers:added:/etc/sudoers.d/badop"}
```

Fields are fixed: `ts`, `severity`, `source`, `message`, `key`. Severities
used today: `info`, `warning`, `error`, `critical`.

`alerts.jsonl` is the canonical record. After writing, each alert is
forwarded to two optional sinks gated by a shared TTL dedupe so a noisy
condition cannot pager-spam:

| Sink | Mechanism | Enable by |
|---|---|---|
| journald | `systemd-cat -t HARDN-ALERT -p <prio>` (fallback `logger(1)`) | Always on |
| Webhook | `curl -fsS -m 10 -X POST` with the JSON payload as body | Set `HARDN_ALERT_WEBHOOK_URL=https://...` |

Dedupe state lives at `/var/lib/hardn/alerts/seen.json`, keyed by the
`key` field. Default TTL is 21600 s (6 hours); override via
`HARDN_ALERT_DEDUPE_TTL_SEC`. The journald tag and dedupe path can be
overridden with `HARDN_ALERT_JOURNALD_TAG` and `HARDN_ALERT_DEDUPE_PATH`.

The GUI tails `alerts.jsonl` and collapses repeats of the same `key` into
a single updating row.

## Prometheus Metrics Endpoint

`hardn-api` publishes a `GET /metrics` endpoint in Prometheus text
exposition format. Unauthenticated; rely on the network-layer policy
already enforced by UFW and the iptables `HARDN-LOCKDOWN` chain
(scoped via `HARDN_API_ALLOWED_CIDRS`).

Series exposed:

| Series | Source |
|---|---|
| `hardn_info{version}` | build metadata |
| `hardn_service_up{service}` | `systemctl is-active` for the four HARDN units |
| `hardn_alerts_total{severity}` | `/var/log/hardn/alerts.jsonl` |
| `hardn_sentry_drift_total{verb,category}` | SENTRY-source alerts |
| `hardn_cron_last_run_timestamp_seconds{job}` | `/var/lib/hardn/monitor/cron_summary.json` |
| `hardn_cron_last_success{job}` | as above |
| `hardn_cron_last_duration_seconds{job}` | as above |
| `hardn_sentry_baseline_age_seconds` | mtime of the SENTRY baseline file |
| `hardn_legion_baseline_present` | 1 if a LEGION baseline SQLite DB exists |

`tools/prometheus.sh` installs Prometheus + node-exporter and writes
`/etc/prometheus/prometheus.d/hardn-scrape.yml` pointing at
`localhost:8000/metrics` and `localhost:9100`. `tools/grafana.sh`
provisions Grafana with the matching Prometheus data source, so the
stack runs out of the box on a fresh install.

## Usage

### Launching the Monitoring Interface

```bash
# Primary method - launches the interactive service manager
sudo make hardn

# Alternative - direct service monitoring
sudo hardn services

# View help and navigation
hardn --help
```

### Navigation

The interactive interface provides:

- **Menu Navigation**: Use numbers or arrow keys to select options
- **Log Viewing**: Press Ctrl+C to return to menus (doesn't exit the application)
- **Quick Exit**: Press 'q' to quit from any menu
- **Real-time Updates**: Live service status and log monitoring

### Monitoring Commands

```bash
# Check service status
sudo hardn --status

# View service logs
sudo journalctl -u hardn.service -f

# Generate security report
sudo hardn --security-report

# Run LEGION monitoring
sudo hardn legion
```

## Architecture

### Monitoring Flow

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   LEGION Daemon │───▶│  Service Manager │───▶│  Interactive UI │
│                 │    │                  │    │                 │
│ • Syslog        │    │ • Status Display │    │ • Menu System   │
│ • Journal       │    │ • Log Aggregation│    │ • Real-time     │
│ • Network       │    │ • Service Control│    │   Monitoring    │
│ • Threat Intel  │    │                  │    │                 │
└─────────────────┘    └──────────────────┘    └─────────────────┘
```

### Integration Points

- **Systemd Services**: All monitoring components run as systemd services
- **Journal Integration**: Uses systemd journal for log aggregation
- **Signal Handling**: Graceful Ctrl+C handling for navigation
- **Async Operations**: Tokio-based concurrent monitoring operations

## Security Features

- **Continuous Monitoring**: 24/7 background security monitoring
- **Threat Detection**: Automated threat intelligence processing
- **Anomaly Detection**: Network and system behavior analysis
- **Incident Response**: Automated response capabilities
- **Audit Logging**: Auditd rules cover MITRE ATT&CK T1003/T1041/T1053/T1059/T1105/T1547/T1562, paired across `arch=b64` and `arch=b32` so 32-bit compat syscalls cannot evade. Audit buffer size and disk-full action scale to free space on `/var/log`.

## Troubleshooting

### Common Issues

- **Service Not Starting**: Check `sudo hardn --status` and journal logs
- **Permission Errors**: Ensure running with sudo privileges
- **Log Access Issues**: Verify systemd journal permissions
- **Network Monitoring**: Check network interface permissions

### Log Locations

- Service logs: `journalctl -u <service-name>`
- LEGION logs: `journalctl -u legion-daemon`
- System logs: `/var/log/hardn/`
- Configuration: `/etc/hardn/`

## Future Enhancements

- Browser-based monitoring dashboard
- Expanded threat analytics
- Extensible monitoring module support
- Remote alerting integration
