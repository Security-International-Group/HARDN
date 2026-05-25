![HARDN Logo](docs/assets/IMG_1233.jpeg)

# HARDN
**Linux Security Hardening and Extended Detection Response**


<p align="center">
	<a href="https://www.debian.org/"><img src="https://img.shields.io/badge/debian-13-8B0000?logo=debian&logoColor=white" alt="Debian Base" /></a>
	<a href="https://www.debian.org/"><img src="https://img.shields.io/badge/debian-12-8B0000?logo=debian&logoColor=white" alt="Debian Base" /></a>
  <a href="https://ubuntu.com/"><img src="https://img.shields.io/badge/ubuntu-22.04-E95420?logo=ubuntu&logoColor=white" alt="Ubuntu" /></a>
  <a href="https://ubuntu.com/"><img src="https://img.shields.io/badge/ubuntu-24.04-red?logo=ubuntu&logoColor=white" alt="Ubuntu" /></a>
	<a href="https://hits.sh/github.com/Security-International-Group/HARDN/"><img src="https://hits.sh/github.com/Security-International-Group/HARDN.svg?style=flat&label=views" alt="views" /></a>
</p>

HARDN is a security hardening toolkit for Debian-based Linux. It automates the
lockdown of a fresh install, watches for drift on the files attackers care
about, and keeps the operator in the loop through a GUI, an API, and a service
manager.

**Demo Version.** This release demonstrates the core features of HARDN-XDR. For
production use and advanced features, contact Security International Group.

## Features

- **Automated hardening.** One-command lockdown of SSH, auditd, sysctl,
  AppArmor, fail2ban, AIDE and friends.
- **Environment-aware.** Auto-detects bare-metal, cloud (AWS, GCP, Azure, DO,
  Oracle, Alibaba), VMs, and containers, then adjusts what it applies so it
  does not lock you out of a cloud instance or break rootless Podman / Firejail
  / Chrome sandbox / bpftrace on a container host.
- **SSH lockout safety.** Will not disable `PasswordAuthentication` on a cloud
  VM that has no public key registered. Operator overrides via
  `HARDN_FORCE_DISABLE_PASSWORD_AUTH=1` and `HARDN_KEEP_PASSWORD_AUTH=1`.
- **SENTRY drift detection.** Daily sha256 baseline diff of high-value files
  (`/etc/passwd`, `/etc/shadow`, `/etc/sudoers`, `authorized_keys`,
  `/etc/cron.*`, `/etc/systemd/system/*`). Drift fires an alert with severity
  scaled to the category.
- **Alert fanout.** Alerts land in `/var/log/hardn/alerts.jsonl` and fan out to
  **journald** (always) and an optional **webhook**
  (`HARDN_ALERT_WEBHOOK_URL`). A TTL-based dedupe cache stops a noisy condition
  from paging the on-call repeatedly.
- **Cron safety.** Every scheduled job runs under `flock` so a manual run and
  the daemon cannot collide. Suricata rule updates land in a staging dir,
  pass `suricata -T -S` validation, and atomically swap into place via
  `rename(2)`.
- **GUI.** GTK4 monitoring dashboard with a first-run welcome wizard, tab
  tooltips, and an auto-generated inventory of every tool under
  `usr/share/hardn/tools`. Read-only; never runs privileged commands without
  a sudo prompt.
- **API.** Optional REST endpoint on port 8000 with SSH-key bearer auth.
- **Clean uninstall.** `hardn-uninstall.sh` reverses what the install put
  in place, including per-user desktop launchers and the
  `/etc/profile.d/hardn-paths.sh` env-var loader. `apt purge hardn` performs
  the same cleanup via `debian/postrm`.

## Quick Start

### From source

```bash
git clone https://github.com/Security-International-Group/HARDN
cd HARDN
sudo make build
sudo make hardn
```

`make build` produces the Debian package. `make hardn` installs it and starts
the GUI service manager, which is where you trigger the actual hardening run.

### First run

On first launch the GUI shows a four-step Debian-style welcome wizard
(overview, GUI tour, common actions, where to get help) with **Skip** and
**Don't show again** options. The marker file is
`$XDG_CONFIG_HOME/hardn/welcome-seen`; set `HARDN_NO_WELCOME=1` to suppress
it under kiosk / CI / autostart.

### Common commands

```bash
sudo hardn --help              # full command list
sudo hardn --status            # current service state
sudo hardn --sentry-check      # diff high-value files vs baseline
sudo hardn run-module hardening
sudo hardn run-tool   fail2ban
sudo hardn legion --create-baseline
sudo hardn-service-manager     # interactive menu (also launched by the GUI)
```

`run-tool` and `run-module` now return exit 127 (POSIX "command not found")
when the requested script does not exist, so cron and CI can tell a typo apart
from a real failure.

## Remote access

HARDN does not block SSH by default. The hardening run tightens sshd
(public-key auth, no root login, modern ciphers, banner, rate limiting) and
leaves the service running. UFW allows the configured SSH port; restrict it
to specific source ranges with `HARDN_SSH_ALLOWED_CIDRS=10.0.0.0/8,...`.

To fully disable SSH, set `HARDN_DISABLE_SSH=1` before the hardening run.
HARDN will stop, disable, and mask `ssh.service` and `ssh.socket`, and skip
adding the UFW allow rule.

Two optional remote channels can be exposed in addition to (or instead of)
SSH:

| Channel | Default port | Auth | Override |
|---|---|---|---|
| HARDN API | 8000 | SSH public key (Bearer) | `HARDN_API_PORT`, `HARDN_API_ALLOWED_CIDRS` |
| Grafana | 3000 | Grafana credentials | `HARDN_GRAFANA_PORT`, `HARDN_GRAFANA_ALLOWED_CIDRS` |

Register a public key with the API:

```bash
sudo install -d -m 750 /etc/hardn
sudo install -m 640 /dev/null /etc/hardn/authorized_keys
cat ~/.ssh/id_ed25519.pub | sudo tee -a /etc/hardn/authorized_keys
sudo systemctl restart hardn-api.service
```

```bash
SSH_KEY=$(cat ~/.ssh/id_ed25519.pub)
curl -H "Authorization: Bearer $SSH_KEY" http://your-server:8000/health
curl -H "Authorization: Bearer $SSH_KEY" http://your-server:8000/overwatch/system
```

See [docs/hardn-api.md](docs/hardn-api.md) for the full endpoint list and key
rotation guidance.

## Services

After install, `debian/postinst` enables four systemd units:

| Unit | Purpose |
|---|---|
| `hardn.service` | Core hardening + LEGION monitoring loop |
| `hardn-api.service` | REST API on port 8000 |
| `hardn-monitor.service` | Service health + alert producer |
| `hardn-monitor.service` companions | Cron orchestrator runs inside |

`legion-daemon.service` is intentionally not enabled on new installs.
`hardn.service` runs the same LEGION daemon code; running both at once
contends on the baseline SQLite database. Operators who want the
response-disabled variant can swap in `legion-daemon.service` manually.

## Environment overrides

The hardening modules and tools read these in addition to the defaults:

| Variable | Default | Effect |
|---|---|---|
| `HARDN_DISABLE_SSH` | `0` | `1` stops + disables + masks `ssh.service` |
| `HARDN_SSH_PORT` | `22` | Port honoured by fail2ban jail and UFW allow rules |
| `HARDN_SSH_ALLOWED_CIDRS` | (none) | Space-separated allowlist for SSH |
| `HARDN_FORCE_DISABLE_PASSWORD_AUTH` | `0` | `1` forces `PasswordAuthentication no` even if no keys exist |
| `HARDN_KEEP_PASSWORD_AUTH` | `0` | `1` forces `PasswordAuthentication yes` |
| `HARDN_API_PORT` | `8000` | API listen port |
| `HARDN_API_ALLOWED_CIDRS` | (none) | Allowlist for the API port |
| `HARDN_GRAFANA_PORT` | `3000` | Grafana listen port |
| `HARDN_GRAFANA_ALLOWED_CIDRS` | (none) | Allowlist for the Grafana port |
| `HARDN_PERMITTED_OUTBOUND_CIDRS` | (none) | Extra outbound destinations to allow in UFW |
| `HARDN_CLOUD_LB_CIDRS` | provider-specific | Overrides fail2ban `ignoreip` health-check ranges |
| `HARDN_CONTAINER_HOST` | auto-detected | `1` forces the "container workload host" sysctl profile |
| `HARDN_STRICT_USERNS` | `0` | `1` applies `kernel.unprivileged_userns_clone=0` even on container hosts |
| `HARDN_STRICT_BPF` | `0` | `1` applies the eBPF lockdown even on container hosts |
| `HARDN_KERNEL_PANIC_SECONDS` | `60` | `kernel.panic` value (`0` to stay in panic for diagnosis) |
| `HARDN_ALERT_WEBHOOK_URL` | (none) | When set, alerts POST to this URL via `curl` |
| `HARDN_ALERT_JOURNALD_TAG` | `HARDN-ALERT` | syslog tag for journald-bound alerts |
| `HARDN_ALERT_DEDUPE_TTL_SEC` | `21600` | Dedupe window for journald + webhook fanout |
| `HARDN_NO_WELCOME` | `0` | `1` suppresses the GUI welcome wizard |

## Basic troubleshooting

```bash
sudo systemctl status hardn.service hardn-api.service hardn-monitor.service
sudo journalctl -u hardn.service -u hardn-monitor.service -f
tail -F /var/log/hardn/*.log
tail -F /var/log/hardn/alerts.jsonl
journalctl -t HARDN-ALERT --since today    # post-PR-C: alert fanout
```

If a hardening module fails inside an unprivileged container, that is
expected. The audit subsystem and several sysctls belong to the host kernel;
HARDN logs those as INFO and continues.

## Documentation

- [HARDN service](docs/hardn.md)
- [LEGION daemon](docs/legion-daemon.md)
- [HARDN API](docs/hardn-api.md)
- [Service manager guide](docs/hardn-service-manager.md)
- [Monitor + alert fanout](docs/hardn-monitor.md)
- [Audit engine internals](docs/hardn-audit.md)
- [Security posture summary](docs/security-posture.md)
- [Architecture diagrams](docs/diagram.md)

## Support

Some modules will partially apply on read-only filesystems, in containers,
and on hosts with non-standard package layouts. HARDN logs what it skipped
and keeps going. Open an issue with the `--security-report --json` output
attached if behaviour looks wrong.

## License

MIT. See `LICENSE`.

# Metrics

![GitHub Metrics](.github/metrics.svg)
