# Changelog

All notable changes to **HARDN** are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### ClamAV signature fetch + Status list drift (dev_testing 2026-06-13 follow-up)

Two bugs surfaced in Orinax's dev_testing screenshots after the
tool-output-honesty round landed:

- **`clamv.sh` now fetches signatures inline when none are on disk.**
  Previously the script warned `ClamAV virus definition files not found`
  and then tried to start `clamav-daemon`, which refuses to start
  without a signature database. The daemon then sat inactive and
  Status reported ClamAV as down. New behaviour: if neither
  `/var/lib/clamav/{main,daily}.{cvd,cld}` exists, stop
  `clamav-freshclam.service` (to release the lock), run
  `freshclam --quiet` with a 5-minute timeout, log to
  `/var/log/hardn/freshclam.log`, and only then attempt to enable
  `clamav-daemon`. Final status now honestly reports which of the two
  services actually came up.

- **Status security-tool list now covers all 13 deployed tools.**
  The Run menu listed 13 entries; Status only listed 9, producing
  `Total active security tools: 1/9` instead of `1/13`. Root cause:
  `get_security_tools()` in `src/main.rs` and `src/setup/main.rs`
  was last updated before PR-G added the Prometheus + Grafana stack
  and before Suricata shipped. Added Suricata, Grafana,
  Prometheus, and Node Exporter to both lists with their real
  systemd unit names (`suricata`, `grafana-server`, `prometheus`,
  `prometheus-node-exporter`).

Regression guard: `tests/static/tool-output-honesty.t.sh` extended
from 7 to 11 assertions. The needle list now includes
`suricata`, `grafana-server`, `prometheus`, and
`prometheus-node-exporter`, so any future tool script added under
`usr/share/hardn/tools/` that does not also land in the Status list
trips pre-push CI.

### Stability sweep across Debian 12-13 + Ubuntu 22.04-24.04 (ISSUE-180 follow-up)

Four additional fixes layered onto the install-time-noise fix below,
each pinning down one stability bug surfaced during the four-OS audit:

- **`hardn-monitor.service` no longer depends on `legion-daemon.service`.**
  The unit's `After=`/`Wants=` lines used to list `legion-daemon.service`,
  which is the mutually-exclusive variant of `hardn.service`
  (`Conflicts=` in the .service file) and is disabled by `debian/postinst`.
  Listing it as a `Wants=` triggered transient activation on every
  `systemctl start hardn-monitor`, which then stopped `hardn.service`.
  Same class of bug PR-181 fixed in the Rust monitor; this fixes the
  unit-dependency layer too.

- **`legion-daemon.service` `ExecStartPre` no longer strips the setgid bit
  from `/var/lib/hardn`.** Previously the prep step `chmod 755`'d the
  data dir, clobbering `debian/postinst`'s `2770 root:hardn` mode. After
  that ran, the `hardn` user (who runs `hardn-api.service`) could no
  longer write under `/var/lib/hardn`. Changed to `chmod 2770` to match
  what postinst sets.

- **`audispd-plugins` dropped from the auditd install line.** Folded into
  the `auditd` package in audit-userspace 3.x (Debian 13 / Ubuntu 24.04
  and later). Asking for it explicitly produces a "transitional package"
  warning on those releases. Removed; everywhere we support, `auditd`
  alone covers it.

- **Duplicate ClamAV install block removed from `hardening.sh`.** The
  module installed ClamAV twice and triggered two `freshclam` signature
  downloads (~250MB each) per hardening run, which on slow / metered
  connections wedged the run for minutes. Now one install, one
  freshclam.

Regression guard: new `tests/static/systemd-unit-safety.t.sh` greps the
unit files to lock in: hardn-monitor does not depend on legion-daemon;
legion-daemon does not chmod-755 the data dir; hardn.service still has
the `Conflicts=`; hardn-api still gates start on `authorized_keys`.

### Install-time noise (ISSUE-180 follow-up)

After PR-181 fixed the `hardn-monitor` restart-loop, the tester
(Orinax) reported that `sudo make hardn` still prints scary
"Job for hardn-api.service failed because the control process exited
with error code" and "Job for legion-daemon.service failed" lines
during install. The HARDN GUI panels then showed inconsistent service
state because two terminals queried `systemctl` at different points in
the still-flapping startup.

Root cause was a single Makefile line:

```makefile
systemctl enable --now hardn.service hardn-api.service \
                       legion-daemon.service hardn-monitor.service
```

Two bugs on that line:

1. `legion-daemon.service` is the mutually-exclusive variant of
   `hardn.service` (`Conflicts=legion-daemon.service` in the unit
   file). `debian/postinst` explicitly disables it; the Makefile
   silently re-enabled it.

2. `hardn-api.service` correctly refuses to start when
   `/etc/hardn/authorized_keys` is empty (HARDN-API has no concept of
   anonymous access). `enable --now` on a fresh install hits that
   refusal before the operator has had a chance to register a key, and
   surfaces it as a generic systemd failure.

Fix in `Makefile` (target `hardn-internal`):

* Drop `legion-daemon.service` from the enable-and-start list. Matches
  `debian/postinst`'s posture.
* Gate the `--now` on `hardn-api.service` behind a presence check for
  a valid public key in `/etc/hardn/authorized_keys`. When no key is
  present, the service is still enabled (so it starts on next boot
  after the operator adds a key) but not started immediately. A
  friendly warning tells the operator the exact `systemctl start`
  command to run.

Regression test: `tests/static/makefile-install-safety.t.sh` greps the
Makefile to lock in both invariants, plus asserts that
`hardn.service` and `hardn-monitor.service` are still enabled+started
on a normal install so the fix can't accidentally drop them.

### CI: `dependency-review.yml` workflow

New standalone workflow at `.github/workflows/dependency-review.yml`
that runs GitHub's official `actions/dependency-review-action` on every
PR. The action diffs the PR's dependency manifests (Cargo.lock and
friends) against the base branch and fails the check when a new
dependency introduces a known advisory at moderate severity or above.
Also blocks the GPL-3.0 / AGPL-3.0 license categories that can't ship
with MIT-licensed HARDN.

The check runs in parallel with `test.yml` and `ci.yml` under its own
concurrency group. Designed to be marked as a required gate in branch
protection alongside the test harness. The action is pinned to the
`@v4` major-version tag; Dependabot's existing `github-actions`
ecosystem entry will pin it to a SHA on its next weekly scan.

### CI: `test.yml` workflow

New standalone workflow at `.github/workflows/test.yml` that runs the
full `tests/run-all.sh` harness on every PR and main push. Designed to
be marked as a **required check** in branch protection so it gates
merges before `ci.yml`'s heavier build step.

The workflow installs every prerequisite the suites might need
(`shellcheck`, `systemd-analyze`, `python3-yaml`, `fastapi`, `httpx`,
`psutil`, stable Rust) so suites that previously reported SKIP on a
bare runner now run for real. Then:

* Runs `bash tests/run-all.sh`.
* Inlines the full Markdown report into `$GITHUB_STEP_SUMMARY` so the
  pass/fail table + per-suite TAP output renders on the GitHub Actions
  run page without downloading anything.
* Uploads the same report as an artifact (`name: test-report`,
  retention 30 days) so it's available to attach to bug reports.
* Fails the workflow on any harness failure.

The harness's report header now uses `## Result: PASS / FAIL` as a real
Markdown heading rather than bold text, so it renders as a top-level
section in the GitHub job summary.

### Service-restart loop fix (ISSUE-180)

Reported by Orinax. After install, `hardn.service` would keep getting
SIGTERM'd a few seconds into each run and eventually go to
`Active: failed (Result: start-limit-hit)`. Root cause was inside
`hardn-monitor`:

1. The monitor watched `legion-daemon.service` and auto-restarted it
   whenever it appeared stopped. `legion-daemon.service` is the
   response-disabled variant of the LEGION daemon and is intentionally
   **not** enabled on new installs (`debian/postinst` disables it).
   `hardn.service` declares `Conflicts=legion-daemon.service`. So:
   monitor saw legion-daemon = stopped, ran `systemctl restart
   legion-daemon`, systemd stopped `hardn.service` to honour the
   conflict, `Restart=always` brought it back, monitor ran again,
   repeat. After 5 such cycles `StartLimitBurst` tripped and
   `hardn.service` went to `start-limit-hit`.
2. The same shape hit `hardn-api.service` whenever
   `/etc/hardn/authorized_keys` was empty (the API refuses to start
   without keys, by design). Monitor restarted it, it failed, repeat.

Fixes in `src/hardn-monitor.rs`:
- Dropped `legion-daemon.service` from the default watch list. Operators
  who explicitly enable it will still get it watched via the gate below.
- New `is_enabled_unmasked()` gate. The monitor now skips auto-restart
  for any unit that is `disabled`, `static`, `masked`, or `linked`.
  Operator intent is respected.
- New per-service backoff. After `MAX_RESTART_ATTEMPTS = 3` consecutive
  failed restarts inside a 5-minute window the monitor stops trying and
  emits a one-shot `critical` alert tagged `svc-backoff:<service>`. A
  successful restart resets the counter. Each service tracks
  independently.
- Three regression tests in `hardn-monitor::tests` cover the backoff
  threshold, the reset on success, and independent per-service state.

This unblocks the testers reproducing the bug on a fresh Debian 13 VM
without changing any documented behaviour for a healthy install.

### Test harness (tests/ directory)

New tests/ directory with a TAP-style harness and Markdown report writer
covering the parts of HARDN we can verify without root + a real VM. The
orchestrator at `tests/run-all.sh` runs every suite and writes a single
timestamped report into `tests/reports/`. Run with:

```
bash tests/run-all.sh
```

Suites shipped in the first cut:

| Suite | What |
|---|---|
| `static/shellcheck` | `shellcheck -S error` on every shell file |
| `static/python-syntax` | `py_compile` on every `src/*.py` |
| `static/yaml-lint` | `yaml.safe_load` on every workflow YAML |
| `static/systemd-verify` | `systemd-analyze verify` on every unit |
| `static/doc-hygiene` | no em-dashes / AI-tell adjectives / vendor strings in maintainer docs |
| `unit/env-detect` | container-host / nftables / cloud-LB CIDR predicates |
| `unit/preflight` | required-vs-optional exit-code logic via mocked `apt-cache` |
| `unit/functions` | `HARDN_STATUS` no-color when not a TTY |
| `unit/alerts-payload` | canonical `{ts,severity,source,message,key}` shape |
| `integration/cli-help` | `hardn --help` lists current flags; `run-tool <missing>` returns 127 |
| `integration/sentry-flow` | first-run baseline + drift detection + alert write |
| `integration/uninstall-dryrun` | every PR-A and PR-E cleanup path referenced in the script |
| `integration/api-endpoints` | FastAPI TestClient on every endpoint + bearer-auth contract + `/metrics` shape |
| `cargo/cargo-test` | wraps `cargo test --bin hardn` and `--bin hardn-monitor` |

Suites that need a missing prerequisite (`shellcheck`, `systemd-analyze`,
`fastapi`, `httpx`, root, writable `/etc/cron.d`) report SKIP rather
than FAIL. `tests/README.md` lists what the harness deliberately does
not cover (real kernel/systemd/apt mutations).

First run on a fresh `test-harness` branch: 14 suites green, 87/89
assertions pass, 2 skipped (preflight on a branch where the script has
not yet landed; api-endpoints when `httpx` is not installed).


The unreleased work landed as seven stacked PRs (A, B, D, C, E, F, G) on
the `patch` branch through May 2026. They are grouped here by area rather
than by PR.

### Observability: Prometheus + Grafana wired through (PR G)

- New **`GET /metrics`** endpoint on `hardn-api`, Prometheus text-format,
  unauthenticated (same access-control story as `/health`: rely on the
  network-layer policy that UFW + the iptables `HARDN-LOCKDOWN` chain
  already enforce). Exposed series:
  - `hardn_info{version=...}`
  - `hardn_service_up{service=...}` for the four HARDN units
  - `hardn_alerts_total{severity=...}` from `alerts.jsonl`
  - `hardn_sentry_drift_total{verb=...,category=...}` from SENTRY records
  - `hardn_cron_last_run_timestamp_seconds{job=...}`,
    `hardn_cron_last_success{job=...}`,
    `hardn_cron_last_duration_seconds{job=...}` from `cron_summary.json`
  - `hardn_sentry_baseline_age_seconds`
  - `hardn_legion_baseline_present`
- New `tools/prometheus.sh`. Installs `prometheus` +
  `prometheus-node-exporter` from Debian main, appends a
  `scrape_config_files: /etc/prometheus/prometheus.d/*.yml` include to the
  shipped `/etc/prometheus/prometheus.yml`, drops a HARDN scrape
  drop-in that pulls from `localhost:8000/metrics` and the node exporter.
  Skips on unprivileged containers.
- `tools/grafana.sh` now honours `HARDN_GRAFANA_PORT` (default 3000) end
  to end. Previously it hard-coded 9002, which mismatched the UFW rule
  written by `modules/hardening.sh`. The firewall and the daemon now
  agree.
- `tools/grafana.sh` provisions a default **HARDN Prometheus** data
  source at `/etc/grafana/provisioning/datasources/hardn-prometheus.yaml`,
  pointed at `$HARDN_PROMETHEUS_URL` (default `http://localhost:9090`).
  Grafana lights up with data as soon as `tools/prometheus.sh` has run.
- New env knobs:
  `HARDN_PROMETHEUS_PORT` (9090),
  `HARDN_NODE_EXPORTER_PORT` (9100),
  `HARDN_PROMETHEUS_ALLOWED_CIDRS`,
  `HARDN_PROMETHEUS_URL`.
- Misleading placeholder removed. The Rust `"System Monitoring"`
  category in `src/main.rs` and `src/setup/main.rs` listed
  `prometheus_monitoring`, which was a string with no backing tool. It is
  now `["audit", "auditd", "prometheus", "grafana"]`, all of which exist
  on disk under `usr/share/hardn/tools/`.

### Hardware, cloud, and container compatibility (PR A + B)

- New env-detection helper `tools/env-detect.sh`. Exports
  `HARDN_ENV_VIRT`, `HARDN_ENV_CLOUD`, and the predicates
  `hardn_in_container`, `hardn_in_vm`, `hardn_in_cloud`,
  `hardn_on_baremetal`. Sourced from `functions.sh` and `hardening.sh`.
- The hardening run now prints a one-line "Detected environment" banner so
  operators see what HARDN will skip.
- SSH hardening will not disable `PasswordAuthentication` when the host has
  no public keys and is on a cloud VM. Override with
  `HARDN_FORCE_DISABLE_PASSWORD_AUTH=1`; force-keep with
  `HARDN_KEEP_PASSWORD_AUTH=1`.
- Cloud instance metadata IP (169.254.169.254, plus 168.63.129.16 on Azure)
  is explicitly allowlisted in UFW and the iptables `HARDN-LOCKDOWN` chain
  on cloud hosts.
- Fail2Ban jail honours `HARDN_SSH_PORT` (was hard-coded 22) and
  pre-populates `ignoreip` with cloud load-balancer health-check ranges
  (GCP shipped; operators override via `HARDN_CLOUD_LB_CIDRS`).
- Auditd ships a disk-safety policy (`disk_full_action=SYSLOG`,
  `space_left_action=SYSLOG`, `admin_space_left_action=SUSPEND`) and sizes
  its audit buffer based on free space on `/var/log`. Small cloud root
  volumes can no longer be filled into a kernel panic.
- Auditd setup exits cleanly inside containers instead of spamming "Operation
  not permitted" against the host audit subsystem.
- FireWire blacklist + `modprobe -r firewire-core` + initramfs rebuild are
  skipped in containers.
- Sysctl writes that fail inside an unprivileged container now log INFO
  ("host owns this parameter") instead of WARNING.

### Tools hygiene (PR D)

- Every cron job runs under `/usr/bin/flock -n -E 99` keyed by
  `/run/hardn/cron-locks/<job>.lock`. Concurrent HARDN processes (daemon
  plus manual run, or two daemons during upgrade) cannot double-fire a job.
  A busy lock is logged as INFO ("another instance held the lock") and
  reported as success so the dashboard does not light up red.
- Suricata rule updates run into a staging directory
  (`/var/lib/hardn/suricata-rules-staging`), pass `suricata -T -S`
  validation, then atomically swap into `/etc/suricata/rules/suricata.rules`
  via `rename(2)`. A running Suricata can no longer observe a half-written
  rule file. Update failure leaves the previous rules untouched.
- Suricata setup uses `install -d -o suricata -g suricata -m 0755 ...` so
  rule, log, and cache dirs land with the right ownership in one syscall.
  Closes the chmod race between `mkdir` and the later `chown`.
- New `EXIT_NOT_FOUND = 127` exit code. `hardn run-tool <missing>` and
  `hardn run-module <missing>` now return 127 (POSIX "command not found")
  instead of 1, so cron and CI can tell a typo from a real failure.

### LEGION tattletale, phase 1 (PR C)

- New sentry module (`legion::modules::sentry`). Runs once-per-day from the
  cron orchestrator, sha256-hashes a curated set of high-value files, diffs
  them against `/var/lib/hardn/sentry/baseline.json`, and emits one alert
  per added, removed, or changed entry. Watched paths:
  `/etc/passwd`, `/etc/shadow`, `/etc/gshadow`, `/etc/group`,
  `/etc/sudoers`, `/etc/sudoers.d/*`,
  `/{root,/home/*}/.ssh/authorized_keys{,2}`, `/etc/crontab`,
  `/etc/cron.{d,daily,hourly,weekly,monthly}/*`,
  `/var/spool/cron/{,crontabs/}*`,
  `/etc/systemd/system/*.{service,timer,socket,path}`,
  `/etc/systemd/system/*.d/*.conf`.
- New CLI: `hardn --sentry-check`. Runs sentry once, prints a short
  report, emits alerts. First run silently writes the baseline; subsequent
  runs alert on drift. Authorized-keys and sudoers drift fire
  `critical`; cron, systemd, and passwd/shadow drift fire `warning`.
- New cron job `hardn-sentry` runs daily at 02:15.
- Alert fanout: every `emit_alert()` now also forwards to journald
  (always) and webhook (when `HARDN_ALERT_WEBHOOK_URL` is set). Both
  sinks share a TTL dedupe cache at `/var/lib/hardn/alerts/seen.json` so
  a noisy condition cannot pager-spam an on-call.
  - Journald uses `systemd-cat -t HARDN-ALERT -p <prio>` (fallback to
    `logger(1)` on non-systemd hosts). Tag overridable via
    `HARDN_ALERT_JOURNALD_TAG`.
  - Webhook POSTs the same JSON payload as `alerts.jsonl` (`ts`,
    `severity`, `source`, `message`, `key`) via `curl -fsS -m 10`. `http://`
    and `https://` only. No new compile-time dep added.
  - Dedupe TTL defaults to 6 hours; override via
    `HARDN_ALERT_DEDUPE_TTL_SEC`.

### GUI guidance and uninstall parity (PR E)

- New welcome wizard: a four-step Debian-style modal that pops up on first
  launch with an overview, GUI tour, common actions, and where to get help.
  Back, Next, Skip, Done navigation; "Don't show this on next launch"
  checkbox writes `$XDG_CONFIG_HOME/hardn/welcome-seen`. Also suppressible
  via `HARDN_NO_WELCOME=1`.
- New Tools tab. Auto-generated inventory of every `usr/share/hardn/tools/*.sh`
  with its one-line description, plus a hint for running them from the
  shell.
- Tooltips on every tab label (Logs, Terminal, Logs+Terminal, Alerts,
  Tools) explain what each view shows.
- `hardn-uninstall.sh` cleans up the install artefacts the previous
  version forgot:
  - `/etc/profile.d/hardn-paths.sh`
  - `/etc/audit/auditd.conf.d/99-hardn.conf` (PR A drop-in)
  - `/etc/fail2ban/jail.local`
  - System-wide `/usr/share/applications/hardn-gui.desktop`
  - Per-user `~/.local/share/applications/hardn-gui.desktop` and
    `~/.local/share/icons/hardn-gui.jpeg` for every passwd entry with
    `uid >= 1000` and a valid home
  - `/run/hardn/` (cron-locks tmpfs dir from PR D)
  - `/var/lib/hardn/{sentry,alerts,suricata-rules-staging}`
  - Runs `update-desktop-database` so the system menu drops the HARDN
    entry without requiring a logout
- New `debian/postrm`. On `apt remove` it removes
  `/etc/profile.d/hardn-paths.sh`; on `apt purge` it also nukes
  `/usr/share/applications/hardn-gui.desktop`, `/var/log/hardn`,
  `/var/lib/hardn`, `/etc/hardn`, `/run/hardn` and refreshes the desktop
  database. Debhelper's auto-generated systemd-unit teardown is preserved
  via `#DEBHELPER#`.

### Kernel rules consolidation (PR F)

- Single audit-rules writer. `modules/hardening.sh` no longer writes
  `/etc/audit/rules.d/99-hardn-hardening.rules`; it delegates to
  `tools/auditd.sh`. The hardening.sh copy had a malformed
  `/etc/cron.monthly/-p war` watch (missing space), placed `-D` after the
  rule list (which wiped its own rules), duplicated the `auditd.conf`
  drop-in from `tools/auditd.sh`, and ignored the container-skip gate.
  One writer, one rules file.
- `kernel.unprivileged_userns_clone=0`, `kernel.unprivileged_bpf_disabled=1`,
  and `net.core.bpf_jit_harden=2` are now gated on a new
  `hardn_is_container_workload_host` heuristic (Docker, Podman, LXD, k8s
  state dirs or binaries present, or `HARDN_CONTAINER_HOST=1`). Operators
  can force the strict values back on with `HARDN_STRICT_USERNS=1` and
  `HARDN_STRICT_BPF=1`. Stops HARDN from breaking rootless Podman,
  Firejail (which HARDN installs), Chrome sandbox, bpftrace, and friends.
- IPv6 `accept_ra=0` is skipped on cloud and VM. SLAAC needs RA enabled to
  learn a default route on AWS, GCP, Azure, and DigitalOcean. Bare-metal
  behaviour unchanged.
- `kernel.exec-shield=1` removed. Red Hat-only patch, dropped upstream
  before kernel 3.x. Produced "unsupported sysctl" warning every run on
  Debian and Ubuntu.
- `kernel.modules_disabled=0` removed. Was a no-op (kernel default) and
  risky to flip to 1 (one-shot kill switch).
- `kernel.panic` is now overridable via `HARDN_KERNEL_PANIC_SECONDS`
  (default 60 retained for compat; cloud hosts typically want 10).
- Every `arch=b64` execve and module rule now has a paired `arch=b32`
  line. A 32-bit compat syscall (int 0x80 on amd64) previously bypassed
  every `mitre_cmd_exec` and `mitre_rootkit` watch unobserved.
- `/tmp` and `/var/tmp` `-p wa` watches removed. Generated one record per
  shell, compiler, or test tempfile and filled `/var/log/audit` on build
  servers in minutes. CIS Benchmark deliberately omits them. SENTRY's
  persistence-vector diff covers what the `/tmp` watch was nominally
  protecting against.
- Broken T1041 exfil rules dropped. `-S connect -F a0=2` filtered on the
  file descriptor instead of the address family (which lives in `*addr`
  and is not reachable from a register filter). The rules matched either
  nothing or every connect on the host, both worthless. Exfil detection
  belongs in a userspace consumer or NIDS; HARDN already ships Suricata
  for that.

### Logs and UX

- `HARDN_STATUS` no longer writes ANSI colour escapes to log files when
  stdout is not a TTY. The GUI's log tail now reads clean text.
- `hardn --help` lists the `--enable-selinux` flag, which was previously
  documented only in the setup binary.
- `hardn --help` lists `--sentry-check`.

## [1.1.0-1] - 2026-05-24

### Audit framework, 100% coverage (194/194 rules)

- 25 sysctl-based audit checks for kernel network hardening
- 19 mount-option audit checks via `/proc/mounts`
- 19 audit checks for the audit subsystem, GRUB, journald, rsyslog,
  coredumps, wireless and wheel-group restrictions
- 16 audit checks for shadow ages, PAM faillock, GRUB, AppArmor and
  rsyslog network configuration
- 15 final audit checks to reach 100% rule coverage
- 12 audit checks for account structure, password ages and umask
- 9 systemd service-state audit checks via `systemctl`
- 8 dpkg-based package install-state audit checks
- 8 audit checks for home directory and dotfile hygiene
- Firewall default-policy and `/var/log` permissions audit checks
- Audit checks for `passwd`, `shadow`, and cron file owner, group, and mode
- 2 kernel-module-disabled audit checks (`cramfs`, `usb-storage`)

### LEGION and alerting

- LEGION emits alerts to the shared alert channel on high or critical risk
- Structured alert channel from `hardn-monitor` to `hardn-gui`
- Unified LEGION baseline DB path via `Config::database_path()`

### hardn-gui

- Tails all HARDN log files and follows correctly from the left pane
- Cleaned security report warning output
- Inline CSS path validation; removed deleted `path_security` dependency
- Fixed GTK app output error (ISSUE_135)

### Packaging and installation

- Full uninstall script with boot-safety fixes for `hardn-api`,
  `hardn.service`, and `legion-daemon.service`
- Hardened tool-launch safety. Renamed `selinux.sh` to
  `selinux.sh.DANGEROUS`, filter helper libraries, fix install logic
- Ignored `dpkg-buildpackage` `hardn.debhelper.log` artifact
- Fixed dpkg failure for monitor output
- Fixed version mismatch in `hardn-monitor` (ISSUE_134)
- Fixed staircasing output issue

### CI and release

- Richer Discord release notification. Embeds the new tag, a short
  changelog of commits since the previous release, and a working URL to
  the actual release page
- Added `.github/CODEOWNERS` with `@OpenSource-For-Freedom` as global owner
- Run `ci.yml` on pull requests to `main`; gate the release job to `main`
  pushes
- Applied least-privilege permissions per job in CI
- Various GitHub Actions and Rust dependency bumps via Dependabot

## [1.0.0-1] - 2024-09-21

### Added

- Initial public demo release
- Core security hardening framework
- Modular architecture with tools support
- Included tools: AIDE, Legion, Fail2ban
- Rust-based CLI interface
- Debian packaging support
- Basic system hardening capabilities
