# Changelog

All notable changes to **HARDN** are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

The unreleased work landed as six stacked PRs (A, B, D, C, E, F) on the
`patch` branch through May 2026. They are grouped here by area rather than
by PR.

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
