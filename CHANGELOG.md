# Changelog

All notable changes to **HARDN** are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Hardware & cloud compatibility

- New environment-detection helper `tools/env-detect.sh` populating
  `HARDN_ENV_VIRT`, `HARDN_ENV_CLOUD`, and `hardn_in_{container,vm,cloud,baremetal}`
  predicates, sourced from `functions.sh` and `hardening.sh`
- A one-line "Detected environment" banner is now printed at the start of
  every hardening run so operators see what HARDN will skip
- SSH hardening no longer disables `PasswordAuthentication` when the host
  has no public keys and is running in a cloud VM — prevents permanent
  remote lockout. Override with `HARDN_FORCE_DISABLE_PASSWORD_AUTH=1`;
  force-keep with `HARDN_KEEP_PASSWORD_AUTH=1`
- Cloud instance metadata endpoint (169.254.169.254, plus 168.63.129.16
  on Azure) is now explicitly allowlisted in UFW and the iptables
  HARDN-LOCKDOWN chain when a cloud environment is detected
- Fail2Ban jail now honours `HARDN_SSH_PORT` (previously hardcoded to 22)
  and pre-populates `ignoreip` with cloud load-balancer health-check
  ranges (GCP today; operators can add their own via `HARDN_CLOUD_LB_CIDRS`)
- Auditd now ships a disk-safety policy (`disk_full_action=SYSLOG`,
  `space_left_action=SYSLOG`, `admin_space_left_action=SUSPEND`) and
  sizes its audit buffer based on free space on `/var/log` — small cloud
  root volumes can no longer be filled into a kernel panic
- Auditd setup exits cleanly inside containers instead of spamming
  "Operation not permitted" against the host audit subsystem
- FireWire blacklist + `modprobe -r firewire-core` + initramfs rebuild
  skipped in containers
- Sysctl writes that fail inside an unprivileged container are now
  logged as INFO ("host owns this parameter") rather than WARNING

### Logs & UX

- HARDN_STATUS no longer writes ANSI colour escapes to log files when
  stdout is not a TTY — the GUI's log tail now reads clean text
- `hardn --help` lists the `--enable-selinux` flag, which was previously
  only documented in the setup binary

## [1.1.0-1] - 2026-05-24

### Audit framework — 100% coverage (194/194 rules)

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
- Audit checks for `passwd`, `shadow` and cron file owner, group and mode
- 2 kernel-module-disabled audit checks (`cramfs`, `usb-storage`)

### LEGION and alerting

- LEGION emits alerts to the shared alert channel on high/critical risk
- Structured alert channel from `hardn-monitor` to `hardn-gui`
- Unified LEGION baseline DB path via `Config::database_path()`

### hardn-gui

- Tails all HARDN log files and follows correctly from the left pane
- Cleaned security report warning output
- Inline CSS path validation; removed deleted `path_security` dependency
- Fixed GTK app output error (ISSUE_135)

### Packaging and installation

- Full uninstall script with boot-safety fixes for `hardn-api`,
  `hardn.service` and `legion-daemon.service`
- Hardened tool-launch safety — renamed `selinux.sh` to
  `selinux.sh.DANGEROUS`, filter helper libraries, fix install logic
- Ignored `dpkg-buildpackage` `hardn.debhelper.log` artifact
- Fixed dpkg failure for monitor output
- Fixed version mismatch in `hardn-monitor` (ISSUE_134)
- Fixed staircasing output issue

### CI and release

- Richer Discord release notification — embeds the new tag, a short
  changelog of commits since the previous release, and a working URL
  to the actual release page
- Added `.github/CODEOWNERS` with `@OpenSource-For-Freedom` as global owner
- Run `ci.yml` on pull requests to `main`; gate the release job to
  `main` pushes
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
