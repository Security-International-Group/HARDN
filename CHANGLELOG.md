# HARDN Demo CHANGELOG

All notable changes to this project will be documented in this file.

- SOURCE: [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0/).

![hardn](docs/assets/IMG_1233.jpeg)

## [Unreleased]

### Security
- **Closed SSH port 22 — remote access now exclusively via Grafana (9002) and HARDN API (8000)**
  - `ufw.sh` no longer opens port 22; all inbound SSH is blocked by default-deny policy
  - Only `ufw allow in 9002/tcp` (Grafana) and `ufw allow in 8000/tcp` (HARDN API) are opened
- **HARDN API: SSH public key auth is now actually enforced**
  - `hardn-api.py`: `verify_ssh_key()` previously accepted any syntactically valid SSH key; now validates submitted key against `/etc/hardn/authorized_keys` using `secrets.compare_digest()` to prevent timing attacks
  - Format-valid but unregistered keys now return HTTP 401
  - Missing or unreadable keys file returns HTTP 503 with a clear error
- **HARDN API: CORS wildcard removed**
  - Replaced `allow_origins=["*"]` (spec-invalid with `allow_credentials=True`) with an explicit origin list defaulting to Grafana (`http://localhost:9002,http://127.0.0.1:9002`); overridable via `HARDN_API_CORS_ORIGINS` env var
  - `allow_methods` and `allow_headers` scoped to minimum required
- **HARDN API now binds to `0.0.0.0` for external access**
  - Previously bound to `127.0.0.1` (loopback-only), making remote API access impossible
  - Host/port now driven by `HARDN_API_HOST` / `HARDN_API_PORT` env vars set in `hardn-api.service`

### Removed
- **Lynis purged from entire codebase**
  - `lynis.sh` tool deleted
  - Removed lynis cron job (`lynis-audit` weekly job) from `src/core/cron.rs`
  - Removed `"Lynis"` tool status match arm from `src/main.rs`
  - Removed lynis `SecurityToolInfo` entry from `src/main.rs` and `src/setup/main.rs`
  - Removed `lynis` from `DEFAULT_TOOL_COMMANDS` array and `format_tool_display()` case in `hardn-service-manager.sh`
  - Removed LYNIS VALIDATION block from `usr/share/hardn/modules/hardening.sh`
  - Removed lynis references from `README.md`, `debian/changelog`, `docs/hardn-service-manager.md`, `docs/hardn-service.md`, and `TOOL_ASSESSMENT.md`
  - Renamed internal `hardn-lynis-comprehensive.sh` script references to `hardn-comprehensive.sh`

### Fixed — `aide.sh`
- Added `set -euo pipefail`
- Fixed `local aide_pid=$!` used at global scope — `local` outside a function returns exit code 1, which would abort the script under `set -e`; changed to plain `aide_pid=$!`
- Replaced `wait $pid; if [ $? -eq 0 ]` antipattern with `if wait $aide_pid`

### Fixed — `auditd.sh`
- **Critical logic bug**: `-D` (flush all rules) was placed mid-file, after the MITRE ATT&CK rules — this silently deleted all MITRE rules every time the ruleset was loaded. Moved `-D`, `-b 8192`, and `-f 1` to the top of the rules heredoc, before any rule definitions
- Fixed syntax error: `-w /etc/cron.monthly/-p war` was missing the required space before `-p`; corrected to `-w /etc/cron.monthly/ -p war`

### Fixed — `grafana.sh`
- Added `set -euo pipefail`
- Added missing `log_tool_execution "grafana.sh"` call (was the only tool not logging execution)
- Fixed `HARDN_STATUS "fail"` — `"fail"` is not a valid level in `functions.sh` (valid: info, pass, warning, error); changed to `"error"`
- Added UFW rule `ufw allow in 9002/tcp` when UFW is active, with graceful fallback if not

### Fixed — `suricata.sh`
- Replaced `cd` with `pushd`/`popd` throughout the source-build path so directory changes are always unwound, including on error exit paths
- Added SHA256 integrity check for downloaded source tarball; aborts and removes the file on mismatch
- Replaced `pip3 install --upgrade pip && pip3 install suricata-update` with `install_package suricata-update` — pip3 install on Debian 12+ (PEP 668) breaks the externally-managed Python environment
- Moved `enable_service suricata` to after `suricata -T` config validation; service no longer starts in a known-broken state
- Added `ACTION REQUIRED` operator warnings to set `af-packet.interface` in `suricata.yaml` before the service will capture traffic
- `create_fallback_suricata_rules()` now emits a warning that fallback rules contain no threat detection signatures (event-protocol includes only)
- Added pre-start check warning when only include-based rules are present and no detection rules have been loaded

### Fixed — `ufw.sh`
- Removed redundant `ufw --force disable` before `ufw --force reset` — reset already disables, the extra call widened the unprotected window
- Added pre-reset rule backup to `/var/log/hardn/ufw-pre-reset-<timestamp>.txt`
- SSH rate-limit rule removed; port 22 is now blocked by default-deny incoming
- Added `ufw allow in 9002/tcp` (Grafana) and `ufw allow in 8000/tcp` (HARDN API)
- SSH port now reads `${SSH_PORT:-22}` env var (variable retained for reference, no longer opened)
- Added comment warning about the brief unprotected window during `--force reset` for remote/server operators

### Fixed — `selinux.sh` *(previous session)*
- Added `#!/bin/bash` shebang and `set -euo pipefail`
- Fixed non-portable `source` path; now uses `$(cd "$(dirname "$0")" && pwd)/functions.sh`
- Fixed all `HARDN_STATUS` calls to two-argument form (`level` + `message`)
- Replaced unconditional `reboot` with operator warning plus optional `--auto-reboot` flag (10-second countdown)
- Added error checking on `apt-get install` and `selinux-activate`

### Changed — `hardn-api.service`
- Added `HARDN_API_HOST=0.0.0.0`, `HARDN_API_PORT=8000`, and `HARDN_AUTHORIZED_KEYS=/etc/hardn/authorized_keys` environment variables

### Changed — `hardn-api.py`
- Startup banner updated: removed hardcoded `'hardn-api-key-2024'` hint, added authorized keys path and remote access policy notice
- `import secrets` added for timing-safe key comparison

### Changed — Documentation
- `README.md`: Added `Zero SSH Exposure` feature bullet; new **Remote Access** section documenting the two allowed channels with key registration steps and curl examples
- `docs/hardn-api.md`: Added SSH-closed callout at top; new **Setup** section for key registration as first step; rewrote Authentication section with Ed25519-preferred workflow; all examples updated to use `your-server:8000`
- `docs/hardn-service.md`: Architecture diagram updated — entry-point node now shows API (port 8000) and Grafana (port 9002) as the two remote access paths; API table row updated to note port 22 is closed

 — compiler warnings eliminated, no `#[allow(dead_code)]` suppressions remaining in target files
  - `src/core/error.rs`: Removed unused `HardnError` variants `ModuleNotFound`, `ToolNotFound`, and `InvalidArgument` along with their `Display` match arms
  - `src/core/types.rs`: Removed unused fields `ServiceStatus::name`, `ServiceStatus::description`, and `SecurityToolInfo::process_name`; updated all construction sites in `src/main.rs` accordingly
  - `src/core/cron.rs`: Removed unused `CronOrchestrator::with_poll_interval` method
- **Toolchain update**: Upgraded WSL Rust toolchain to stable 1.93.1 (was 1.75.0) to resolve Cargo lock file v4 compatibility error; build now completes cleanly

### Security
- **Fixed 4 High-severity path traversal vulnerabilities (CWE-22)** detected by CodeQL analysis
  - Added new `utils/path_security.rs` module with `sanitize_path()`, `validate_env_path()`, and `safe_read_env_file()` functions
  - Fixed uncontrolled CSS file path in `hardn-gui.rs` from `HARDN_GUI_CSS` environment variable - now validates against whitelist of allowed directories
  - Fixed uncontrolled binary path from `HARDN_AUDIT_BIN` environment variable in path discovery
  - All environment variable paths are now validated against strict whitelists and canonicalized to prevent directory traversal attacks
  - Implemented defense-in-depth with multiple validation layers following principle of least privilege

### Added
- Refactored gui to be scalable to UI environment. 
- Declared API runtime dependencies (python3-fastapi, python3-uvicorn) in packaging and native install paths to ensure services start on fresh installs.

### Changed
- Relaxed inter-service `Wants=` dependencies in HARDN systemd units, allowing individual services to start or stop without implicitly launching the rest of the stack.
- Refined Dependabot configuration to consolidate Python and Rust dependency updates into single PRs while authenticating against the private registry.
- Declared workflow-level permissions for the CodeQL pipeline to follow GitHub's least-privilege guidance.

### Fixed
- Hardened `hardn-service-manager.sh` status and log viewers to handle inactive services gracefully, preventing crashes and showing friendlier feedback when no data is available.
- Resolved API unit start failures by installing missing FastAPI/Uvicorn dependencies via deb packaging and Makefile installs.

### What's Changed v1.0.0

#### Service Manager Integration & Interactive Interface
- New menu lets you manage every HARDN service from one screen.
- Pressing Ctrl+C drops you back to the menu instead of killing the app.
- Live status panel shows which services are running, enabled, or down using clear colors.
- Added quick log viewers for single services or the whole stack.
- `hardn-service-manager.sh` is now the main launch point.

#### LEGION Security Monitoring System DEMO
- LEGION now watches syslog, the journal, and network events in real time.
- Basic threat-correlation and anomaly spotting are wired in.
- IOC messaging hooks are in place for future feeds.
- Security alerts now include detailed log context.
- CPU and memory stats report real usage instead of placeholder numbers.
- Risk reports now call out the exact problems they found.
- Extra checks look for auth failures, risky SUID/SGID files, kernel gaps, and container issues.

#### User Experience Improvements
- `hardn -h` now shows a plain-language help screen.
- Menus explain how to move around and how to quit.
- `sudo make hardn` is highlighted as the fastest way to launch the toolkit.
- Help text includes quick fixes for common errors.
- Examples now use package-friendly commands instead of raw file paths.
- Updated GUI display to include the HARDN logo

#### Technical Enhancements
- Code is split into clearer modules (services, legion, display, and more).
- Async tasks are tuned for smoother concurrent monitoring.
- ctrlc crate handles signals cleanly across the app.
- Makefile still handles privileged operations safely.

### What's New

- Full menu-driven service manager.
- LEGION daemon (demo) with live security monitoring.
- Friendlier help and troubleshooting flow.
- One-command launch flow via `make hardn`.
- `grafana.sh` launches a grafana protection data manager. 

### Security

- Continuous monitoring broadens the security coverage.
- Added hooks for threat intel and IOC handling.
- Privileged actions still follow least-privilege rules.

### Upcoming Features

- Finish IOC data exchange end to end.
- Expand analytics for deeper threat correlation.
- Explore a web dashboard and richer GTK app.
- Open the door for plug-in security modules.

