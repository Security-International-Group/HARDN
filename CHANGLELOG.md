# HARDN Demo CHANGELOG

All notable changes to this project will be documented in this file.

- SOURCE: [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0/).

![hardn](docs/assets/IMG_1233.jpeg)

## [Unreleased]

### Added
- Back-to-previous navigation entries on every `hardn-service-manager.sh` submenu so operators can exit nested views without relying on Ctrl+C.

### Changed
- Relaxed inter-service `Wants=` dependencies in HARDN systemd units, allowing individual services to start or stop without implicitly launching the rest of the stack.
- Refined Dependabot configuration to consolidate Python and Rust dependency updates into single PRs while authenticating against the private registry.
- Declared workflow-level permissions for the CodeQL pipeline to follow GitHub's least-privilege guidance.

### Fixed
- Hardened `hardn-service-manager.sh` status and log viewers to handle inactive services gracefully, preventing crashes and showing friendlier feedback when no data is available.

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