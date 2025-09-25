![hardn](docs/IMG_1233.jpeg)
# HARDN

Linux Security Hardening and Extended Detection & Response Toolkit

HARDN is a comprehensive security hardening system for Debian-based Linux systems, providing both automated hardening capabilities and continuous security monitoring.
> [![ci](https://github.com/Security-International-Group/HARDN/actions/workflows/ci.yml/badge.svg)](https://github.com/Security-International-Group/HARDN/actions/workflows/ci.yml)
## Features

- Security Scanners: Lynis, AIDE, Legion integration
- Network Security: Fail2ban, Suricata support
- System Hardening: Basic security configurations
- Continuous Monitoring: LEGION security monitoring daemon
- Modular Architecture: Extensible tool and module system
- Service Integration: Systemd service management

## Installation

```bash
# 1. Clone the repository
git clone https://github.com/Security-International-Group/HARDN.git
cd HARDN

# 2. Install dependencies and build the package
make build

# 3. Build and install the package (includes running all modules)
make hardn

# 4. Verify installation
hardn --help
```

## Quick Start

After installation, HARDN provides two main services:

### Continuous Monitoring with LEGION

LEGION provides advanced, continuous security monitoring. You can manage and interact with the LEGION daemon using the following commands:

```bash
# Check status of the LEGION daemon
sudo systemctl status legion-daemon.service

# Start the LEGION daemon
sudo systemctl start legion-daemon.service

# Stop the LEGION daemon
sudo systemctl stop legion-daemon.service

# Restart the LEGION daemon
sudo systemctl restart legion-daemon.service

# View logs for the LEGION daemon
sudo journalctl -u legion-daemon.service

# Run LEGION once for a security assessment
sudo hardn legion

# Run LEGION as a daemon with verbose output
sudo hardn legion --daemon --verbose

# Show LEGION command options
sudo hardn legion --help
```

### On-Demand Hardening with HARDN - service
```bash
# Run all security modules
sudo hardn --run-all-modules

# Or use the service
sudo systemctl start hardn.service
```

## Command Reference and Education

- See docs explaining both hardn.service and legion.daemon
- [HARDN Docs](docs/hardn.md)

### Main Commands

```bash
# Show help and available commands
sudo hardn -h

# Show system status
sudo hardn status

# List available modules and tools
sudo hardn --list-modules
sudo hardn --list-tools
```

### Module and Tool Execution

```bash
# Run all modules
sudo hardn --run-all-modules

# Run all tools
sudo hardn --run-all-tools

# Run everything (modules and tools)
sudo hardn --run-everything

# Run specific module or tool
sudo hardn run-module <name>
sudo hardn run-tool <name>
```

### Service Management

```bash
# Service status
sudo hardn --service-status

# Quick service commands
sudo hardn --service-enable
sudo hardn --service-start

# Manual service management
sudo systemctl status hardn.service
sudo systemctl status legion-daemon.service
```

### Security Reports

```bash
# Generate comprehensive security report
sudo hardn --security-report
```

### Sandbox Mode

```bash
# Enable sandbox mode (disconnects network, closes ports)
sudo hardn --sandbox-on

# Disable sandbox mode
sudo hardn --sandbox-off
```

## Services

HARDN installs two systemd services:

### hardn.service
- Type: Oneshot
- Purpose: Runs security hardening modules on demand
- Status: Enabled, runs when triggered
- Manual start: `sudo systemctl start hardn.service`

### legion-daemon.service
- Type: Simple (daemon)
- Purpose: Continuous security monitoring
- Status: Active, runs continuously
- Monitors: SSH, packages, binaries, filesystem, processes, network

## Architecture

### Modules
Security hardening scripts located in `/usr/share/hardn/modules/`
- Executed with root privileges
- Can modify system configuration
- Examples: hardening.sh (basic security settings)

### Tools
Security scanning and utility tools in `/usr/share/hardn/tools/`
- Security scanners (Lynis, AIDE)
- Network security tools (Fail2ban, Suricata)
- Utility functions

### LEGION
Advanced security monitoring system:
- Continuous anomaly detection
- Filesystem integrity monitoring
- Process analysis
- Network security assessment
- Configurable monitoring intervals

## Configuration

### Environment Variables
```bash
# Custom search paths
export HARDN_MODULE_PATH="/custom/path:/another/path"
export HARDN_TOOL_PATH="/custom/tools:/more/tools"
```

### Default Paths
- Modules: `/usr/share/hardn/modules/`
- Tools: `/usr/share/hardn/tools/`
- Config: `/etc/hardn/`
- Logs: `/var/log/hardn/`
- Data: `/var/lib/hardn/`

## Development

```bash
# Build from source
cargo build --release

# Run tests
cargo test

# Build Debian package
make build

# Install locally
make install-deb
```

## Troubleshooting

### Service Issues
```bash
# Check service status
sudo systemctl status hardn.service
sudo systemctl status legion-daemon.service

# View service logs
sudo journalctl -u hardn.service
sudo journalctl -u legion-daemon.service

# Restart services
sudo systemctl restart hardn.service
sudo systemctl restart legion-daemon.service
```

### Module/Environment Issues
Some modules may fail in restricted environments (containers, read-only filesystems). This is expected behavior - the service will still complete successfully while logging module failures.

## Note

This is a demonstration version with core security features. For enterprise security requirements, please contact Security International Group for the full HARDN solution.

## License

MIT License - See LICENSE file for details
