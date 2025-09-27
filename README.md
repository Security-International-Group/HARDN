![hard](docs/IMG_1233.jpeg)

# HARDN
Linux Security Hardening and Extended Detection Response

HARDN is a comprehensive security hardening system for Debian-based Linux systems, providing both automated hardening capabilities and continuous security monitoring.
> [![ci](https://github.com/Security-International-Group/HARDN/actions/workflows/ci.yml/badge.svg)](https://github.com/Security-International-Group/HARDN/actions/workflows/ci.yml)
> [![SAST](https://github.com/Security-International-Group/HARDN/actions/workflows/codeql.yml/badge.svg)](https://github.com/Security-International-Group/HARDN/actions/workflows/codeql.yml)
## Features
- HARDN builds a rust core and binary. 
- Security Scanners: Lynis, AIDE, Legion integration
- Network Security: Fail2ban, Suricata support
- System Hardening: Basic security configurations
- Continuous Monitoring: LEGION security monitoring daemon
- Modular Architecture: Extensible tool and module system
- Service Integration: Systemd service management
- Interactive Management: User-friendly service manager interface

## Installation

### 1. Build
```
git clone https://github.com/Security-International-Group/HARDN.git
cd HARDN
sudo make build
sudo make hardn
hardn -h 
```
### 2. Verify 
```
hardn --version
```
- After installation, HARDN provides two main services, see below. 

### 3. Interactive Service Management
HARDN includes an interactive service manager for easy system management:
```
sudo hardn-service-manager
```
This provides a menu-driven interface for managing services, running modules/tools, and monitoring system security.

### Continuous Monitoring with LEGION and HARDN Services

#### References
- [LEGION](docs/legion-daemon.md)
- [HARDN](docs/hardn.md)
- [HARDN API](docs.hardn-api.md)
- [HARDN Service Manager](docs/hardn-service-manager.md)

## Services

HARDN installs two systemd services:

### hardn.service
- Type: Oneshot
- Purpose: Runs security hardening modules on demand
- Status: Enabled, runs when triggered
- Manual start: `sudo systemctl start hardn.service`

### legion-daemon.service
![legion](docs/legion.jpeg)
- Type: Monitoring (daemon)
- Purpose: Continuous security monitoring
- Status: Active, runs continuously
- Monitors: Kernel, Memory, cron, packages, binaries, filesystem, processes, network, IDS
![enemy](docs/enemy.jpeg)

## monitoring

### HARDN REST-API
- The backend REST api is there for remote monitoring by host protocol. 
- Purpose: Remote endpoint monitoring
- Status: Active and running upon launch
- Manual Start, see documentation. 
- The strict purpose would be to see the hardn-service, legion daemon alerting and localy hosts protocols. 
- This does require a sha256 hash key, public an dpriate to enteract with the backend tool. See doecumentaion referenced above for more information. 


## Architecture

### Modules
Security hardening scripts located in `/usr/share/hardn/modules/`
- Executed with root privileges
- Can modify system configuration
- Examples: hardening.sh (basic security settings)

### Tools
Security scanning and utility tools in `/usr/share/hardn/tools/`
- Security scanners (Lynis, AIDE, LEGION)
- Network security tools (Fail2ban, Suricata)
- Utility functions

## Configuration

### Default Paths
- Modules: `/usr/share/hardn/modules/`
- Tools: `/usr/share/hardn/tools/`
- Config: `/etc/hardn/`
- Logs: `/var/log/hardn/`
- Data: `/var/lib/hardn/`


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
