![HARDN Logo](docs/assets/IMG_1233.jpeg)
# HARDN
**Linux Security Hardening and Extended Detection Response**

> [![ci](https://github.com/Security-International-Group/HARDN/actions/workflows/ci.yml/badge.svg)](https://github.com/Security-International-Group/HARDN/actions/workflows/ci.yml)
> [![SAST](https://github.com/Security-International-Group/HARDN/actions/workflows/codeql.yml/badge.svg)](https://github.com/Security-International-Group/HARDN/actions/workflows/codeql.yml)

HARDN is a comprehensive security hardening system for Debian-based Linux systems, providing automated security hardening and continuous monitoring through an integrated toolkit.

**Demo Version** - This is a demonstration version showcasing core security features of HARDN-XDR, the full enterprise solution. For production use and advanced features, please contact Security International Group.
## Key Features

- **Automated System Hardening** - One-command security configuration
- **Continuous Security Monitoring** - Real-time threat detection via LEGION daemon
- **Security Scanner Integration** - Built-in Lynis, AIDE, and custom security tools
- **Network Protection** - Fail2ban integration with advanced network monitoring
- **Interactive GUI** - Real-time monitoring dashboard
- **Service Management** - Easy-to-use command-line service manager

## Quick Start

### From Source
```bash
git clone https://github.com/Security-International-Group/HARDN.git
cd HARDN
sudo make build
sudo make hardn
```
- This launches the service manager automatically and builds the Debian package. 
- To move forward, use the service manager choices to launch the hardening script or other options as needed. 

### HARDN Usage

- Upon using the standard `sudo make hardn` the Security Information and Event Management (SIEM) graphic interface will launch automatically alongside the service manager. 
- This application provides real-time monitoring of a system's security status and places a local GTK4 Native app within the user's 
desktop environment.

**SIEM**
- When you have deployed `hardn` as the native app, and close it, when you click to reopen it all services will be "down" until you choose option (11) start hardn SIEM - and that will restart all services and logging. 

**Service Manager**

- This service manager allows users to manage HARDN services interactively, through both a command line interface (CLI) and the SIEM.
```bash
sudo hardn-service-manager
```

- Users can choose to launch HARDN module scripts or run security tools indivually. 
- A security report can be launced based on a built in HARDN Compliance meter; built in accordance to CIS standards (Center for Internet Security). 
- The Service Manager is there to monitor, launch and get the needed system data an administrator needs in times of monitoring and response. 

## What HARDN Does

### Security Hardening
Applies comprehensive security configurations to a system with a single command.

### Real-Time Monitoring
Continuous security monitoring through the LEGION daemon, tracking system changes and potential threats.

### Integrated GUI
Real-time monitoring dashboard showing system status, security events, and service health.

## Services

HARDN installs two main services:

### **hardn.service**
Security hardening service that applies security configurations when triggered.

### **legion-daemon.service**
![LEGION](docs/assets/legion.jpeg)
Continuous security monitoring daemon that watches for threats and system changes.

![Enemy Detection](docs/assets/enemy.jpeg)

## Basic Troubleshooting

### Check Service Status
```bash
sudo systemctl status hardn.service
sudo systemctl status legion-daemon.service
```

### View Logs
```bash
sudo journalctl -u hardn.service
sudo journalctl -u legion-daemon.service
```

## Documentation

For detailed technical information, see:
- [HARDN Service Documentation](docs/hardn.md)
- [LEGION Daemon Documentation](docs/legion-daemon.md)
- [HARDN API Documentation](docs/hardn-api.md)
- [Service Manager Guide](docs/hardn-service-manager.md)

## Support

Some modules may fail in restricted environments (containers, read-only filesystems). This is expected behavior - the service will continue running while logging any issues.

## Note

This is a demonstration version with core security features. For enterprise security requirements, please contact Security International Group for the full HARDN solution.

## License

MIT License - See LICENSE file for details


# Metrics

![GitHub Metrics](.github/metrics.svg)


