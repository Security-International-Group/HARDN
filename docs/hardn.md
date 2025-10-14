# HARDN - Linux Security Hardening & Extended Detection Toolkit

## Overview

HARDN is a comprehensive, open-source security hardening and threat detection system designed specifically for Debian-based Linux distributions. It provides automated security configuration, continuous monitoring, and real-time threat response capabilities to protect systems against modern cyber threats.

## What HARDN Is

HARDN is a complete security framework that includes:

### Core Security Components
- **Automated Hardening**: STIG-compliant security configuration and hardening scripts
- **Threat Detection**: Advanced anomaly detection and threat intelligence integration
- **Service Management**: Comprehensive systemd service orchestration and monitoring
- **API Integration**: RESTful API for remote monitoring and management
- **Interactive Interface**: User-friendly service manager with real-time monitoring

### Security Monitoring Features
- **LEGION Daemon**: Continuous security monitoring with syslog, journal, and network analysis
- **IOC Processing**: Indicators of Compromise detection and automated response
- **Service Health Monitoring**: Real-time status monitoring of all security services
- **Log Aggregation**: Centralized logging and alerting across all components

### Management Tools
- **Interactive Service Manager**: Menu-driven interface for complete system control
- **Command-Line Interface**: Full CLI for automation and scripting
- **REST API**: Programmatic access for integration with other security tools
- **Package Management**: Automated installation and configuration

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    HARDN Security Framework                 │
├─────────────────────────────────────────────────────────────┤
│   ┌─────────────┐  ┌─────────────┐  ┌─────────────┐         │
│   │ Service     │  │ LEGION      │  │ REST API    │         │
│   │ Manager     │  │ Daemon      │  │ Service     │         │
│   │ (Interactive│  │ (Monitoring)│  │ (Remote     │         │
│   │ Interface)  │  │             │  │ Access)     │         │
│   └─────────────┘  └─────────────┘  └─────────────┘         │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐          │
│  │ Hardening   │  │ Threat      │  │ System      │          │
│  │ Scripts     │  │ Intelligence│  │ Monitoring  │          │
│  │             │  │             │  │             │          │
│  └─────────────┘  └─────────────┘  └─────────────┘          │
├─────────────────────────────────────────────────────────────┤
│                 Debian Linux System                         │
└─────────────────────────────────────────────────────────────┘
```

## Key Features

### Security Hardening
- **STIG Compliance**: Automated implementation of Security Technical Implementation Guides
- **CIS Benchmarks**: Center for Internet Security benchmark compliance
- **Package Hardening**: Secure configuration of installed packages
- **Network Security**: Firewall configuration and network hardening

### Threat Detection & Response
- **Real-time Monitoring**: Continuous system and network monitoring
- **Anomaly Detection**: Machine learning-based behavioral analysis
- **IOC Integration**: Automated processing of threat intelligence feeds
- **Incident Response**: Automated response to detected threats

### Service Management
- **Systemd Integration**: Complete service lifecycle management
- **Dependency Management**: Automatic handling of service dependencies
- **Health Monitoring**: Continuous service health checks
- **Failover Support**: Automatic service restart and recovery

### User Interface
- **Interactive Console**: Menu-driven interface for system administration
- **Web Dashboard**: Browser-based monitoring and management (planned)
- **API Access**: RESTful API for programmatic control
- **CLI Tools**: Command-line utilities for automation

## Quick Start

### Installation & Setup

```bash
# Clone the repository
git clone https://github.com/Security-International-Group/HARDN.git
cd HARDN

# Build and install
sudo make build
sudo make hardn

# Launch the interactive service manager
sudo make hardn
```

### Basic Usage

```bash
# Check system status
sudo hardn --status

# Run security assessment
sudo hardn --security-report

# View help
hardn --help
```

## Components

### HARDN Service Manager
The primary interface for managing all HARDN components. Provides:
- Interactive menus for service control
- Real-time monitoring dashboards
- Log viewing and analysis
- Configuration management

### LEGION Security Daemon
Continuous monitoring daemon that provides:
- System log analysis
- Network traffic monitoring
- Threat intelligence processing
- Automated incident response

### HARDN API Service
RESTful API for remote management and monitoring:
- System health metrics
- Service status monitoring
- Remote command execution
- Integration with external tools

### Hardening Modules
Automated security configuration modules:
- System hardening scripts
- Package security configuration
- Network security setup
- Compliance automation

## Security Benefits

### Proactive Protection
- **Continuous Monitoring**: 24/7 system surveillance
- **Threat Intelligence**: Integration with global threat feeds
- **Automated Response**: Immediate action on detected threats
- **Compliance Automation**: Maintain security standards automatically

### Operational Security
- **Access Control**: SSH key-based authentication
- **Audit Logging**: Comprehensive security event logging
- **Integrity Monitoring**: File and system integrity checks
- **Network Security**: Advanced firewall and intrusion detection

### Incident Response
- **Real-time Alerts**: Immediate notification of security events
- **Automated Mitigation**: Self-healing security responses
- **Forensic Analysis**: Detailed incident investigation tools
- **Recovery Automation**: Streamlined system recovery procedures

## Community & Support

### Who We Are
HARDN is developed by the **Security International Group (SIG)**, a community-driven organization focused on advancing cybersecurity through open-source solutions.

### Getting Help
- **Documentation**: Comprehensive guides and API references
- **Community Support**: Active community forums and discussion groups
- **Issue Tracking**: GitHub issues for bug reports and feature requests
- **Contributing**: Open contribution guidelines for community involvement

### Resources
- [HARDN Service Manager Documentation](hardn-service-manager.md)
- [LEGION Daemon Documentation](legion-daemon.md)
- [HARDN API Documentation](hardn-api.md)
- [HARDN Monitor Documentation](hardn-monitor.md)

## License & Contributing

HARDN is released under the MIT License, encouraging community contributions and commercial use. We welcome contributions from security researchers, developers, and system administrators to help improve and expand the platform.

## Roadmap

### Current Version
- Interactive service manager
- LEGION security daemon
- REST API service
- Automated hardening scripts
- Real-time monitoring

### Upcoming Features
- Web-based dashboard
- Advanced threat intelligence
- Machine learning integration
- Multi-system orchestration
- Cloud integration

---

**Website**: [Security International Group](https://securityinternationalgroup.org)
**Repository**: [GitHub](https://github.com/Security-International-Group/HARDN)
**Documentation**: [Full Documentation](https://docs.hardn.security)
