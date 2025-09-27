# HARDN Monitoring System

## Overview

HARDN features a comprehensive monitoring system that provides real-time security monitoring, service management, and threat detection capabilities. The system integrates multiple monitoring components into a unified, interactive interface.

## Core Components

### LEGION Security Monitoring Daemon

The LEGION daemon (`legion-daemon.service`) provides continuous security monitoring with the following capabilities:

- **Syslog Monitoring**: Real-time analysis of system logs for security events
- **Journal Monitoring**: systemd journal monitoring for service and system events
- **Network Monitoring**: Network traffic analysis and anomaly detection
- **Threat Intelligence**: Integration with threat intelligence feeds and IOC (Indicators of Compromise) processing
- **Active Monitoring**: Continuous background monitoring with automated response capabilities

### Service Monitoring

HARDN monitors and manages multiple systemd services:

- `hardn.service` - Main HARDN security service
- `hardn-api.service` - REST API service for external integrations
- `legion-daemon.service` - LEGION security monitoring daemon
- `hardn-monitor.service` - Monitoring coordination service

### Interactive Service Manager

The `hardn-service-manager.sh` script provides a comprehensive menu-driven interface for:

- **Service Status Monitoring**: Real-time display of service states with color-coded indicators
- **Service Management**: Start, stop, restart, enable, and disable services
- **Log Viewing**: Interactive log monitoring for individual services or all services simultaneously
- **Module Execution**: Run security hardening modules and tools
- **LEGION Control**: Manage LEGION monitoring operations and view security reports

## Monitoring Feeds

### Log Data Sources

The monitoring system aggregates log data from multiple sources:

1. **LEGION Daemon Logs**: Security events, threat detections, and monitoring alerts
2. **HARDN Service Logs**: Core service operations and hardening activities
3. **HARDN API Logs**: API requests, responses, and integration activities
4. **System Journal**: systemd service logs and system-level events

### IOC and Error Monitoring

- **Indicators of Compromise (IOC)**: Automated detection and processing of known threat indicators
- **Error Monitoring**: Comprehensive error tracking across all HARDN components
- **Update Monitoring**: Tracking of security updates and system changes
- **Collective Feed Source**: Unified log aggregation for centralized monitoring

## Usage

### Launching the Monitoring Interface

```bash
# Primary method - launches the interactive service manager
sudo make hardn

# Alternative - direct service monitoring
sudo hardn services

# View help and navigation
hardn --help
```

### Navigation

The interactive interface provides:

- **Menu Navigation**: Use numbers or arrow keys to select options
- **Log Viewing**: Press Ctrl+C to return to menus (doesn't exit the application)
- **Quick Exit**: Press 'q' to quit from any menu
- **Real-time Updates**: Live service status and log monitoring

### Monitoring Commands

```bash
# Check service status
sudo hardn --status

# View service logs
sudo journalctl -u hardn.service -f

# Generate security report
sudo hardn --security-report

# Run LEGION monitoring
sudo hardn legion
```

## Architecture

### Monitoring Flow

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   LEGION Daemon │───▶│  Service Manager │───▶│  Interactive UI │
│                 │    │                  │    │                 │
│ • Syslog        │    │ • Status Display │    │ • Menu System   │
│ • Journal       │    │ • Log Aggregation│    │ • Real-time     │
│ • Network       │    │ • Service Control│    │   Monitoring    │
│ • Threat Intel  │    │                  │    │                 │
└─────────────────┘    └──────────────────┘    └─────────────────┘
```

### Integration Points

- **Systemd Services**: All monitoring components run as systemd services
- **Journal Integration**: Uses systemd journal for log aggregation
- **Signal Handling**: Graceful Ctrl+C handling for navigation
- **Async Operations**: Tokio-based concurrent monitoring operations

## Security Features

- **Continuous Monitoring**: 24/7 background security monitoring
- **Threat Detection**: Automated threat intelligence processing
- **Anomaly Detection**: Network and system behavior analysis
- **Incident Response**: Automated response capabilities
- **Audit Logging**: Comprehensive security event logging

## Troubleshooting

### Common Issues

- **Service Not Starting**: Check `sudo hardn --status` and journal logs
- **Permission Errors**: Ensure running with sudo privileges
- **Log Access Issues**: Verify systemd journal permissions
- **Network Monitoring**: Check network interface permissions

### Log Locations

- Service logs: `journalctl -u <service-name>`
- LEGION logs: `journalctl -u legion-daemon`
- System logs: `/var/log/hardn/`
- Configuration: `/etc/hardn/`

## Future Enhancements

- **Web Interface**: Browser-based monitoring dashboard
- **Advanced Analytics**: Machine learning-based threat detection
- **Plugin System**: Extensible monitoring modules
- **Cloud Integration**: Remote monitoring and alerting