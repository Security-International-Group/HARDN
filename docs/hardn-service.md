# HARDN Security Service

## Purpose

HARDN (Hardened Detection and Response Network) is a comprehensive STIG-compliant security hardening and monitoring system for Linux systems. It provides automated security hardening, continuous monitoring, intrusion detection, and incident response capabilities. HARDN integrates multiple security tools and services to create a layered defense approach for endpoint protection.

## Architecture Overview

HARDN consists of two main components:

### 1. HARDN Core Service (`hardn.service`)
- **Type**: One-shot systemd service
- **Purpose**: Automated security hardening and configuration
- **Execution**: Runs hardening modules on system startup or manual trigger
- **Scope**: System-wide security configuration and hardening

### 2. HARDN API (`hardn-api.service`)
- **Type**: REST API server
- **Purpose**: Remote monitoring and management interface
- **Execution**: HTTP server providing overwatch capabilities
- **Scope**: Remote access to system health and security status

## Service Components

### HARDN Core Service

The main HARDN service performs comprehensive system hardening:

**Security Hardening Tasks:**
- SSH root login disablement
- Secure umask configuration for system files
- Critical file permission hardening
- Password quality enforcement (pwquality)
- Antivirus installation (ClamAV)
- Rootkit detection (rkhunter)
- Security auditing (Lynis)
- Intrusion prevention (Fail2Ban)
- System auditing (auditd)
- System logging (rsyslog)
- Automatic updates (unattended-upgrades)
- Firewall configuration (UFW)
- Kernel security parameter tuning

**Service Configuration:**
```ini
[Unit]
Description=HARDN Security Hardening Service
After=network.target
Wants=network.target

[Service]
Type=oneshot
User=root
Group=root
ExecStart=/usr/local/bin/hardn --run-all-modules
RemainAfterExit=no
StandardOutput=journal
StandardError=journal
SyslogIdentifier=hardn
SuccessExitStatus=0 1

# Security settings
NoNewPrivileges=yes
ProtectHome=yes
ProtectSystem=strict
```

## Usage Commands

### Service Management

```bash
# Check overall HARDN status
sudo hardn --status

# Enable HARDN services
sudo hardn --service-enable

# Start HARDN services
sudo hardn --service-start

# Check service status
sudo hardn --service-status
```

### Module Execution

```bash
# Run all available modules
sudo hardn --run-all-modules

# Run specific module
sudo hardn run-module hardening

# List available modules
hardn --list-modules
```

### Tool Execution

```bash
# Run all security tools
sudo hardn --run-all-tools

# Run specific tool
sudo hardn run-tool lynis

# List available tools
hardn --list-tools
```

### System Hardening

```bash
# Run complete hardening suite
sudo hardn --run-everything

# Enable sandbox mode (disconnects network)
sudo hardn --sandbox-on

# Disable sandbox mode
sudo hardn --sandbox-off
```

## Security Tools Integration

HARDN integrates and manages multiple security tools:

### Mandatory Access Control
- **AppArmor**: Application-level access control
- **Status**: Active by default on Ubuntu/Debian systems

### Network Security
- **UFW (Uncomplicated Firewall)**: Host-based firewall
- **Fail2Ban**: Intrusion prevention system
- **Suricata**: Network intrusion detection (when installed)

### System Integrity
- **AIDE**: File integrity monitoring
- **Auditd**: System call auditing
- **Lynis**: Security auditing and hardening

### Malware Protection
- **ClamAV**: Antivirus engine
- **rkhunter**: Rootkit detection

## Command Line Interface

### General Options

```bash
hardn --help              # Show help information
hardn --about             # Show information about HARDN
hardn --version           # Show version information
hardn --security-report   # Generate security score report
```

### Status Commands

```bash
hardn status              # Show current system status
hardn --status            # Same as above
hardn --service-status    # Show service status only
```

### Execution Commands

```bash
# Module operations
hardn --run-all-modules   # Run all hardening modules
hardn run-module <name>   # Run specific module

# Tool operations
hardn --run-all-tools     # Run all security tools
hardn run-tool <name>     # Run specific tool

# Combined operations
hardn --run-everything    # Run modules and tools
```

### Service Management

```bash
hardn service enable      # Enable HARDN services
hardn service start       # Start HARDN services
hardn service stop        # Stop HARDN services
hardn service restart     # Restart HARDN services
hardn service status      # Show service status
```

## System Status Output

### HARDN System Status

```
═══════════════════════════════════════════════════════════════════════════════
                          HARDN SYSTEM STATUS
═════════════════════════════════════════════════════════════════════════════════

SYSTEM INFORMATION:
  OS: Debian 24.04 (noble)
  HARDN Version: 2.2.0
  Timestamp: 1758752537 (Unix epoch)

HARDN SERVICES:
  [DOWN] hardn         [INACTIVE] [enabled]

SECURITY TOOLS STATUS:
  [OK] AppArmor     - Mandatory Access Control system for applications
  [OK] Fail2Ban     [PID: 1578] - Intrusion prevention - Bans IPs with multiple auth failures
  [OK] UFW          - Uncomplicated Firewall - Network traffic filtering
  [OK] Auditd       [PID: 1014] - Linux Audit Framework - Security event logging
  [OK] ClamAV       [PID: 1318] - Antivirus engine for detecting trojans and malware

  Total active security tools: 5/10
```

### Module Execution Output

```
HARDN Security Hardening Module
==================================
[2025-09-24 18:22:25] Starting basic security hardening...
[2025-09-24 18:22:25] Setting secure umask in system files...
[2025-09-24 18:22:27] Setting secure permissions on critical files...
[2025-09-24 18:22:31] Installing ClamAV antivirus...
[2025-09-24 18:22:35] Installing rkhunter...
[2025-09-24 18:22:36] Installing Lynis...
[2025-09-24 18:22:39] Installing Fail2Ban...
[2025-09-24 18:22:41] Installing auditd...
[2025-09-24 18:23:30] Setting up UFW firewall...
[2025-09-24 18:23:38] Configuring kernel security parameters...
[2025-09-24 18:23:38] Basic hardening completed successfully!

 Module 'hardening' completed
   - SSH root login disabled
   - Secure umask configured
   - Critical file permissions set
[PASS] module completed successfully
```

## Integration with HARDN API

The HARDN services provide data to the HARDN API for remote monitoring:

- **Service Status**: `/overwatch/services` endpoint monitors HARDN service health
- **System Health**: `/overwatch/system` includes security tool status
- **Command Execution**: `/hardn/execute` allows remote triggering of HARDN commands

## Security Considerations

### Service Isolation
- HARDN services run with minimal privileges where possible
- API service uses SSH key authentication
- Systemd security hardening applied to all services

### Monitoring and Alerting
- Systemd journaling for comprehensive logging
- Integration with system audit framework
- Automatic security tool health checking

### Compliance and Standards
- STIG-compliant hardening configurations
- CIS benchmark alignment
- NIST security control implementation
- Regular security updates and patches

## Troubleshooting

### Common Issues

**Service won't start:**
```bash
# Check service status
systemctl status hardn.service

# Check logs
journalctl -u hardn.service -n 50
```

**Module execution fails:**
```bash
# Run with verbose output
sudo hardn run-module hardening

# Check system resources
df -h && free -h
```

### Log Locations

- **System logs**: `/var/log/syslog` or `journalctl`
- **HARDN logs**: `journalctl -u hardn.service`
- **API logs**: `journalctl -u hardn-api.service`

## Performance Impact

### Resource Usage
- **HARDN service**: Minimal (one-time execution)
- **Security tools**: Variable based on scanning frequency
- **API service**: Minimal web server load

### Optimization
- Security scanning can be scheduled during off-hours
- Memory limits applied to prevent resource exhaustion
- CPU nice levels for background processing