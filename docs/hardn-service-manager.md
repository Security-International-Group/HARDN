![HARDN Logo](docs/assets/IMG_1233.jpeg)
# HARDN Interactive Service Manager

## Overview

The HARDN Interactive Service Manager (`hardn-service-manager`) is a user-friendly bash script that provides a comprehensive menu-driven interface for managing all HARDN security functionality. It serves as the primary user interface for interacting with HARDN's services, modules, tools, and monitoring capabilities.

## Purpose

The service manager addresses the complexity of managing multiple security components by providing:

- **Centralized Control**: Single interface for all HARDN operations
- **User-Friendly Menus**: Hierarchical menu system with clear options
- **Safety Checks**: Root privilege verification and confirmation prompts for dangerous operations
- **Status Monitoring**: Real-time service status and system health information
- **Comprehensive Coverage**: Access to all HARDN features through organized menus

## Features

### Service Management
- Start, stop, restart, enable, and disable HARDN services
- Individual service control (hardn.service, hardn-api.service, legion-daemon.service)
- Bulk operations for all services
- Service status monitoring and log viewing

### Module Execution
- Dynamic listing of available hardening modules
- Individual module execution
- Batch execution of all modules
- Real-time execution feedback

### Tool Execution
- Dynamic listing of available security tools by category:
  - Security Scanners (Lynis, AIDE)
  - Network Security (Fail2ban, Legion)
  - Utility Tools (functions)
- Individual tool execution
- Batch execution of all tools

### LEGION Security Monitoring
- Basic security assessments
- Continuous monitoring daemon control
- Advanced options:
  - System baseline creation
  - ML-powered anomaly detection
  - Predictive analysis
  - Automated response capabilities
- Custom LEGION option configuration

### System Operations
- Security report generation
- Comprehensive status display
- Sandbox mode (network isolation)
- Run everything (modules + tools combined)

### Informational Features
- HARDN version information
- About HARDN details
- Complete help system integration

### Dangerous Operations
- SELinux enabling (with safety warnings and confirmations)
- Requires explicit user acknowledgment of risks

## Usage

### Prerequisites
- Root privileges (script checks automatically)
- HARDN binary installed and accessible
- Systemd services installed

### Running the Script
```bash
# As root
sudo hardn-service-manager

# Or from the installation directory
sudo /usr/bin/hardn-service-manager
```

### Menu Navigation
The script uses a hierarchical menu system:
1. **Main Menu**: Top-level operations and status
2. **Sub-menus**: Specialized operations (services, modules, tools, LEGION)
3. **Interactive Prompts**: Confirmation for dangerous operations

## Menu Structure

```
Main Menu
├── 1. Quick Start (Enable & Start All Services)
├── 2. Manage HARDN Services
│   ├── Individual service control
│   ├── Bulk operations
│   └── Log viewing
├── 3. Run HARDN Modules
│   ├── Dynamic module listing
│   └── Individual/batch execution
├── 4. Run Security Tools
│   ├── Categorized tool listing
│   └── Individual/batch execution
├── 5. LEGION Security Monitoring
│   ├── Basic operations
│   └── Advanced features
├── 6. Generate Security Report
├── 7. View HARDN Status
├── 8. Sandbox Mode
├── 9. Run Everything
├── 10. Dangerous Operations
├── a. About HARDN
├── v. Show Version
└── h. View HARDN Help
```

## Safety Features

### Privilege Checks
- Automatic root privilege verification
- Clear error messages for insufficient permissions
- Secure binary path detection

### Confirmation Prompts
- Dangerous operations require explicit confirmation
- SELinux enabling requires multiple confirmation steps
- Sandbox mode warns about network disconnection

### Error Handling
- Comprehensive error checking
- Graceful failure handling
- User-friendly error messages

## Dependencies

### Required System Components
- `systemctl` (systemd service management)
- `journalctl` (system logging)
- HARDN binary (automatically detected)
- Bash 4.0+ (advanced features)

### HARDN Components
- Core HARDN binary
- Systemd services (hardn.service, hardn-api.service, legion-daemon.service)
- Security modules and tools

## Installation

The service manager is installed automatically with HARDN via the Debian package:

```bash
# Install HARDN (includes service manager)
sudo dpkg -i hardn_*.deb

# Run service manager
sudo hardn-service-manager
```

## File Locations

- **Binary**: `/usr/bin/hardn-service-manager`
- **Permissions**: `755` (root execute, user/group read/execute)
- **Owner**: `root:root`

## Troubleshooting

### Common Issues

**"This script must be run as root!"**
- Solution: Run with `sudo hardn-service-manager`

**"HARDN binary not found!"**
- Solution: Ensure HARDN is properly installed
- Check: `which hardn` or `/usr/bin/hardn --version`

**"No modules/tools found!"**
- Solution: Verify HARDN installation
- Check: `hardn --list-modules` and `hardn --list-tools`

**Permission denied on script execution**
- Solution: Check file permissions: `ls -la /usr/bin/hardn-service-manager`
- Should be: `-rwxr-xr-x 1 root root`

### Log Locations
- Service logs: `/var/log/hardn/`
- System logs: `journalctl -u hardn*`
- Script execution: Terminal output

## Security Considerations

- **Root Access**: Script requires root privileges for system management
- **Input Validation**: All user inputs are validated
- **Safe Operations**: Dangerous operations have multiple confirmation steps
- **Audit Trail**: All operations are logged via systemd/journald

## Integration

The service manager integrates with:
- **HARDN Core**: All command-line functionality
- **Systemd**: Service management
- **Journald**: Logging system
- **Security Modules**: Dynamic module discovery
- **Security Tools**: Dynamic tool discovery

## Development

For development and testing:
```bash
# Test script syntax
bash -n /usr/bin/hardn-service-manager

# Debug mode (if implemented)
bash -x /usr/bin/hardn-service-manager
```

## Related Documentation

- [HARDN Core Documentation](hardn.md)
- [LEGION Daemon Documentation](legion-daemon.md)
- [HARDN API Documentation](hardn-api.md)
- [HARDN Service Documentation](hardn-service.md)