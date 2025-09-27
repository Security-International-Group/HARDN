# HARDN Demo CHANGELOG

All notable changes to this project will be documented in this file.

- SOURCE: [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0/).

## [Unreleased]

### What's Changed

#### Service Manager Integration & Interactive Interface
- **Interactive Service Manager**: Added comprehensive menu-driven interface for managing all HARDN services
- **Ctrl+C Handling**: Implemented graceful signal handling - Ctrl+C now returns to menus instead of exiting the application
- **Service Monitoring**: Real-time service status display with color-coded indicators (active/enabled/inactive)
- **Log Viewing**: Interactive log monitoring for individual services and all services simultaneously
- **Main Orchestrator**: Established `hardn-service-manager.sh` as the primary interface for overall monitoring and launching

#### LEGION Security Monitoring System DEMO
- **Active Monitoring**: Implemented continuous security monitoring with syslog, journal, and network monitoring
- **Threat Intelligence**: Integrated threat correlation and anomaly detection capabilities
- **IOC Communication**: Added Indicators of Compromise (IOC) communication framework
- **Security Events**: Enhanced security event processing with detailed logging and alerting
- **Live System Metrics**: Fixed CPU and memory usage reporting to show real-time data instead of hardcoded values
- **Detailed Contributing Factors**: Enhanced risk reporting to list specific security issues found instead of generic messages
- **Comprehensive System Checks**: Added detailed checks for authentication failures, SUID/SGID files, kernel parameters, and container security

#### User Experience Improvements
- **Simplified Help System**: Refactored `hardn -h` into a clean, user-focused help menu
- **Navigation Guidance**: Added clear instructions for menu navigation (arrow keys, numbers, 'q' to quit)
- **Quick Start Commands**: Prominently featured `sudo make hardn` as the main orchestrator command
- **Troubleshooting Section**: Added practical error resolution guidance in help output
- **Package Commands**: Replaced direct file references with clean package-level commands

#### Technical Enhancements
- **Modular Architecture**: Improved code organization with separate modules for services, legion, display, etc.
- **Async Operations**: Enhanced tokio-based async operations for concurrent monitoring
- **Signal Handling**: Added ctrlc crate for robust signal interception and handling
- **Build System**: Maintained Makefile with proper privilege handling for system operations

### What's New

- **Interactive Service Manager**: Complete menu-driven interface for service management
- **LEGION Daemon(DEMO)**: Full security monitoring daemon with active threat detection
- **Enhanced Help System**: User-friendly help with navigation and troubleshooting guidance
- **Main Orchestrator Pattern**: Single command (`make hardn`) to launch the primary interface

### Security

- **Enhanced Monitoring**: Improved security posture with continuous monitoring capabilities
- **Threat Detection**: Added proactive threat intelligence and IOC processing
- **Access Control**: Maintained proper privilege handling throughout the system

### Upcoming Features

- **IOC Integration**: Complete Indicators of Compromise communication system
- **Advanced Analytics**: Enhanced threat correlation and predictive analysis
- **Web Interface**: Potential web-based management interface and local GTK App
- **Plugin System**: Extensible architecture for additional security modules