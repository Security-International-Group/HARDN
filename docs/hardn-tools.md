# HARDN Security Tools Activation Guide

## Problem Description

The HARDN security report shows certain security tools as permanently DISABLED because the current implementation only checks for systemd services with specific names. However, many security tools:

1. Don't run as persistent daemons (e.g., RKHunter, Lynis)
2. Use different service names than expected (e.g., `clamav-daemon` instead of `clamav`)
3. Run as systemd timers instead of services (e.g., AIDE)
4. Require special activation methods (e.g., UFW firewall rules)

## Root Cause

In `/src/main.rs`, the `check_service_status()` function only checks for systemd services using `systemctl is-active` and `systemctl is-enabled`. This fails for tools that:

- **AIDE**: Runs via `dailyaidecheck.timer`, not as a service
- **RKHunter**: Command-line tool, no service
- **OSSEC**: May use different service names or custom init scripts
- **Lynis**: Audit tool that runs on-demand or via timer
- **UFW**: Firewall that needs special status checking

## Solution Components

### 1. Enhanced Detection in Main Binary
**File**: `/src/main.rs`

The main HARDN binary now includes:
- `check_enhanced_tool_status()` function with tool-specific detection
- `ToolStatusType` enum for different status levels
- Proper detection for timers, processes, and non-service tools
- Integration with the security report generation

### 2. Interactive CLI Manager (Bash)
**File**: `/usr/share/hardn/scripts/security-tools-manager.sh`

Features:
- Interactive menu for tool activation
- Automatic installation if tools are missing
- Proper initialization (e.g., AIDE database, RKHunter properties)
- Status checking with color-coded output
- Batch activation option

## Usage on a VM

### On Your VM (as root):

#### Interactive Mode
```bash
sudo /usr/share/hardn/scripts/security-tools-manager.sh
```

This will show:
- Current status of all tools (Active/Enabled/Installed/Not Installed)
- Menu to activate individual tools
- Option to activate all tools at once

#### Command Line Mode
```bash
# Check status of all tools
sudo /usr/share/hardn/scripts/security-tools-manager.sh --status

# Activate all tools automatically
sudo /usr/share/hardn/scripts/security-tools-manager.sh --activate-all

# Get help
sudo /usr/share/hardn/scripts/security-tools-manager.sh --help
```

## Tool-Specific Activation Details

### AIDE (Advanced Intrusion Detection Environment)
- Installs `aide` and `aide-common` packages
- Initializes AIDE database (may take several minutes)
- Enables `dailyaidecheck.timer` for scheduled checks

### AppArmor
- Installs `apparmor`, `apparmor-utils`, and `apparmor-profiles`
- Enables and starts `apparmor.service`

### Fail2Ban
- Installs `fail2ban` package
- Enables and starts `fail2ban.service`
- Monitors auth logs for brute-force attempts

### UFW (Uncomplicated Firewall)
- Installs `ufw` package
- Enables firewall with `ufw --force enable`
- Default configuration allows established connections

### Auditd
- Installs `auditd` and `audispd-plugins`
- Enables and starts `auditd.service`
- Monitors system calls and security events

### RKHunter
- Installs `rkhunter` package
- Updates properties database with `rkhunter --propupd`
- Updates signatures with `rkhunter --update`

### ClamAV
- Installs `clamav`, `clamav-daemon`, and `clamav-freshclam`
- Updates virus definitions with `freshclam`
- Starts both freshclam and clamav-daemon services

### Suricata
- Installs `suricata` and `suricata-update`
- Updates IDS rules with `suricata-update`
- Enables and starts `suricata.service`

### OSSEC
- Requires manual installation (not in standard repos)
- Once installed, starts with `/var/ossec/bin/ossec-control start`

### Lynis
- Installs `lynis` package
- Creates systemd timer for daily audits
- Enables `lynis.timer` for scheduled security audits

## How It Works

### Enhanced Detection in HARDN Binary

The main HARDN binary (`/src/main.rs`) now includes enhanced detection:

1. **`check_enhanced_tool_status()` function** handles each tool appropriately:
   - AIDE: Checks `dailyaidecheck.timer`
   - Lynis: Checks `lynis.timer` and binary
   - UFW: Directly checks firewall status
   - RKHunter: Checks binary and database
   - Others: Standard systemd checks

2. **Security Report Integration**:
   - The `generate_security_report()` function uses the enhanced detection
   - Shows four status levels: ACTIVE, ENABLED, INSTALLED, NOT INSTALLED
   - Provides accurate scoring based on actual tool state

### Standalone Tool Manager Script

The Bash script (`/usr/share/hardn/scripts/security-tools-manager.sh`) provides:
- Interactive menu for tool activation
- Automatic installation if tools are missing
- Proper initialization and configuration
- Works independently without recompiling HARDN

## Testing on Your VM

1. Copy the scripts to your VM, or download them from the repo, (whatever your workflow).

2. Run the manager to activate tools:
```bash
sudo /usr/share/hardn/scripts/security-tools-manager.sh
```

3. Verify activation:
```bash
sudo /usr/share/hardn/scripts/security-tools-manager.sh --status
```

## Troubleshooting

### Tool shows as "INSTALLED" but not "ACTIVE"
- Some tools don't run continuously (RKHunter, Lynis)
- Check if the tool needs initialization (AIDE database, RKHunter properties)
- Verify systemd timers with: `systemctl list-timers`

### Installation fails
- Ensure VM has internet connectivity
- Update package lists: `sudo apt update`
- Check for held packages: `sudo apt-mark showhold`

### Service fails to start
- Check logs: `journalctl -xe -u service-name`
- Verify configuration files exist
- Ensure no port conflicts (especially for network services)

## Security Considerations

- Always run these tools as root/sudo
- Review firewall rules after enabling UFW
- Some tools may impact system performance (ClamAV, Suricata)
- Configure tools appropriately for your environment
- Regular updates are crucial (virus definitions, IDS rules, etc.)

## Future Improvements

1. Add deactivation functionality
2. Implement configuration templates for each tool
3. Add health checks and monitoring
4. Create systemd service units for tools that lack them
5. Add automated testing for tool activation
6. Implement rollback functionality
7. Add network-based activation for remote VMs