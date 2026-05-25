#!/bin/bash
# HARDN auditd Setup Script

set -euo pipefail

source "$(cd "$(dirname "$0")" && pwd)/functions.sh"

check_root
log_tool_execution "auditd.sh"

hardn_detect_env

# Auditd inside an unprivileged container can't write rules — the audit
# subsystem is hosted by the host kernel. Skip cleanly rather than spam the
# log with "Operation not permitted" failures.
if hardn_in_container; then
    HARDN_STATUS "info" "Container detected ($HARDN_ENV_VIRT); skipping auditd rule load (audit subsystem owned by host)"
    exit 0
fi

HARDN_STATUS "info" "Configuring enhanced audit rules"

# Make sure auditd is present before trying to install rules.
if ! command -v auditctl >/dev/null 2>&1; then
    install_package auditd || true
fi

if ! command -v auditctl >/dev/null 2>&1; then
    HARDN_STATUS "error" "auditctl not available; cannot apply audit rules"
    exit 1
fi

# ----------------------------------------------------------------------------
# Disk-full safety policy
#
# Auditd will halt the kernel by default when its log volume fills, which on
# small cloud root disks (≤20 GB) and aggressive rules turns "low free space"
# into a hard panic. Pick a buffer size and disk policy that match the
# available space on /var/log so we degrade to syslog rather than crash.
# ----------------------------------------------------------------------------
AUDITD_CONF_DROPIN="/etc/audit/auditd.conf.d/99-hardn.conf"
mkdir -p "$(dirname "$AUDITD_CONF_DROPIN")" 2>/dev/null || true

# Free MB on /var/log (the auditd log volume); default to a conservative
# value if df isn't reading what we expect.
free_mb=$(df -Pm /var/log 2>/dev/null | awk 'NR==2 {print $4+0}')
free_mb=${free_mb:-0}

if [ "$free_mb" -lt 4096 ]; then
    # Small disk (<4 GB free): conservative buffer, SYSLOG on full so we keep
    # the box reachable rather than halt.
    buffer=4096
    disk_full_action="SYSLOG"
    space_left_mb=256
    admin_space_left_mb=64
elif [ "$free_mb" -lt 16384 ]; then
    buffer=8192
    disk_full_action="SYSLOG"
    space_left_mb=512
    admin_space_left_mb=128
else
    buffer=16384
    disk_full_action="SYSLOG"
    space_left_mb=1024
    admin_space_left_mb=256
fi

cat > "$AUDITD_CONF_DROPIN" <<EOF
# HARDN auditd disk-safety policy
# Generated based on free space on /var/log (${free_mb} MB)
max_log_file = 50
num_logs = 5
max_log_file_action = ROTATE
space_left = ${space_left_mb}
space_left_action = SYSLOG
admin_space_left = ${admin_space_left_mb}
admin_space_left_action = SUSPEND
disk_full_action = ${disk_full_action}
disk_error_action = SYSLOG
EOF
HARDN_STATUS "info" "Auditd disk policy written to $AUDITD_CONF_DROPIN (buffer=${buffer}, disk_full=${disk_full_action})"

cat > /etc/audit/rules.d/99-hardn-hardening.rules <<EOF
# HARDN Audit Rules (MITRE ATT&CK framework thanks to @4nt11 )

# Flush existing rules first
-D

# Buffer Size — sized for available log volume
-b ${buffer}

# Failure Mode (1 = printk warning, not panic)
-f 1

# T1059 – Command execution (focus on interactive users)
-a always,exit -F arch=b64 -S execve -F exe=/usr/bin/bash  -F auid>=1000 -F auid!=4294967295 -k mitre_cmd_exec
-a always,exit -F arch=b64 -S execve -F exe=/bin/sh        -F auid>=1000 -F auid!=4294967295 -k mitre_cmd_exec
-a always,exit -F arch=b64 -S execve -F exe=/bin/dash      -F auid>=1000 -F auid!=4294967295 -k mitre_cmd_exec
-a always,exit -F arch=b64 -S execve -F exe=/usr/bin/python3 -F auid>=1000 -F auid!=4294967295 -k mitre_cmd_exec
-a always,exit -F arch=b64 -S execve -F exe=/usr/bin/perl  -F auid>=1000 -F auid!=4294967295 -k mitre_cmd_exec
-a always,exit -F arch=b64 -S execve -F exe=/usr/bin/php   -F auid>=1000 -F auid!=4294967295 -k mitre_cmd_exec

# T1105 – Ingress tool transfer (watch for encoded/packaged drops)
-w /var/tmp/ -p wa -k mitre_ingress
-w /tmp/    -p wa -k mitre_ingress

# T1053 – Scheduled task/cron modifications
-w /etc/cron.d/      -p war -k mitre_scheduled
-w /etc/cron.daily/  -p war -k mitre_scheduled
-w /etc/cron.weekly/ -p war -k mitre_scheduled
-w /etc/cron.monthly/ -p war -k mitre_scheduled
-w /var/spool/cron/  -p war -k mitre_scheduled

# T1547 – Boot or logon autostart persistence
-w /etc/systemd/system/ -p wa -k mitre_autostart
-w /lib/systemd/system/ -p wa -k mitre_autostart
-a always,exit -F arch=b64 -S init_module,finit_module,delete_module -k mitre_rootkit

# T1003 – Credential dumping files
-w /etc/shadow -p war -k mitre_creds

# T1562 – Defense evasion (AV/audit tampering)
-w /etc/audit/        -p wa -k mitre_defense_evasion
-w /var/lib/audit/    -p wa -k mitre_defense_evasion
-w /usr/bin/freshclam -p x  -k mitre_defense_evasion
-w /usr/sbin/auditd   -p x  -k mitre_defense_evasion

# T1041 – Exfiltration over C2 channels
-a always,exit -F arch=b64 -S connect -F a0=2 -F auid>=1000 -F auid!=4294967295 -k mitre_exfil  # IPv4 sockets
-a always,exit -F arch=b64 -S sendto,sendmsg -F auid>=1000 -F auid!=4294967295 -k mitre_exfil

# Monitor authentication events
-w /var/log/faillog -p wa -k auth_failures
-w /var/log/lastlog -p wa -k logins
-w /var/log/tallylog -p wa -k logins

# Monitor user/group changes
-w /etc/group -p wa -k identity
-w /etc/passwd -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity

# Monitor sudoers
-w /etc/sudoers -p wa -k sudoers
-w /etc/sudoers.d/ -p wa -k sudoers

# Monitor SSH configuration
-w /etc/ssh/sshd_config -p wa -k sshd_config

# Monitor privileged commands
-a always,exit -F path=/usr/bin/passwd -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged

# Make configuration immutable
-e 2
EOF

# Reload audit rules
if augenrules --load >/dev/null 2>&1; then
    HARDN_STATUS "pass" "Audit rules loaded via augenrules"
else
    HARDN_STATUS "info" "augenrules reported an issue, but rules may still be applied"
fi

if systemctl restart auditd >/dev/null 2>&1; then
    HARDN_STATUS "pass" "auditd restarted with new rules"
else
    HARDN_STATUS "warning" "Could not restart auditd service"
fi

HARDN_STATUS "info" "Auditd rules applied. Review /etc/audit/rules.d/99-hardn-hardening.rules for details."
