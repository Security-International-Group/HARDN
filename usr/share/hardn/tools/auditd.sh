#!/bin/bash
# HARDN auditd Setup Script

set -euo pipefail

source "$(cd "$(dirname "$0")" && pwd)/functions.sh"

check_root
log_tool_execution "auditd.sh"

HARDN_STATUS "info" "Configuring enhanced audit rules"

if command -v auditctl >/dev/null 2>&1; then
    cat > /etc/audit/rules.d/99-hardn-hardening.rules <<'EOF'
# HARDN Audit Rules (MITRE ATT&CK framework thanks to @4nt11 )

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
-w /etc/cron.monthly/-p war -k mitre_scheduled
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

-D

# Buffer Size
-b 8192

# Failure Mode
-f 1

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
else
    HARDN_STATUS "error" "auditctl not available; cannot apply audit rules"
fi

HARDN_STATUS "info" "Auditd rules applied. Review /etc/audit/rules.d/99-hardn-hardening.rules for details."
