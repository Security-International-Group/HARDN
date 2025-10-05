#!/bin/bash
# HARDN Fail2Ban Setup Script

set -euo pipefail

source "$(cd "$(dirname "$0")" && pwd)/functions.sh"

check_root
log_tool_execution "fail2ban.sh"

HARDN_STATUS "info" "Ensuring Fail2Ban package is installed"
if install_package fail2ban; then
    HARDN_STATUS "pass" "Fail2Ban package present"
else
    HARDN_STATUS "error" "Failed to install Fail2Ban"
    exit 1
fi

HARDN_STATUS "info" "Configuring Fail2Ban SSH jail"
cat <<'EOF' > /etc/fail2ban/jail.local
[DEFAULT]
ignoreip = 127.0.0.1/8 ::1
allowipv6 = auto
bantime = 1h
findtime = 10m
maxretry = 5
backend = systemd

[sshd]
enabled = true
port = 22
logpath = %(sshd_log)s
EOF

if fail2ban-client -t >/dev/null 2>&1; then
    HARDN_STATUS "pass" "Fail2Ban configuration test passed"
else
    HARDN_STATUS "warning" "Fail2Ban configuration test reported issues"
fi

if enable_service fail2ban; then
    HARDN_STATUS "pass" "Fail2Ban service enabled and running"
else
    HARDN_STATUS "warning" "Unable to enable or start Fail2Ban service"
fi

HARDN_STATUS "info" "Fail2Ban setup complete"