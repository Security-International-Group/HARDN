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

# Hard guard — install_package succeeds on "already installed" packages whose
# binaries are missing from PATH (e.g. broken dpkg states). Bail loudly rather
# than failing silently mid-config.
if ! command_exists fail2ban-client; then
    HARDN_STATUS "error" "fail2ban-client missing from PATH; refusing to write jail.local"
    exit 1
fi

# Honour HARDN_SSH_PORT when the operator has moved sshd off 22; otherwise the
# jail watches the wrong port and brute-force on the real port goes unblocked.
SSH_PORT="${HARDN_SSH_PORT:-22}"

# Build ignoreip list. Always include loopback. When running on a cloud
# provider with known health-check source ranges, allow those too so the LB
# probes can never get the instance banned and removed from rotation.
hardn_detect_env
IGNORE_IP="127.0.0.1/8 ::1"
HC_CIDRS=""
while IFS= read -r cidr; do
    [ -n "$cidr" ] || continue
    HC_CIDRS="$HC_CIDRS $cidr"
done < <(hardn_cloud_health_check_cidrs)
if [ -n "$HC_CIDRS" ]; then
    IGNORE_IP="$IGNORE_IP$HC_CIDRS"
    HARDN_STATUS "info" "Cloud detected ($HARDN_ENV_CLOUD); adding LB health-check ranges to ignoreip:$HC_CIDRS"
fi

HARDN_STATUS "info" "Configuring Fail2Ban SSH jail (port=${SSH_PORT})"
cat > /etc/fail2ban/jail.local <<EOF
[DEFAULT]
ignoreip = ${IGNORE_IP}
allowipv6 = auto
bantime = 1h
findtime = 10m
maxretry = 5
backend = systemd

[sshd]
enabled = true
port = ${SSH_PORT}
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
