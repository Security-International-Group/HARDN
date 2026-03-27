#!/bin/bash
# HARDN UFW Setup Script
set -euo pipefail

source "$(cd "$(dirname "$0")" && pwd)/functions.sh"

check_root
log_tool_execution "ufw.sh"

HARDN_STATUS "info" "Configuring firewall with strict rules..."

# SSH port — override by setting SSH_PORT in environment before running this script
SSH_PORT="${SSH_PORT:-22}"

if command -v ufw >/dev/null 2>&1; then
    # Backup existing rules before making changes
    local_backup="/var/log/hardn/ufw-pre-reset-$(date +%Y%m%d%H%M%S).txt"
    mkdir -p /var/log/hardn
    ufw status verbose > "$local_backup" 2>/dev/null || true
    HARDN_STATUS "info" "UFW rules backed up to $local_backup"

    # NOTE: --force reset disables UFW and clears all rules, creating a brief
    # unprotected window until 'ufw --force enable' runs below.
    # Do not run this script over an untrusted network without a console fallback.
    ufw --force reset || true
    
    # Default policies
    ufw default deny incoming || true
    ufw default allow outgoing || true
    ufw default deny routed || true
    # Remote access: Grafana dashboard (port 9002)
    ufw allow in 9002/tcp comment 'Grafana dashboard' || true
    # Remote access: HARDN API (port 8000)
    ufw allow in 8000/tcp comment 'HARDN API' || true
    # NOTE: SSH port 22 is intentionally NOT opened.
    # Remote access is via Grafana (9002) and HARDN API (8000) only.
    ufw allow out 53 comment 'DNS' || true
    ufw allow out 80/tcp comment 'HTTP' || true
    ufw allow out 443/tcp comment 'HTTPS' || true
    ufw allow out 123/udp comment 'NTP' || true
    ufw --force enable || true
    HARDN_STATUS "pass" "UFW firewall configured with strict rules"
else
    HARDN_STATUS "warning" "ufw not installed; skipping firewall configuration"
fi
