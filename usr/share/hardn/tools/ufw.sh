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
    # HARDN API (8000) and Grafana (9002) are loopback by default. To
    # expose either to specific source ranges set the corresponding env
    # var to a comma-separated CIDR list before running this script:
    #   HARDN_REMOTE_API_CIDRS="10.0.0.0/24,192.168.1.0/24"
    #   HARDN_REMOTE_DASHBOARD_CIDRS="10.0.0.0/24"
    # An empty / unset value means localhost-only, which is the
    # recommended default. Loopback is already permitted by the implicit
    # 'lo' rule that UFW installs, so no per-port rule is needed for that
    # path.
    if [ -n "${HARDN_REMOTE_API_CIDRS:-}" ]; then
        IFS=',' read -ra _api_cidrs <<< "$HARDN_REMOTE_API_CIDRS"
        for cidr in "${_api_cidrs[@]}"; do
            cidr_trim="$(echo "$cidr" | xargs)"
            [ -z "$cidr_trim" ] && continue
            ufw allow from "$cidr_trim" to any port 8000 proto tcp comment 'HARDN API (operator opt-in)' || true
        done
    fi
    if [ -n "${HARDN_REMOTE_DASHBOARD_CIDRS:-}" ]; then
        IFS=',' read -ra _dash_cidrs <<< "$HARDN_REMOTE_DASHBOARD_CIDRS"
        for cidr in "${_dash_cidrs[@]}"; do
            cidr_trim="$(echo "$cidr" | xargs)"
            [ -z "$cidr_trim" ] && continue
            ufw allow from "$cidr_trim" to any port 9002 proto tcp comment 'Grafana (operator opt-in)' || true
        done
    fi
    # NOTE: SSH port 22 is intentionally NOT opened.
    ufw allow out 53 comment 'DNS' || true
    ufw allow out 80/tcp comment 'HTTP' || true
    ufw allow out 443/tcp comment 'HTTPS' || true
    ufw allow out 123/udp comment 'NTP' || true
    ufw --force enable || true
    HARDN_STATUS "pass" "UFW firewall configured with strict rules"
else
    HARDN_STATUS "warning" "ufw not installed; skipping firewall configuration"
fi
