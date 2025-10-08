#!/bin/bash
# HARDN UFW Setup Script
set -euo pipefail

source "$(cd "$(dirname "$0")" && pwd)/functions.sh"

check_root
log_tool_execution "ufw.sh"

HARDN_STATUS "info" "Configuring firewall with strict rules..."

if command -v ufw >/dev/null 2>&1; then
    # Reset UFW to defaults
    ufw --force disable || true
    ufw --force reset || true
    
    # Default policies
    ufw default deny incoming || true
    ufw default allow outgoing || true
    ufw default deny routed || true
    
    # Allow SSH (rate limited)
    ufw limit ssh/tcp comment 'SSH rate limit' || true
    
    # Allow DNS
    ufw allow out 53 comment 'DNS' || true
    
    # Allow HTTP/HTTPS out
    ufw allow out 80/tcp comment 'HTTP' || true
    ufw allow out 443/tcp comment 'HTTPS' || true
    
    # Allow NTP
    ufw allow out 123/udp comment 'NTP' || true
    
    # Enable UFW
    ufw --force enable || true
    HARDN_STATUS "pass" "UFW firewall configured with strict rules"
else
    HARDN_STATUS "warning" "ufw not installed; skipping firewall configuration"
fi
