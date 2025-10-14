#!/bin/bash
# HARDN ClamAV Setup Script

set -euo pipefail

source "$(cd "$(dirname "$0")" && pwd)/functions.sh"

check_root
log_tool_execution "clamv.sh"

HARDN_STATUS "info" "Ensuring ClamAV packages are installed"
if install_package clamav && install_package clamav-daemon; then
    HARDN_STATUS "pass" "ClamAV packages installed"
else
    HARDN_STATUS "error" "Failed to install ClamAV packages"
    exit 1
fi

HARDN_STATUS "info" "Checking ClamAV virus definitions"
if [[ -f /var/lib/clamav/daily.cld && -f /var/lib/clamav/main.cvd ]]; then
    # Check if database is reasonably current (less than 7 days old)
    if [[ $(find /var/lib/clamav/daily.cld -mtime -7 2>/dev/null) ]]; then
        HARDN_STATUS "pass" "ClamAV virus definitions are current"
    else
        HARDN_STATUS "info" "ClamAV virus definitions may be outdated (clamav-freshclam service should update automatically)"
    fi
else
    HARDN_STATUS "warning" "ClamAV virus definition files not found"
fi

HARDN_STATUS "info" "Enabling ClamAV services"
if enable_service clamav-freshclam && enable_service clamav-daemon; then
    HARDN_STATUS "pass" "ClamAV services enabled"
else
    HARDN_STATUS "warning" "One or more ClamAV services could not be enabled"
fi

HARDN_STATUS "info" "ClamAV setup complete"