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

HARDN_STATUS "info" "Updating ClamAV virus definitions"
if freshclam >/dev/null 2>&1; then
    HARDN_STATUS "pass" "ClamAV virus definitions updated"
else
    HARDN_STATUS "warning" "Could not update virus definitions via freshclam"
fi

HARDN_STATUS "info" "Enabling ClamAV services"
if enable_service clamav-freshclam && enable_service clamav-daemon; then
    HARDN_STATUS "pass" "ClamAV services enabled"
else
    HARDN_STATUS "warning" "One or more ClamAV services could not be enabled"
fi

HARDN_STATUS "info" "ClamAV setup complete"