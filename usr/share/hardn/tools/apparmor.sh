#!/bin/bash
# HARDN AppArmor Setup Script

set -euo pipefail

source "$(cd "$(dirname "$0")" && pwd)/functions.sh"

check_root
log_tool_execution "apparmor.sh"

HARDN_STATUS "info" "Enabling AppArmor profiles in complain mode"

if command -v aa-complain >/dev/null 2>&1; then
    if apt-get install -y apparmor-profiles apparmor-utils >/dev/null 2>&1; then
        HARDN_STATUS "pass" "AppArmor profiles and utilities installed"
    else
        HARDN_STATUS "warning" "Failed to install AppArmor utilities; continuing with best effort"
    fi

    if aa-complain /etc/apparmor.d/* >/dev/null 2>&1; then
        HARDN_STATUS "pass" "All AppArmor profiles set to complain mode"
    else
        HARDN_STATUS "warning" "Some AppArmor profiles may not have switched to complain mode"
    fi
else
    HARDN_STATUS "warning" "AppArmor utilities not available; skipping profile adjustments"
fi

HARDN_STATUS "info" "AppArmor configuration task completed"


