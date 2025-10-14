#!/bin/bash
# HARDN AppArmor Setup Script

set -euo pipefail

source "$(cd "$(dirname "$0")" && pwd)/functions.sh"

check_root
log_tool_execution "apparmor.sh"

HARDN_STATUS "info" "Setting critical native Linux applications to appropriate AppArmor modes"

if command -v aa-complain >/dev/null 2>&1; then
    if apt-get install -y apparmor-profiles apparmor-utils >/dev/null 2>&1; then
        HARDN_STATUS "pass" "AppArmor profiles and utilities installed"
    else
        HARDN_STATUS "warning" "Failed to install AppArmor utilities; continuing with best effort"
    fi

    # List of problematic native applications that should be DISABLED (cause segfaults)
    DISABLE_PROFILES=(
        "nautilus"           # GNOME Files (file manager) - causes segfaults
        "evince"             # Document viewer - can have profile issues
        "firefox"            # Firefox browser - sometimes has profile conflicts
    )

    for profile in "${DISABLE_PROFILES[@]}"; do
        if aa-disable "$profile" >/dev/null 2>&1; then
            HARDN_STATUS "pass" "Disabled $profile AppArmor profile (prevents segfaults)"
        else
            HARDN_STATUS "info" "Profile $profile not found or already disabled"
        fi
    done

    # List of native Linux applications that should be in complain mode
    COMPLAIN_PROFILES=(
        "hardn-gui"          # HARDN GUI application
        "gnome-terminal"     # GNOME Terminal
        "gedit"              # GNOME Text Editor
        "thunderbird"        # Email client
        "rhythmbox"          # Music player
        "totem"              # Video player
        "eog"                # Image viewer
        "shotwell"           # Photo manager
        "cheese"             # Webcam app
        "gnome-calculator"   # Calculator
        "gnome-calendar"     # Calendar
        "gnome-clocks"       # Clocks
        "gnome-weather"      # Weather
        "gnome-maps"         # Maps
        "baobab"             # Disk usage analyzer
        "seahorse"           # Passwords and keys
        "gnome-system-monitor" # System monitor
        "gnome-disk-utility" # Disks
        "simple-scan"        # Document scanner
        "yelp"               # Help viewer
    )

    for profile in "${COMPLAIN_PROFILES[@]}"; do
        if aa-complain "$profile" >/dev/null 2>&1; then
            HARDN_STATUS "pass" "Set $profile to complain mode"
        else
            HARDN_STATUS "info" "Profile $profile not found or already in complain mode"
        fi
    done

    HARDN_STATUS "pass" "Critical native applications configured (some disabled, some in complain mode)"
else
    HARDN_STATUS "warning" "AppArmor utilities not available; skipping profile adjustments"
fi

HARDN_STATUS "info" "AppArmor configuration task completed"


