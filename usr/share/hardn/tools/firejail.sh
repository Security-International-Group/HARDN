#!/bin/bash
# HARDN Firejail Setup Script
# Configures Firejail profiles for HARDN applications

set -euo pipefail

source "$(cd "$(dirname "$0")" && pwd)/functions.sh"

check_root
log_tool_execution "firejail.sh"    
HARDN_STATUS "info" "Configuring Firejail profiles for HARDN applications"

# Try to install Firejail
if install_package firejail; then
    HARDN_STATUS "pass" "Firejail installed"
else
    HARDN_STATUS "warning" "Failed to install Firejail; skipping Firejail configuration"
    exit 0
fi

if command -v firejail >/dev/null 2>&1; then

    FIREJAIL_PROFILE_DIR="/etc/firejail"
    HARDN_FIREJAIL_PROFILE_DIR="/usr/share/hardn/firejail"
    MODULE_DIR="/usr/share/hardn/modules"
    TOOL_DIR="/usr/share/hardn/tools"

    # Ensure the HARDN Firejail profile directory exists
    if [ ! -d "$HARDN_FIREJAIL_PROFILE_DIR" ]; then
        mkdir -p "$HARDN_FIREJAIL_PROFILE_DIR"
        HARDN_STATUS "info" "Created HARDN Firejail profile directory at $HARDN_FIREJAIL_PROFILE_DIR"
    fi

    # Create or update Firejail profiles for HARDN applications
    declare -A FIREJAIL_PROFILES=(
        ["hardn-gui"]="hardn-gui.profile"
        ["hardn-service-manager"]="hardn-service-manager.profile"
        # Add more HARDN applications and their corresponding profile names here
    )

    for app in "${!FIREJAIL_PROFILES[@]}"; do
        profile_name="${FIREJAIL_PROFILES[$app]}"
        profile_path="$FIREJAIL_PROFILE_DIR/$profile_name"

        # Create a basic Firejail profile if it doesn't exist
        if [ ! -f "$profile_path" ]; then
            cat > "$profile_path" <<EOL
# Firejail profile for $app
noblacklist ${MODULE_DIR}
noblacklist ${TOOL_DIR}
include /etc/firejail/whitelist-common.inc
include /etc/firejail/whitelist-gui.inc
EOL
            HARDN_STATUS "pass" "Created Firejail profile for $app at $profile_path"
        else
            HARDN_STATUS "info" "Firejail profile for $app already exists at $profile_path"
        fi
    done    

    HARDN_STATUS "pass" "Firejail configuration completed"
else
    HARDN_STATUS "warning" "Firejail is not installed; skipping Firejail configuration"
fi

HARDN_STATUS "info" "Firejail configuration task completed"  