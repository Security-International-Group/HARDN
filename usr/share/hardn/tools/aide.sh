x#!/bin/bash

source "$(cd "$(dirname "$0")" && pwd)/functions.sh"

# HARDN Tool: aide.sh
# Purpose: Initialize AIDE database in necessary directories
# Location: /src/tools/aide.sh

check_root
log_tool_execution "aide.sh"

# Check if AIDE is installed
if ! is_package_installed aide; then
    HARDN_STATUS "error" "AIDE package not installed. Please install aide first."
    exit 1
fi

# Check if AIDE configuration exists
if [ ! -f /etc/aide/aide.conf ]; then
    # Try to install our minimal configuration
    if [ -f /usr/share/hardn/etc/aide/aide.conf ]; then
        cp /usr/share/hardn/etc/aide/aide.conf /etc/aide/aide.conf
        HARDN_STATUS "pass" "Installed minimal AIDE configuration to /etc/aide/aide.conf"
    else
        HARDN_STATUS "error" "AIDE configuration not found at /etc/aide/aide.conf and no default config available"
        exit 1
    fi
else
    HARDN_STATUS "info" "AIDE config: /etc/aide/aide.conf"
fi

# Check if AIDE database already exists
if [ -f /var/lib/aide/aide.db ] || [ -f /var/lib/aide/aide.db.gz ]; then
    HARDN_STATUS "pass" "AIDE database already exists - skipping initialization"
    HARDN_STATUS "info" "You can run 'aide --check' to verify system integrity"
    exit 0
fi

HARDN_STATUS "info" "Initializing AIDE database in necessary directories..."

# Create AIDE database directory if it doesn't exist
if [ ! -d /var/lib/aide ]; then
    mkdir -p /var/lib/aide
    HARDN_STATUS "pass" "Created AIDE database directory: /var/lib/aide"
fi

# Function to show spinner
show_spinner() {
    local pid=$1
    local delay=0.2
    local spinstr='|/-\'
    echo -n "Building AIDE database "
    while kill -0 $pid 2>/dev/null; do
        local temp=${spinstr#?}
        printf " [%c]  " "$spinstr"
        local spinstr=$temp${spinstr%"$temp"}
        sleep $delay
        printf "\b\b\b\b\b\b"
    done
    printf "    \b\b\b\b"
}

# Initialize AIDE database
HARDN_STATUS "info" "Scanning essential directories: /etc, /bin, /sbin, /usr/bin, /usr/sbin, /boot, /var/log"

# Run aideinit in background and show spinner
(aideinit 2>/dev/null || aide --init 2>/dev/null) &
local aide_pid=$!
show_spinner $aide_pid

# Wait for completion and check result
wait $aide_pid
if [ $? -eq 0 ]; then
    HARDN_STATUS "pass" "AIDE database initialized successfully"
    
    # Move new database into place if needed
    if [ -f /var/lib/aide/aide.db.new ]; then
        mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
        HARDN_STATUS "pass" "AIDE database moved into place"
    fi
    
    HARDN_STATUS "pass" "AIDE initialization complete"
    HARDN_STATUS "info" "Database location: /var/lib/aide/aide.db"
    HARDN_STATUS "info" "Run 'aide --check' to verify system integrity"
else
    HARDN_STATUS "error" "Failed to initialize AIDE database"
    exit 1
fi
