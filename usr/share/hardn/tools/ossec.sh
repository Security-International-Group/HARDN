#!/bin/bash
# HARDN OSSEC Setup Script
set -euo pipefail

source "$(cd "$(dirname "$0")" && pwd)/functions.sh"

HARDN_STATUS "Installing and configuring OSSEC..."

if command -v ossec-control >/dev/null 2>&1; then
    ossec-control start
    HARDN_STATUS "OSSEC started successfully"
else
    HARDN_STATUS "OSSEC is not installed"
fi  

check_root
log_tool_execution "ossec.sh"   
HARDN_STATUS "info" "Ensuring OSSEC package is installed"   
if install_package ossec-hids; then
    HARDN_STATUS "pass" "OSSEC package installed"
else
    HARDN_STATUS "error" "Failed to install OSSEC"
    exit 1
fi
HARDN_STATUS "info" "Configuring OSSEC for offline operation..."
if [ -f /var/ossec/etc/ossec.conf ]; then
    sed -i 's|<update>yes</update>|<update>no</update>|g' /var/ossec/etc/ossec.conf 2>/dev/null || true
    sed -i 's|<check_for_updates>yes</check_for_updates>|<check_for_updates>no</check_for_updates>|g' /var/ossec/etc/ossec.conf 2>/dev/null || true
    sed -i 's|<email_notification>yes</email_notification>|<email_notification>no</email_notification>|g' /var/ossec/etc/ossec.conf 2>/dev/null || true
    sed -i 's|<smtp_server>.*</smtp_server>|<smtp_server></smtp_server>|g' /var/ossec/etc/ossec.conf 2>/dev/null || true
    sed -i 's|<email_from>.*</email_from>|<email_from></email_from>|g' /var/ossec/etc/ossec.conf 2>/dev/null || true
    sed -i 's|<email_to>.*</email_to>|<email_to></email_to>|g' /var/ossec/etc/ossec.conf 2>/dev/null || true
fi          
if enable_service ossec; then
    HARDN_STATUS "pass" "OSSEC service enabled and running"
else
    HARDN_STATUS "warning" "Unable to enable or start OSSEC service"
fi
HARDN_STATUS "info" "OSSEC setup complete"  
