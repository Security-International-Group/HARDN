#!/bin/bash
# HARDN HIDS Setup Script (OSSEC with Wazuh fallback)
### RESOURCE HEAVY ######
set -euo pipefail

source "$(cd "$(dirname "$0")" && pwd)/functions.sh"

check_root
log_tool_execution "ossec.sh"

has_package_candidate() {
    local pkg="$1"
    local cand
    cand=$(apt-cache policy "$pkg" 2>/dev/null | awk '/Candidate:/ {print $2}')
    [ -n "${cand:-}" ] && [ "$cand" != "(none)" ]
}

ensure_wazuh_repo() {
    HARDN_STATUS "info" "Configuring Wazuh APT repository and key"
    install -d -m 0755 /etc/apt/keyrings 2>/dev/null || true
    if ! [ -f /etc/apt/keyrings/wazuh.gpg ]; then
        if command -v curl >/dev/null 2>&1 && command -v gpg >/dev/null 2>&1; then
            curl -fsSL https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --dearmor > /etc/apt/keyrings/wazuh.gpg 2>/dev/null || true
            chmod 0644 /etc/apt/keyrings/wazuh.gpg || true
        else
            HARDN_STATUS "warning" "curl or gpg unavailable; skipping Wazuh repo key setup"
        fi
    fi
    echo "deb [signed-by=/etc/apt/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" > /etc/apt/sources.list.d/wazuh.list
    apt_update || true
}

install_ossec_or_wazuh() {
    # Prefer OSSEC if available
    if is_package_installed ossec-hids; then
        HARDN_STATUS "pass" "OSSEC package already installed"
        echo ossec
        return 0
    fi
    if has_package_candidate ossec-hids; then
        HARDN_STATUS "info" "Installing OSSEC (ossec-hids)"
        if install_package ossec-hids; then
            echo ossec
            return 0
        fi
        HARDN_STATUS "warning" "OSSEC install failed; will attempt Wazuh"
    else
        HARDN_STATUS "info" "OSSEC not available in repository; will attempt Wazuh"
    fi

    # Try Wazuh agent
    if ! has_package_candidate wazuh-agent; then
        ensure_wazuh_repo || true
    fi
    if is_package_installed wazuh-agent; then
        HARDN_STATUS "pass" "Wazuh agent already installed"
        echo wazuh-agent
        return 0
    fi
    if has_package_candidate wazuh-agent && install_package wazuh-agent; then
        echo wazuh-agent
        return 0
    fi

    # Neither available/installed
    echo none
    return 1
}

HARDN_STATUS "info" "Installing and configuring HIDS (OSSEC/Wazuh)"

agent_service=$(install_ossec_or_wazuh || true)

if [ -z "${agent_service}" ] || [ "${agent_service}" = "none" ]; then
    HARDN_STATUS "warning" "No OSSEC/Wazuh agent available on this system; skipping HIDS setup"
    exit 0
fi

# Common config path (both OSSEC and Wazuh use /var/ossec)
HARDN_STATUS "info" "Configuring agent for offline operation..."
if [ -f /var/ossec/etc/ossec.conf ]; then
    sed -i 's|<update>yes</update>|<update>no</update>|g' /var/ossec/etc/ossec.conf 2>/dev/null || true
    sed -i 's|<check_for_updates>yes</check_for_updates>|<check_for_updates>no</check_for_updates>|g' /var/ossec/etc/ossec.conf 2>/dev/null || true
    sed -i 's|<email_notification>yes</email_notification>|<email_notification>no</email_notification>|g' /var/ossec/etc/ossec.conf 2>/dev/null || true
    sed -i 's|<smtp_server>.*</smtp_server>|<smtp_server></smtp_server>|g' /var/ossec/etc/ossec.conf 2>/dev/null || true
    sed -i 's|<email_from>.*</email_from>|<email_from></email_from>|g' /var/ossec/etc/ossec.conf 2>/dev/null || true
    sed -i 's|<email_to>.*</email_to>|<email_to></email_to>|g' /var/ossec/etc/ossec.conf 2>/dev/null || true
fi

# Enable whichever service exists
HARDN_STATUS "info" "Enabling and starting agent service"
service_candidates=("${agent_service}" ossec ossec-hids wazuh-agent)
started=0
for svc in "${service_candidates[@]}"; do
    if service_exists "$svc"; then
        if enable_service "$svc"; then
            HARDN_STATUS "pass" "Service $svc enabled and running"
            started=1
            break
        else
            HARDN_STATUS "warning" "Failed to enable/start $svc"
        fi
    fi
done

# As an extra fallback, try ossec-control if present
if [ "$started" -eq 0 ] && command -v ossec-control >/dev/null 2>&1; then
    ossec-control start || true
    HARDN_STATUS "info" "Attempted start via ossec-control"
fi

HARDN_STATUS "info" "HIDS setup complete"  
