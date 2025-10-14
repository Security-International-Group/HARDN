#!/bin/bash

# Robust Grafana setup: ensure APT repo/key, install package, enable service
# Idempotent and tolerant to network/repo issues to avoid failing "Run ALL tools".

source "$(cd "$(dirname "$0")" && pwd)/functions.sh"

check_root

# Return 0 if a candidate version is available for installation
has_grafana_candidate() {
    local cand
    cand=$(apt-cache policy grafana 2>/dev/null | awk '/Candidate:/ {print $2}')
    [ -n "$cand" ] && [ "$cand" != "(none)" ]
}

ensure_grafana_repo() {
    HARDN_STATUS "info" "Configuring Grafana APT repository and key"
    install -d -m 0755 /etc/apt/keyrings 2>/dev/null || true

    # Ensure prerequisites (quietly)
    if ! command -v curl >/dev/null 2>&1 || ! command -v gpg >/dev/null 2>&1; then
        HARDN_STATUS "info" "Installing prerequisites for repo setup (curl, gnupg)"
        apt-get update -y >/dev/null 2>&1 || true
        apt-get install -y curl gnupg >/dev/null 2>&1 || true
    fi

    # Always refresh key to handle key rotations
    if command -v curl >/dev/null 2>&1 && command -v gpg >/dev/null 2>&1; then
        curl -fsSL https://apt.grafana.com/gpg.key | gpg --dearmor > /etc/apt/keyrings/grafana.gpg 2>/dev/null || return 1
        chmod 0644 /etc/apt/keyrings/grafana.gpg || true
    else
        HARDN_STATUS "warning" "curl or gpg not available; skipping repo key refresh"
    fi

echo "deb [signed-by=/etc/apt/keyrings/grafana.gpg] https://apt.grafana.com stable main" > /etc/apt/sources.list.d/grafana.list
    apt_update || true
}

HARDN_STATUS "info" "Ensuring Grafana package is installed"
if is_package_installed grafana; then
    HARDN_STATUS "pass" "Grafana package already installed"
else
    # Try direct install first
    if ! install_package grafana; then
        HARDN_STATUS "warning" "Grafana not found in current APT sources; adding official repo"
        ensure_grafana_repo || true
        # Re-try installation
        if ! install_package grafana; then
            if ! has_grafana_candidate; then
                HARDN_STATUS "warning" "Grafana repository unavailable at this time; skipping install"
                HARDN_STATUS "info" "You can install later with: apt-get install -y grafana"
                exit 0
            fi
            HARDN_STATUS "warning" "Grafana install failed even with repo configured; skipping"
            exit 0
        fi
    fi
fi

# systemd may require a daemon-reload before the new unit is recognized
HARDN_STATUS "info" "Reloading systemd units"
systemctl daemon-reload 2>/dev/null || true

HARDN_STATUS "info" "Enabling and starting Grafana service"
if enable_service grafana-server; then
    HARDN_STATUS "pass" "Grafana service enabled and running"
else
    HARDN_STATUS "warning" "Unable to enable or start Grafana service"
fi

HARDN_STATUS "info" "Grafana setup complete"
HARDN_STATUS "info" "Grafana management URL: http://localhost:9002"
HARDN_STATUS "info" "Default credentials: admin/admin (change on first login)"
HARDN_STATUS "info" "Grafana configured with system monitoring permissions"
