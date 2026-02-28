#!/bin/bash

# ------------------------------------------------------------
# Grafana Installation + Configuration Script
# ------------------------------------------------------------
# What this does:
#   - Ensures Grafana APT repo and key exist
#   - Installs Grafana if missing
#   - Forces Grafana to listen on port 9002
#   - Enables and starts the service
#   - Verifies health via curl against loopback
#
# Designed to be:
#   - Idempotent (safe to run multiple times)
#   - Tolerant of transient repo/network failures
#   - Non-breaking for “Run ALL tools” workflows
# ------------------------------------------------------------

source "$(cd "$(dirname "$0")" && pwd)/functions.sh"

check_root


# ------------------------------------------------------------
# Check if Grafana has an installable resource 
# ------------------------------------------------------------
has_grafana_candidate() {
    local cand
    cand=$(apt-cache policy grafana 2>/dev/null | awk '/Candidate:/ {print $2}')
    [ -n "$cand" ] && [ "$cand" != "(none)" ]
}


# ------------------------------------------------------------
# Ensure Grafana official APT repository exists and install
# ------------------------------------------------------------
ensure_grafana_repo() {
    HARDN_STATUS "info" "Configuring Grafana APT repository"

    install -d -m 0755 /etc/apt/keyrings 2>/dev/null || true

    # Install tools 
    if ! command -v curl >/dev/null 2>&1 || ! command -v gpg >/dev/null 2>&1; then
        HARDN_STATUS "info" "Installing repo prerequisites (curl, gnupg)"
        apt-get update -y >/dev/null 2>&1 || true
        apt-get install -y curl gnupg >/dev/null 2>&1 || true
    fi

    # Refresh repo key (key rotation)
    if command -v curl >/dev/null 2>&1 && command -v gpg >/dev/null 2>&1; then
        curl -fsSL https://apt.grafana.com/gpg.key \
            | gpg --dearmor > /etc/apt/keyrings/grafana.gpg 2>/dev/null || return 1
        chmod 0644 /etc/apt/keyrings/grafana.gpg || true
    else
        HARDN_STATUS "warning" "Unable to refresh Grafana GPG key"
    fi

    echo "deb [signed-by=/etc/apt/keyrings/grafana.gpg] https://apt.grafana.com stable main" \
        > /etc/apt/sources.list.d/grafana.list

    apt_update || true
}


# ------------------------------------------------------------
# Ensure Grafana listens on port 9002
# modifies grafana.ini and adds a systemd override
# ------------------------------------------------------------
ensure_grafana_port() {

    local desired_port="9002"
    local ini="/etc/grafana/grafana.ini"
    local override_dir="/etc/systemd/system/grafana-server.service.d"
    local override_file="${override_dir}/override.conf"

    HARDN_STATUS "info" "Configuring Grafana to listen on port ${desired_port}"

    # Modify ini
    if [ -f "$ini" ]; then

        if grep -q '^\[server\]' "$ini"; then

            if grep -q '^[[:space:]]*http_port[[:space:]]*=' "$ini"; then
                sed -i -E \
                    "s|^[[:space:]]*http_port[[:space:]]*=.*|http_port = ${desired_port}|" \
                    "$ini"
            else
                awk -v port="$desired_port" '
                    /^\[server\]/ { print; print "http_port = " port; next }
                    { print }
                ' "$ini" > "${ini}.tmp" && mv "${ini}.tmp" "$ini"
            fi

        else
            echo "" >> "$ini"
            echo "[server]" >> "$ini"
            echo "http_port = ${desired_port}" >> "$ini"
        fi

    else
        install -d -m 0755 "$(dirname "$ini")" 2>/dev/null || true
        cat > "$ini" <<EOF
[server]
http_port = ${desired_port}
EOF
    fi

    # Add systemd override to enforce 
    install -d -m 0755 "$override_dir" 2>/dev/null || true
    cat > "$override_file" <<EOF
[Service]
Environment=GF_SERVER_HTTP_PORT=${desired_port}
EOF

    systemctl daemon-reload 2>/dev/null || true
}


# ------------------------------------------------------------
# Perform loopback health check
# Uses Grafana /api/health endpoint
# ------------------------------------------------------------
grafana_health_check() {

    local url="http://127.0.0.1:9002/api/health"
    local attempts=15
    local delay=2

    HARDN_STATUS "info" "Checking Grafana health via ${url}"

    if ! command -v curl >/dev/null 2>&1; then
        HARDN_STATUS "warning" "curl not installed; skipping health check"
        return 0
    fi

    for ((i=1; i<=attempts; i++)); do

        response=$(curl -s --max-time 5 "$url" 2>/dev/null)
        code=$(curl -s -o /dev/null -w "%{http_code}" "$url" 2>/dev/null)

        if [ "$code" = "200" ]; then
            HARDN_STATUS "pass" "Grafana is healthy on port 9002"
            HARDN_STATUS "info" "Health response: $response"
            return 0
        fi

        sleep "$delay"
    done

    HARDN_STATUS "fail" "Grafana did not report healthy on port 9002"
    return 1
}

HARDN_STATUS "info" "Ensuring Grafana package is installed"

if is_package_installed grafana; then
    HARDN_STATUS "pass" "Grafana already installed"
else

    if ! install_package grafana; then
        HARDN_STATUS "warning" "Grafana not found in current sources"
        ensure_grafana_repo || true

        if ! install_package grafana; then
            if ! has_grafana_candidate; then
                HARDN_STATUS "warning" "Grafana repo unavailable; skipping"
                exit 0
            fi
            HARDN_STATUS "warning" "Grafana installation failed"
            exit 0
        fi
    fi
fi


# Apply port configuration
ensure_grafana_port


# Enable and start
HARDN_STATUS "info" "Enabling and starting Grafana service"

if enable_service grafana-server; then
    HARDN_STATUS "pass" "Grafana service enabled"
else
    HARDN_STATUS "warning" "Unable to enable/start Grafana service"
fi


# Restart 
systemctl restart grafana-server 2>/dev/null || true
grafana_health_check || true


HARDN_STATUS "info" "Grafana setup complete"
HARDN_STATUS "info" "Access URL: http://localhost:9002"
HARDN_STATUS "info" "Default credentials: admin / admin (change immediately)"