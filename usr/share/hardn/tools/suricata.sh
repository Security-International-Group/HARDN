#!/bin/bash
set -euo pipefail

source "$(cd "$(dirname "$0")" && pwd)/functions.sh"

# HARDN Tool: suricata.sh
# Purpose: Install and configure Suricata IDS/IPS
#### RESOURCE HEAVY ######

check_root
log_tool_execution "suricata.sh"

create_fallback_suricata_rules() {
    HARDN_STATUS "info" "Creating fallback suricata.rules configuration..."

    # Ensure the rules directory exists with the right owner from the start.
    install -d -o suricata -g suricata -m 0755 /etc/suricata/rules

    # Create a basic suricata.rules file that includes all existing rule files
    cat > /etc/suricata/rules/suricata.rules << 'EOF'
# HARDN Generated Suricata Rules Configuration
# This file includes all available Suricata rule files

# Include all rule files from the rules directory
include $RULE_PATH/app-layer-events.rules
include $RULE_PATH/decoder-events.rules
include $RULE_PATH/dhcp-events.rules
include $RULE_PATH/dnp3-events.rules
include $RULE_PATH/dns-events.rules
include $RULE_PATH/files.rules
include $RULE_PATH/http2-events.rules
include $RULE_PATH/http-events.rules
include $RULE_PATH/ipsec-events.rules
include $RULE_PATH/kerberos-events.rules
include $RULE_PATH/modbus-events.rules
include $RULE_PATH/mqtt-events.rules
include $RULE_PATH/nfs-events.rules
include $RULE_PATH/ntp-events.rules
include $RULE_PATH/smb-events.rules
include $RULE_PATH/smtp-events.rules
include $RULE_PATH/ssh-events.rules
include $RULE_PATH/stream-events.rules
include $RULE_PATH/tls-events.rules
EOF

    # Set proper ownership and permissions
    chown suricata:suricata /etc/suricata/rules/suricata.rules
    chmod 644 /etc/suricata/rules/suricata.rules

    HARDN_STATUS "pass" "Fallback suricata.rules file created"
    HARDN_STATUS "warning" "Fallback rules contain only protocol event includes — NO threat detection rules. Run suricata-update to load detection rules."
}

fix_suricata_configuration() {
    HARDN_STATUS "info" "Attempting to fix Suricata configuration issues..."

    # `install -d` sets owner+group+mode in one syscall — avoids the window
    # where the directory exists with the wrong ownership before the later
    # chown lands (which matters when suricata is already running and tries
    # to read its rule dir mid-bootstrap).
    install -d -o suricata -g suricata -m 0755 /var/log/suricata
    install -d -o suricata -g suricata -m 0755 /var/lib/suricata
    install -d -o suricata -g suricata -m 0755 /var/lib/suricata/rules
    install -d -o suricata -g suricata -m 0755 /etc/suricata/rules

    # Ensure the suricata.rules file exists
    if [ ! -f "/etc/suricata/rules/suricata.rules" ]; then
        create_fallback_suricata_rules
    fi

    chmod 644 /etc/suricata/rules/*.rules 2>/dev/null || true

    HARDN_STATUS "info" "Configuration fix attempts completed"
}

# Run suricata-update against a staging directory, then atomically swap the
# resulting suricata.rules into place via rename(2). Without this, a running
# suricata that reloads mid-update can see a truncated/inconsistent rules file.
suricata_update_rules_atomic() {
    local staging_dir="/var/lib/hardn/suricata-rules-staging"
    local live_dir="/etc/suricata/rules"
    local live_file="$live_dir/suricata.rules"
    local staged_file="$staging_dir/suricata.rules"

    install -d -o suricata -g suricata -m 0755 "$staging_dir"
    install -d -o suricata -g suricata -m 0755 "$live_dir"

    HARDN_STATUS "info" "Running suricata-update into staging dir $staging_dir"
    if ! suricata-update --output "$staging_dir" --no-test --force; then
        HARDN_STATUS "warning" "suricata-update failed; keeping existing rules"
        return 1
    fi

    if [ ! -s "$staged_file" ]; then
        HARDN_STATUS "warning" "suricata-update produced no rules file; keeping existing rules"
        return 1
    fi

    # Validate the staged rules against the live config BEFORE swapping in.
    # If suricata can't parse them we abort and the running daemon is unharmed.
    if [ -f /etc/suricata/suricata.yaml ]; then
        if ! suricata -T -c /etc/suricata/suricata.yaml -S "$staged_file" >/dev/null 2>&1; then
            HARDN_STATUS "warning" "Staged rules failed suricata -T validation; keeping existing rules"
            return 1
        fi
    fi

    chown suricata:suricata "$staged_file" 2>/dev/null || true
    chmod 644 "$staged_file" 2>/dev/null || true

    # rename(2) is atomic on the same filesystem. /var/lib and /etc/suricata
    # are both on / on all supported targets.
    if mv -f "$staged_file" "$live_file"; then
        HARDN_STATUS "pass" "Suricata rules swapped in atomically"
        return 0
    else
        HARDN_STATUS "warning" "Could not atomically swap rules into $live_file"
        return 1
    fi
}

HARDN_STATUS "info" "Setting up Suricata IDS/IPS..."

# Helper to check if a package has a repository candidate
has_package_candidate() {
    local pkg="$1"
    local cand
    cand=$(apt-cache policy "$pkg" 2>/dev/null | awk '/Candidate:/ {print $2}')
    [ -n "${cand:-}" ] && [ "$cand" != "(none)" ]
}

# Try to install Suricata from package first
if ! is_package_installed suricata; then
    HARDN_STATUS "info" "Installing Suricata from repository..."
    if install_package suricata; then
        HARDN_STATUS "pass" "Suricata installed from repository"
    else
        # Only attempt source build if there is no repo candidate
        if has_package_candidate suricata; then
            HARDN_STATUS "warning" "APT busy or failed; repository candidate exists, skipping source build"
        elif [ "${HARDN_SURICATA_ALLOW_SOURCE_BUILD:-0}" != "1" ]; then
            HARDN_STATUS "warning" "Suricata not available in repository; skipping source build (set HARDN_SURICATA_ALLOW_SOURCE_BUILD=1 to enable)"
        else
            HARDN_STATUS "warning" "Suricata not available in repository; attempting source installation..."

            # Install build dependencies
            HARDN_STATUS "info" "Installing Suricata build dependencies..."
            build_deps=(
                build-essential libpcap-dev libnet1-dev libyaml-0-2 libyaml-dev \
                zlib1g zlib1g-dev libcap-ng-dev libmagic-dev libjansson-dev \
                libnss3-dev liblz4-dev libtool libnfnetlink-dev libevent-dev \
                pkg-config libhiredis-dev python3 python3-yaml python3-setuptools \
                python3-pip python3-dev rustc cargo wget
            )

            apt_update || true
            for pkg in "${build_deps[@]}"; do
                if ! install_package "$pkg"; then
                    HARDN_STATUS "warning" "Failed to install build dependency: $pkg"
                fi
            done

            suricata_version="7.0.0"
            download_url="https://www.suricata-ids.org/download/releases/suricata-${suricata_version}.tar.gz"
            download_dir="/tmp/suricata_install"
            tar_file="$download_dir/suricata-${suricata_version}.tar.gz"
            extracted_dir="suricata-${suricata_version}"

            mkdir -p "$download_dir"
            pushd "$download_dir" >/dev/null || {
                HARDN_STATUS "error" "Cannot change directory to $download_dir"
                exit 1
            }

            suricata_sha256="19d58e0be67c0cdd09a69df76fdf0e27d83d21d8fde2b2b71ea4083aebc57869"

            HARDN_STATUS "info" "Downloading Suricata source..."
            if wget -q "$download_url" -O "$tar_file"; then
                HARDN_STATUS "pass" "Download successful"

                HARDN_STATUS "info" "Verifying download integrity..."
                actual_sha256=$(sha256sum "$tar_file" | awk '{print $1}')
                if [ "$actual_sha256" != "$suricata_sha256" ]; then
                    HARDN_STATUS "error" "SHA256 mismatch — aborting. Expected: $suricata_sha256 Got: $actual_sha256"
                    rm -f "$tar_file"
                    exit 1
                fi
                HARDN_STATUS "pass" "Integrity check passed"

                HARDN_STATUS "info" "Extracting source..."
                if tar -xzf "$tar_file" -C "$download_dir"; then
                    HARDN_STATUS "pass" "Extraction successful"

                    if [[ -d "$download_dir/$extracted_dir" ]]; then
                        pushd "$download_dir/$extracted_dir" >/dev/null || {
                            HARDN_STATUS "error" "Cannot change directory to extracted folder"
                            exit 1
                        }

                        HARDN_STATUS "info" "Configuring Suricata build..."
                        if ./configure \
                            --prefix=/usr \
                            --sysconfdir=/etc \
                            --localstatedir=/var \
                            --disable-gccmarch-native \
                            --enable-lua \
                            --enable-geoip; then
                            HARDN_STATUS "pass" "Configure successful"

                            HARDN_STATUS "info" "Building Suricata..."
                            if make -j"$(nproc)"; then
                                HARDN_STATUS "pass" "Build successful"

                                HARDN_STATUS "info" "Installing Suricata..."
                                if make install; then
                                    HARDN_STATUS "pass" "Suricata installed from source"
                                    ldconfig || true
                                else
                                    HARDN_STATUS "error" "Installation failed"
                                    exit 1
                                fi
                            else
                                HARDN_STATUS "error" "Build failed"
                                exit 1
                            fi
                        else
                            HARDN_STATUS "error" "Configure failed"
                            exit 1
                        fi
                    else
                        HARDN_STATUS "error" "Extracted directory not found"
                        exit 1
                    fi
                else
                    HARDN_STATUS "error" "Extraction failed"
                    exit 1
                fi
            else
                HARDN_STATUS "error" "Download failed"
                exit 1
            fi

            # Cleanup
            popd >/dev/null 2>&1 || true
            popd >/dev/null 2>&1 || true
            rm -rf "$download_dir"
            HARDN_STATUS "info" "Source installation cleanup completed"
        fi
    fi
else
    HARDN_STATUS "pass" "Suricata package already installed"
fi

# Configure Suricata if installed
if command_exists suricata; then
    HARDN_STATUS "info" "Configuring Suricata..."

    # Ensure configuration directory exists
    if [ ! -d /etc/suricata ]; then
        HARDN_STATUS "info" "Creating /etc/suricata directory..."
        mkdir -p /etc/suricata
    fi

    # Create user and group if they don't exist
    if ! id -u suricata >/dev/null 2>&1; then
        HARDN_STATUS "info" "Creating suricata user..."
        useradd --system --no-create-home --shell /bin/false suricata
        HARDN_STATUS "pass" "Suricata user created"
    fi

    # Create log + rules dirs with correct owner/perms in one syscall.
    install -d -o suricata -g suricata -m 0755 /var/log/suricata
    install -d -o suricata -g suricata -m 0755 /var/lib/suricata
    install -d -o suricata -g suricata -m 0755 /var/lib/suricata/rules

    # Install/update suricata-update for rule management
    if ! command_exists suricata-update; then
        HARDN_STATUS "info" "Installing suricata-update..."
        if install_package suricata-update; then
            HARDN_STATUS "pass" "suricata-update installed successfully"
        else
            HARDN_STATUS "warning" "Failed to install suricata-update"
        fi
    fi

    # Update rules if suricata-update is available
    if command_exists suricata-update; then
        HARDN_STATUS "info" "Updating Suricata rules (atomic swap)..."
        if suricata_update_rules_atomic; then
            :
        elif [ ! -f /etc/suricata/rules/suricata.rules ]; then
            HARDN_STATUS "warning" "No existing rules to fall back to; writing fallback configuration"
            create_fallback_suricata_rules
        fi
    else
        HARDN_STATUS "warning" "suricata-update not available, creating basic rule configuration"
        create_fallback_suricata_rules
    fi

    # Test configuration before starting the service
    if [ -f /etc/suricata/suricata.yaml ]; then
        HARDN_STATUS "info" "Testing Suricata configuration..."

        # Warn if only fallback event rules exist (no real detection rules)
        if [ -f /etc/suricata/rules/suricata.rules ]; then
            if ! grep -qv '^#\|^$\|^include' /etc/suricata/rules/suricata.rules 2>/dev/null; then
                HARDN_STATUS "warning" "suricata.rules contains only includes — run suricata-update to load detection rules"
            fi
        fi

        # First verify the rules file exists
        if [ ! -f "/etc/suricata/rules/suricata.rules" ]; then
            HARDN_STATUS "warning" "suricata.rules file missing, creating fallback configuration"
            create_fallback_suricata_rules
        fi

        # Test the configuration
        if suricata -T -c /etc/suricata/suricata.yaml 2>/dev/null; then
            HARDN_STATUS "pass" "Suricata configuration test passed"
        else
            HARDN_STATUS "warning" "Suricata configuration test failed"
            HARDN_STATUS "info" "Attempting to fix common configuration issues..."

            fix_suricata_configuration

            if suricata -T -c /etc/suricata/suricata.yaml 2>/dev/null; then
                HARDN_STATUS "pass" "Suricata configuration test passed after fixes"
            else
                HARDN_STATUS "warning" "Suricata configuration still failing — set af-packet.interface in /etc/suricata/suricata.yaml and re-run"
            fi
        fi

        # Enable and start service only after config validation
        if enable_service suricata; then
            HARDN_STATUS "pass" "Suricata service enabled and started"
        else
            HARDN_STATUS "warning" "Failed to enable/start Suricata service"
        fi
    else
        HARDN_STATUS "warning" "No suricata.yaml found — not starting service. Set af-packet.interface and restart manually."
    fi

    # Remind operator to set the capture interface
    HARDN_STATUS "info" "ACTION REQUIRED: set 'af-packet.interface' in /etc/suricata/suricata.yaml to your capture interface (e.g. eth0, ens3)"
    HARDN_STATUS "info" "Then run: suricata-update && systemctl restart suricata"

else
    HARDN_STATUS "error" "Suricata command not found after installation attempt"
fi

HARDN_STATUS "pass" "Suricata setup completed"