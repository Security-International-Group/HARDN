#!/bin/bash

set -euo pipefail

source "$(cd "$(dirname "$0")" && pwd)/functions.sh"

check_root
log_tool_execution "lynis.sh"

create_custom_profile() {
    cat > /etc/lynis/custom.prf <<'EOF'
# Custom Lynis profile for HARDN
# Using new format (key=value) for Lynis 3.x compatibility

# Skip certain tests that might not apply
skip-test=FIRE-4513
skip-test=FIRE-4524

# Skip container tests if not applicable
skip-test=CONT-8004
skip-test=CONT-8104

# Set machine role (server, desktop, or workstation)
machine-role=server

# Set colors for output
colors=yes

# Upload settings (disabled by default)
upload=no

# Show warnings only (set to yes to reduce output)
show-warnings-only=no

# Refresh database of software packages (improves accuracy)
refresh-repositories=yes

# Test for NIS/NIS+
test-scan-mode=yes
EOF
}

create_logrotate_config() {
    cat > /etc/logrotate.d/lynis <<'EOF'
/var/log/lynis/*.log {
    weekly
    missingok
    rotate 12
    compress
    delaycompress
    notifempty
    copytruncate
    create 640 root root
}

/var/log/lynis/*.dat {
    weekly
    missingok
    rotate 4
    compress
    delaycompress
    notifempty
    copytruncate
    create 640 root root
}
EOF
}

create_audit_runner() {
    cat > /usr/local/bin/lynis-audit.sh <<'EOF'
#!/bin/bash
# Automated Lynis security audit script for HARDN

set -euo pipefail

AUDIT_LOG="/var/log/lynis/hardn-audit.log"
REPORT_FILE="/var/log/lynis/hardn-report.dat"
CONCISE_REPORT="/var/log/lynis/lynis-report-concise.log"
RUN_LOG="/var/log/lynis/audit-runs.log"

mkdir -p /var/log/lynis

echo "$(date): Starting Lynis security audit" >> "$RUN_LOG"
if lynis audit system --verbose --log-file "$AUDIT_LOG" --report-file "$REPORT_FILE" 2>/dev/null; then
    echo "$(date): Lynis audit completed successfully" >> "$RUN_LOG"
    echo "Audit log: $AUDIT_LOG" >> "$RUN_LOG"
    echo "Report file: $REPORT_FILE" >> "$RUN_LOG"

    if command -v rg >/dev/null 2>&1; then
        echo "$(date): Generating concise report" >> "$RUN_LOG"
        if rg -i "Hardening index|NONE|UNSAFE|WEAK|NOT FOUND|DISABLED|^Suggestion:" "$AUDIT_LOG" \
            | sed 's/^[0-9]\+|[0-9-]\+ [0-9:]\+ //' > "$CONCISE_REPORT"; then
            echo "$(date): Concise report generated: $CONCISE_REPORT" >> "$RUN_LOG"
        else
            echo "$(date): Failed to generate concise report" >> "$RUN_LOG"
        fi
    else
        echo "$(date): ripgrep not found, concise report skipped" >> "$RUN_LOG"
    fi
else
    echo "$(date): Lynis audit failed" >> "$RUN_LOG"
fi
EOF

    chmod +x /usr/local/bin/lynis-audit.sh
}

ensure_lynis_installed() {
    if dpkg -s lynis >/dev/null 2>&1; then
        HARDN_STATUS "pass" "Lynis package already installed"
        return 0
    fi

    HARDN_STATUS "info" "Installing Lynis package"
    if apt-get update >/dev/null 2>&1 && apt-get install -y lynis >/dev/null 2>&1; then
        HARDN_STATUS "pass" "Lynis installed successfully"
        return 0
    else
        HARDN_STATUS "error" "Failed to install Lynis"
        return 1
    fi
}

prepare_configuration() {
    mkdir -p /etc/lynis

    if [ -f /etc/lynis/custom.prf ] && grep -E "^[a-z-]+:" /etc/lynis/custom.prf >/dev/null 2>&1; then
        local backup="/etc/lynis/custom.prf.old-$(date +%Y%m%d-%H%M%S)"
        cp /etc/lynis/custom.prf "$backup"
        HARDN_STATUS "info" "Backed up legacy Lynis profile to $backup"
    fi

    create_custom_profile
    HARDN_STATUS "info" "Custom Lynis profile deployed"

    mkdir -p /var/log/lynis
    chmod 755 /var/log/lynis
    create_logrotate_config
    HARDN_STATUS "info" "Logrotate policy for Lynis installed"

    create_audit_runner
    HARDN_STATUS "info" "Automated Lynis audit helper installed"
}

generate_concise_report() {
    local audit_log="/var/log/lynis/hardn-audit.log"
    local concise_report="/var/log/lynis/lynis-report-concise.log"

    if ! command -v rg >/dev/null 2>&1; then
        HARDN_STATUS "warning" "ripgrep not available; attempting installation for concise reports"
if install_package ripgrep; then
            HARDN_STATUS "pass" "ripgrep installed for Lynis summaries"
        else
            HARDN_STATUS "warning" "Could not install ripgrep; concise report generation skipped"
            return
        fi
    fi

    if rg -i "Hardening index|NONE|UNSAFE|WEAK|NOT FOUND|DISABLED|^Suggestion:" "$audit_log" \
        | sed 's/^[0-9]\+|[0-9-]\+ [0-9:]\+ //' > "$concise_report"; then
        HARDN_STATUS "pass" "Concise Lynis report generated"
        summarize_concise_report "$concise_report"
    else
        HARDN_STATUS "warning" "Failed to generate concise Lynis report"
    fi
}

summarize_concise_report() {
    local concise_report="$1"

    # Be tolerant of no matches under set -euo pipefail
    local hardening_index
    hardening_index=$(grep -i -m1 "Hardening index" "$concise_report" || true)
    local unsafe_count
    unsafe_count=$(grep -ci "UNSAFE" "$concise_report" || echo 0)
    local not_found_count
    not_found_count=$(grep -ci "NOT FOUND" "$concise_report" || echo 0)
    local weak_count
    weak_count=$(grep -ci "WEAK" "$concise_report" || echo 0)
    local disabled_count
    disabled_count=$(grep -ci "DISABLED" "$concise_report" || echo 0)
    local suggestions_count
    suggestions_count=$(grep -ci "^Suggestion:" "$concise_report" || echo 0)

    [ -n "$hardening_index" ] && HARDN_STATUS "info" "$hardening_index"
    HARDN_STATUS "info" "UNSAFE findings: $unsafe_count"
    HARDN_STATUS "info" "NOT FOUND items: $not_found_count"
    HARDN_STATUS "info" "WEAK configurations: $weak_count"
    HARDN_STATUS "info" "DISABLED features: $disabled_count"
    HARDN_STATUS "info" "Suggestions: $suggestions_count"
}

run_lynis_audit() {
    local audit_log="/var/log/lynis/hardn-audit.log"
    local report_file="/var/log/lynis/hardn-report.dat"

    mkdir -p /var/log/lynis
    HARDN_STATUS "info" "Running Lynis audit (this may take a few minutes)"

    # Run audit with timeout to prevent hanging
    if timeout 120 lynis audit system --quiet --log-file "$audit_log" --report-file "$report_file" 2>/dev/null; then
        HARDN_STATUS "pass" "Lynis audit completed successfully"
        HARDN_STATUS "info" "Audit log: $audit_log"
        HARDN_STATUS "info" "Report file: $report_file"
        generate_concise_report
    else
        HARDN_STATUS "warning" "Lynis audit timed out or failed - configuration files are ready for manual audit"
        HARDN_STATUS "info" "Run manually: lynis audit system --log-file $audit_log --report-file $report_file"
    fi
}

main() {
    HARDN_STATUS "info" "Starting Lynis installation and configuration"

    if ! ensure_lynis_installed; then
        exit 1
    fi

    prepare_configuration
    run_lynis_audit

    HARDN_STATUS "info" "To schedule regular audits add: 0 2 * * * /usr/local/bin/lynis-audit.sh"
    HARDN_STATUS "info" "Lynis setup complete"
}

main "$@"

printf "[HARDN] lynis.sh executed at $(date)\n" | tee -a /var/log/hardn/hardn-tools.log
