#!/bin/bash

install_and_configure_lynis() {
    printf "\033[1;31m[+] Installing and configuring Lynis security auditing tool...\033[0m\n"
    
    # Check if Lynis is already installed
    if dpkg -s lynis >/dev/null 2>&1; then
        printf "\033[1;32m[+] Lynis is already installed.\033[0m\n"
    else
        printf "\033[1;31m[+] Installing Lynis...\033[0m\n"
        apt update
        apt install -y lynis || {
            printf "\033[1;31m[-] Failed to install Lynis.\033[0m\n"
            return 1
        }
    fi

    printf "\033[1;31m[+] Configuring Lynis...\033[0m\n"
    
    # Create Lynis configuration directory
    mkdir -p /etc/lynis
    
    # Check if old configuration exists and back it up
    if [ -f /etc/lynis/custom.prf ]; then
        # Check if it uses old format
        if grep -E "^[a-z-]{1,}:" /etc/lynis/custom.prf >/dev/null 2>&1; then
            printf "\033[1;33m[!] Found old format configuration, backing up and replacing...\033[0m\n"
            cp /etc/lynis/custom.prf /etc/lynis/custom.prf.old-$(date +%Y%m%d-%H%M%S)
        fi
    fi
    
    # Create basic Lynis configuration
    cat > /etc/lynis/custom.prf << 'EOF'
# Custom Lynis profile for HARDN
# Using new format (key=value) for Lynis 3.x compatibility
# Note: log-file and report-file are command-line options, not profile settings

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

    # Create log directory with proper permissions
    mkdir -p /var/log/lynis
    chmod 755 /var/log/lynis
    
    # Create logrotate configuration for Lynis
    cat > /etc/logrotate.d/lynis << 'EOF'
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

    # Create a script for regular Lynis audits
    cat > /usr/local/bin/lynis-audit.sh << 'EOF'
#!/bin/bash
# Automated Lynis security audit script for HARDN

# Create log directory if it doesn't exist
mkdir -p /var/log/lynis

# Log files
AUDIT_LOG="/var/log/lynis/hardn-audit.log"
REPORT_FILE="/var/log/lynis/hardn-report.dat"
CONCISE_REPORT="/var/log/lynis/lynis-report-concise.log"
RUN_LOG="/var/log/lynis/audit-runs.log"

# Run Lynis audit with verbose output
echo "$(date): Starting Lynis security audit" >> "$RUN_LOG"
lynis audit system --verbose --log-file "$AUDIT_LOG" --report-file "$REPORT_FILE" 2>/dev/null

# Check if audit completed successfully
if [ $? -eq 0 ]; then
    echo "$(date): Lynis audit completed successfully" >> "$RUN_LOG"
    echo "Audit log: $AUDIT_LOG" >> "$RUN_LOG"
    echo "Report file: $REPORT_FILE" >> "$RUN_LOG"
    
    # Generate concise report using ripgrep if available
    if command -v rg >/dev/null 2>&1; then
        echo "$(date): Generating concise report..." >> "$RUN_LOG"
        rg -i "Hardening index|NONE|UNSAFE|WEAK|NOT FOUND|DISABLED|^Suggestion:" "$AUDIT_LOG" | sed 's/^[0-9]\+|[0-9-]\+ [0-9:]\+ //' > "$CONCISE_REPORT"
        if [ $? -eq 0 ]; then
            echo "$(date): Concise report generated: $CONCISE_REPORT" >> "$RUN_LOG"
        else
            echo "$(date): Failed to generate concise report" >> "$RUN_LOG"
        fi
    else
        echo "$(date): ripgrep not found, skipping concise report generation" >> "$RUN_LOG"
    fi
else
    echo "$(date): Lynis audit failed with exit code $?" >> "$RUN_LOG"
fi
EOF

    chmod +x /usr/local/bin/lynis-audit.sh
    
    printf "\033[1;32m[+] Lynis installed and configured successfully.\033[0m\n"
    printf "\033[1;33m[!] Running Lynis security audit (this may take a few minutes)...\033[0m\n"
    
    # Ensure log directory exists
    mkdir -p /var/log/lynis
    
    # Run comprehensive audit with verbose output
    lynis audit system --verbose --log-file /var/log/lynis/hardn-audit.log --report-file /var/log/lynis/hardn-report.dat 2>/dev/null
    
    # Generate concise report if ripgrep is available
    if command -v rg >/dev/null 2>&1; then
        printf "\033[1;33m[!] Generating concise security report...\033[0m\n"
        rg -i "Hardening index|NONE|UNSAFE|WEAK|NOT FOUND|DISABLED|^Suggestion:" /var/log/lynis/hardn-audit.log | sed 's/^[0-9]\+|[0-9-]\+ [0-9:]\+ //' > /var/log/lynis/lynis-report-concise.log
        
        if [ $? -eq 0 ]; then
            printf "\033[1;32m[+] Concise report generated successfully.\033[0m\n"
            
            # Display summary statistics
            TOTAL_LINES=$(wc -l < /var/log/lynis/lynis-report-concise.log)
            HARDENING_INDEX=$(grep -i "Hardening index" /var/log/lynis/lynis-report-concise.log | head -1)
            UNSAFE_COUNT=$(grep -c "UNSAFE" /var/log/lynis/lynis-report-concise.log)
            NOT_FOUND_COUNT=$(grep -c "NOT FOUND" /var/log/lynis/lynis-report-concise.log)
            WEAK_COUNT=$(grep -c "WEAK" /var/log/lynis/lynis-report-concise.log)
            DISABLED_COUNT=$(grep -c "DISABLED" /var/log/lynis/lynis-report-concise.log)
            SUGGESTIONS_COUNT=$(grep -c "^Suggestion:" /var/log/lynis/lynis-report-concise.log)
            
            printf "\033[1;36m\n=== Security Audit Summary ===\033[0m\n"
            [ -n "$HARDENING_INDEX" ] && printf "\033[1;33m$HARDENING_INDEX\033[0m\n"
            printf "\033[1;31mSecurity Issues Found:\033[0m\n"
            printf "  - UNSAFE findings: \033[1;31m$UNSAFE_COUNT\033[0m\n"
            printf "  - NOT FOUND items: \033[1;33m$NOT_FOUND_COUNT\033[0m\n"
            printf "  - WEAK configurations: \033[1;33m$WEAK_COUNT\033[0m\n"
            printf "  - DISABLED features: \033[1;33m$DISABLED_COUNT\033[0m\n"
            printf "  - Suggestions: \033[1;36m$SUGGESTIONS_COUNT\033[0m\n"
            printf "\033[1;36m==============================\033[0m\n\n"
        else
            printf "\033[1;33m[!] Failed to generate concise report (ripgrep might not be configured properly)\033[0m\n"
        fi
    else
        printf "\033[1;33m[!] ripgrep not installed. Installing for future report generation...\033[0m\n"
        apt install -y ripgrep 2>/dev/null || printf "\033[1;33m[!] Could not install ripgrep. Concise reports will not be generated.\033[0m\n"
    fi
    
    printf "\033[1;33m[!] Lynis audit complete.\033[0m\n"
    printf "\033[1;32m[+] Audit log: /var/log/lynis/hardn-audit.log\033[0m\n"
    printf "\033[1;32m[+] Report file: /var/log/lynis/hardn-report.dat\033[0m\n"
    [ -f /var/log/lynis/lynis-report-concise.log ] && printf "\033[1;32m[+] Concise report: /var/log/lynis/lynis-report-concise.log\033[0m\n"
    printf "\033[1;33m[!] To run automated audits, add this to crontab:\033[0m\n"
    printf "0 2 * * * /usr/local/bin/lynis-audit.sh\n"
}

main() {
    install_and_configure_lynis
}

# Run main function if script is executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi

printf "[HARDN] lynis.sh executed at $(date)\n" | tee -a /var/log/hardn/hardn-tools.log
