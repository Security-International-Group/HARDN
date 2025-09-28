#!/bin/bash
# HARDN PAM/Sudo Recovery Script
# Purpose: Diagnose and fix PAM configuration issues preventing sudo access
# WARNING: Run this ONLY on your Virtual Machine, not on the host!

set -euo pipefail

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging function
log_message() {
    local level=$1
    shift
    local message="$*"
    
    case $level in
        ERROR)
            echo -e "${RED}[✗]${NC} $message"
            ;;
        SUCCESS)
            echo -e "${GREEN}[✓]${NC} $message"
            ;;
        WARNING)
            echo -e "${YELLOW}[⚠]${NC} $message"
            ;;
        INFO)
            echo -e "${BLUE}[ℹ]${NC} $message"
            ;;
    esac
}

# Check if running with appropriate privileges
check_privileges() {
    if [[ $EUID -eq 0 ]]; then
        log_message INFO "Running as root"
    else
        log_message WARNING "Not running as root - some diagnostics may be limited"
        log_message INFO "If sudo is broken, try: su - root"
    fi
}

# Diagnose PAM configuration
diagnose_pam() {
    echo ""
    log_message INFO "=== DIAGNOSING PAM CONFIGURATION ==="
    echo ""
    
    # Check PAM directory structure
    if [[ -d /etc/pam.d ]]; then
        log_message SUCCESS "/etc/pam.d directory exists"
    else
        log_message ERROR "/etc/pam.d directory missing!"
        return 1
    fi
    
    # Check critical PAM files
    local critical_files=(
        "/etc/pam.d/sudo"
        "/etc/pam.d/common-auth"
        "/etc/pam.d/common-account"
        "/etc/pam.d/common-password"
        "/etc/pam.d/common-session"
        "/etc/pam.d/common-session-noninteractive"
    )
    
    for file in "${critical_files[@]}"; do
        if [[ -f "$file" ]]; then
            log_message SUCCESS "$file exists"
            
            # Check for unknown modules
            if grep -E "^[^#].*\.so" "$file" 2>/dev/null | while read -r line; do
                module=$(echo "$line" | grep -oE "pam_[a-z0-9_]+\.so" | head -1)
                if [[ -n "$module" ]]; then
                    # Check if module exists
                    if ! find /lib/*/security/ -name "$module" 2>/dev/null | grep -q .; then
                        log_message ERROR "Unknown module in $file: $module"
                        echo "    Line: $line"
                        return 1
                    fi
                fi
            done; then
                :
            else
                log_message WARNING "Found problematic PAM module reference in $file"
            fi
        else
            log_message ERROR "$file is missing!"
        fi
    done
    
    # Check for syntax errors in sudo PAM file
    if [[ -f /etc/pam.d/sudo ]]; then
        echo ""
        log_message INFO "Checking /etc/pam.d/sudo content:"
        echo "----------------------------------------"
        cat /etc/pam.d/sudo | head -20
        echo "----------------------------------------"
    fi
}

# Create backup of current PAM configuration
backup_pam() {
    local backup_dir="/root/pam-backup-$(date +%Y%m%d-%H%M%S)"
    
    if [[ $EUID -eq 0 ]]; then
        log_message INFO "Creating backup of PAM configuration to $backup_dir"
        mkdir -p "$backup_dir"
        cp -r /etc/pam.d "$backup_dir/" 2>/dev/null || true
        cp /etc/security/* "$backup_dir/" 2>/dev/null || true
        log_message SUCCESS "Backup created at $backup_dir"
    else
        log_message WARNING "Cannot create backup without root privileges"
    fi
}

# Fix PAM configuration for sudo
fix_sudo_pam() {
    echo ""
    log_message INFO "=== FIXING SUDO PAM CONFIGURATION ==="
    echo ""
    
    if [[ $EUID -ne 0 ]]; then
        log_message ERROR "Root privileges required to fix PAM configuration"
        log_message INFO "Try: su - root (if you know root password)"
        return 1
    fi
    
    # Create standard sudo PAM configuration for Debian
    cat > /etc/pam.d/sudo << 'EOF'
#%PAM-1.0

# Enable the alternate authentication scheme
@include common-auth
@include common-account
@include common-session-noninteractive
EOF
    
    log_message SUCCESS "Created standard /etc/pam.d/sudo configuration"
    
    # Ensure common-auth is correct
    cat > /etc/pam.d/common-auth << 'EOF'
#
# /etc/pam.d/common-auth - authentication settings common to all services
#
# This file is included from other service-specific PAM config files,
# and should contain a list of the authentication modules that are
# common to all services.
#

# Standard Unix authentication.
auth    [success=1 default=ignore]      pam_unix.so nullok
# here's the fallback if no module succeeds
auth    requisite                       pam_deny.so
# prime the stack for a pam_permit.so
auth    required                        pam_permit.so
# and here are more per-package modules (the "Additional" block)
auth    optional                        pam_cap.so
EOF
    
    log_message SUCCESS "Restored /etc/pam.d/common-auth"
    
    # Ensure common-account is correct
    cat > /etc/pam.d/common-account << 'EOF'
#
# /etc/pam.d/common-account - account verification common to all services
#
# This file is included from other service-specific PAM config files,
# and should contain a list of the account verification modules that are
# common to all services.
#

# Standard Unix account management.
account [success=1 new_authtok_reqd=done default=ignore]        pam_unix.so
# here's the fallback if no module succeeds
account requisite                       pam_deny.so
# prime the stack for a pam_permit.so
account required                        pam_permit.so
# and here are more per-package modules (the "Additional" block)
EOF
    
    log_message SUCCESS "Restored /etc/pam.d/common-account"
    
    # Ensure common-session-noninteractive is correct
    cat > /etc/pam.d/common-session-noninteractive << 'EOF'
#
# /etc/pam.d/common-session-noninteractive - session handling for
# non-interactive services
#

# Standard Un session management.
session [default=1]                     pam_permit.so
# here's the fallback if no module succeeds
session requisite                       pam_deny.so
# prime the stack for a pam_permit.so
session required                        pam_permit.so
# The pam_umask module sets the umask for the session
session optional                        pam_umask.so
# and here are more per-package modules (the "Additional" block)
session required                        pam_unix.so
EOF
    
    log_message SUCCESS "Restored /etc/pam.d/common-session-noninteractive"
    
    # Fix permissions
    chmod 644 /etc/pam.d/sudo
    chmod 644 /etc/pam.d/common-*
    
    log_message SUCCESS "Fixed PAM file permissions"
}

# Verify PAM modules exist
verify_pam_modules() {
    echo ""
    log_message INFO "=== VERIFYING PAM MODULES ==="
    echo ""
    
    local required_modules=(
        "pam_unix.so"
        "pam_deny.so"
        "pam_permit.so"
    )
    
    for module in "${required_modules[@]}"; do
        if find /lib/*/security/ -name "$module" 2>/dev/null | grep -q .; then
            log_message SUCCESS "Found module: $module"
        else
            log_message ERROR "Missing module: $module"
            log_message INFO "Install with: apt-get install libpam-modules"
        fi
    done
}

# Test sudo after fix
test_sudo() {
    echo ""
    log_message INFO "=== TESTING SUDO ==="
    echo ""
    
    # Create a test script
    echo "echo 'Sudo test successful'" > /tmp/sudo_test.sh
    chmod +x /tmp/sudo_test.sh
    
    if sudo /tmp/sudo_test.sh 2>/dev/null; then
        log_message SUCCESS "Sudo is working!"
    else
        log_message ERROR "Sudo still not working"
        log_message INFO "You may need to:"
        log_message INFO "  1. Log out and log back in"
        log_message INFO "  2. Restart the system"
        log_message INFO "  3. Check /var/log/auth.log for details"
    fi
    
    rm -f /tmp/sudo_test.sh
}

# Alternative recovery using dpkg
recover_with_dpkg() {
    echo ""
    log_message INFO "=== ATTEMPTING DPKG RECOVERY ==="
    echo ""
    
    if [[ $EUID -ne 0 ]]; then
        log_message ERROR "Root privileges required for dpkg recovery"
        return 1
    fi
    
    log_message INFO "Attempting to reconfigure PAM packages..."
    
    # Try to reconfigure PAM packages
    dpkg-reconfigure -p critical libpam-modules 2>/dev/null || true
    dpkg-reconfigure -p critical libpam-runtime 2>/dev/null || true
    
    # Reinstall sudo package
    log_message INFO "Reinstalling sudo package..."
    apt-get update 2>/dev/null || true
    apt-get install --reinstall sudo libpam-modules libpam-runtime -y 2>/dev/null || true
    
    log_message SUCCESS "Package recovery attempted"
}

# Main execution
main() {
    echo -e "${BLUE}╔════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║     HARDN PAM/Sudo Recovery Tool          ║${NC}"
    echo -e "${BLUE}╚════════════════════════════════════════════╝${NC}"
    echo ""
    
    check_privileges
    
    # Diagnose the problem
    diagnose_pam
    
    # Verify PAM modules
    verify_pam_modules
    
    # If running as root, offer to fix
    if [[ $EUID -eq 0 ]]; then
        echo ""
        echo -e "${YELLOW}Do you want to attempt automatic recovery? (y/n)${NC}"
        read -r response
        
        if [[ "$response" == "y" || "$response" == "Y" ]]; then
            backup_pam
            fix_sudo_pam
            test_sudo
            
            echo ""
            echo -e "${YELLOW}Do you want to try dpkg recovery as well? (y/n)${NC}"
            read -r response2
            
            if [[ "$response2" == "y" || "$response2" == "Y" ]]; then
                recover_with_dpkg
                test_sudo
            fi
        fi
    else
        echo ""
        log_message WARNING "To fix PAM configuration, run this script as root:"
        log_message INFO "su - root"
        log_message INFO "bash $0"
    fi
    
    echo ""
    log_message INFO "Additional debugging information:"
    log_message INFO "  - Check /var/log/auth.log for detailed errors"
    log_message INFO "  - Check /var/log/syslog for system messages"
    log_message INFO "  - Try: journalctl -xe | grep -i pam"
    echo ""
}

# Run main function
main "$@"