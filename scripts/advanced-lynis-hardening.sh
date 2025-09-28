#!/bin/bash
# HARDN Advanced Lynis Hardening Script
# This script implements additional advanced security measures for maximum Lynis score
# WARNING: Test this script ONLY on your Virtual Machine!

set -euo pipefail

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m'

# Configuration
BACKUP_DIR="/var/backups/hardn-$(date +%Y%m%d-%H%M%S)"
LOG_FILE="/var/log/hardn-advanced-hardening.log"
IMPROVEMENTS=0

# Function to log and print
log_action() {
    local level=$1
    local message=$2
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    case $level in
        SUCCESS)
            echo -e "${GREEN}[✓]${NC} $message"
            echo "[$timestamp] SUCCESS: $message" >> "$LOG_FILE"
            ((IMPROVEMENTS++))
            ;;
        ERROR)
            echo -e "${RED}[✗]${NC} $message"
            echo "[$timestamp] ERROR: $message" >> "$LOG_FILE"
            ;;
        WARNING)
            echo -e "${YELLOW}[⚠]${NC} $message"
            echo "[$timestamp] WARNING: $message" >> "$LOG_FILE"
            ;;
        INFO)
            echo -e "${BLUE}[ℹ]${NC} $message"
            echo "[$timestamp] INFO: $message" >> "$LOG_FILE"
            ;;
        SECTION)
            echo ""
            echo -e "${CYAN}╔════════════════════════════════════════════════════════╗${NC}"
            echo -e "${CYAN}║${NC} ${WHITE}$message${NC}"
            echo -e "${CYAN}╚════════════════════════════════════════════════════════╝${NC}"
            echo "[$timestamp] === $message ===" >> "$LOG_FILE"
            ;;
    esac
}

# Check root privileges
if [[ $EUID -ne 0 ]]; then
    log_action ERROR "This script must be run as root"
    exit 1
fi

# Initialize
mkdir -p "$BACKUP_DIR"
mkdir -p "$(dirname "$LOG_FILE")"
touch "$LOG_FILE"
chmod 600 "$LOG_FILE"

log_action SECTION "HARDN Advanced Lynis Hardening"
log_action INFO "Backup directory: $BACKUP_DIR"

# ═══════════════════════════════════════════════════════════════════
# ADVANCED NETWORK HARDENING
# ═══════════════════════════════════════════════════════════════════
log_action SECTION "Advanced Network Security"

# Create advanced sysctl settings
cat > /etc/sysctl.d/98-hardn-advanced.conf << 'EOF'
# HARDN Advanced Network Security Parameters

# TCP/IP Stack Hardening
net.ipv4.tcp_fin_timeout = 20
net.ipv4.tcp_keepalive_time = 300
net.ipv4.tcp_keepalive_probes = 5
net.ipv4.tcp_keepalive_intvl = 15
net.ipv4.tcp_retries1 = 3
net.ipv4.tcp_retries2 = 5
net.ipv4.tcp_syn_retries = 2
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_max_syn_backlog = 4096
net.ipv4.tcp_max_tw_buckets = 1440000
net.ipv4.tcp_tw_reuse = 0
net.ipv4.tcp_rfc1337 = 1
net.ipv4.tcp_sack = 0
net.ipv4.tcp_dsack = 0
net.ipv4.tcp_fack = 0

# ICMP Hardening
net.ipv4.icmp_ratelimit = 100
net.ipv4.icmp_ratemask = 88089
net.ipv4.icmp_errors_use_inbound_ifaddr = 1

# ARP Security
net.ipv4.conf.all.arp_ignore = 1
net.ipv4.conf.all.arp_announce = 2
net.ipv4.conf.default.arp_ignore = 1
net.ipv4.conf.default.arp_announce = 2

# Additional IPv6 Hardening (if enabled)
net.ipv6.conf.all.use_tempaddr = 2
net.ipv6.conf.default.use_tempaddr = 2
net.ipv6.conf.all.max_addresses = 1
net.ipv6.conf.default.max_addresses = 1
net.ipv6.conf.all.router_solicitations = 0
net.ipv6.conf.default.router_solicitations = 0
net.ipv6.conf.all.accept_ra_rtr_pref = 0
net.ipv6.conf.default.accept_ra_rtr_pref = 0
net.ipv6.conf.all.accept_ra_pinfo = 0
net.ipv6.conf.default.accept_ra_pinfo = 0
net.ipv6.conf.all.accept_ra_defrtr = 0
net.ipv6.conf.default.accept_ra_defrtr = 0
net.ipv6.conf.all.autoconf = 0
net.ipv6.conf.default.autoconf = 0
net.ipv6.conf.all.dad_transmits = 0
net.ipv6.conf.default.dad_transmits = 0
EOF

sysctl -p /etc/sysctl.d/98-hardn-advanced.conf >/dev/null 2>&1 && \
    log_action SUCCESS "Advanced network parameters configured" || \
    log_action WARNING "Some advanced network parameters failed"

# ═══════════════════════════════════════════════════════════════════
# USER LIMITS AND SESSION SECURITY (without PAM modifications)
# ═══════════════════════════════════════════════════════════════════
log_action SECTION "User Limits and Session Security"

# HARDN policy: Avoid PAM modifications for stability
log_action INFO "Following HARDN policy: No PAM modifications"

# Configure user limits via limits.conf instead of PAM
cat > /etc/security/limits.d/99-hardn-security.conf << 'EOF'
# HARDN Security Limits Configuration
# Hard limits for all users

# Core dumps
* hard core 0
* soft core 0

# Maximum number of processes
* hard nproc 1024
* soft nproc 512

# Maximum file size (1GB)
* hard fsize 1048576

# Maximum locked memory (64MB)
* hard memlock 65536
* soft memlock 65536

# Maximum number of open files
* hard nofile 4096
* soft nofile 1024

# Maximum stack size (8MB)
* hard stack 8192
* soft stack 8192

# CPU time (minutes)
* hard cpu 60
* soft cpu 30

# Priority settings
* hard nice -20
* soft nice 0
EOF

log_action SUCCESS "User limits configured via limits.conf"

# ═══════════════════════════════════════════════════════════════════
# APPARMOR CONFIGURATION (HARDN standard - no SELinux)
# ═══════════════════════════════════════════════════════════════════
log_action SECTION "AppArmor Mandatory Access Control"

# HARDN uses AppArmor, not SELinux
log_action INFO "HARDN uses AppArmor for MAC (SELinux is not supported)"

# Check for AppArmor
if command -v aa-status >/dev/null 2>&1; then
    # Enable AppArmor if not already
    systemctl enable apparmor 2>/dev/null || true
    systemctl start apparmor 2>/dev/null || true
    
    # Set all profiles to enforce mode
    for profile in /etc/apparmor.d/*; do
        if [[ -f "$profile" ]] && [[ ! "$profile" == *.dpkg* ]] && [[ ! "$profile" == *README* ]]; then
            profile_name=$(basename "$profile")
            aa-enforce "$profile" 2>/dev/null && \
                log_action SUCCESS "Profile enforced: $profile_name" || \
                log_action INFO "Could not enforce: $profile_name (may be disabled)"
        fi
    done
    
    # Load additional AppArmor profiles if available
    if [[ -d /usr/share/apparmor/extra-profiles ]]; then
        for extra_profile in /usr/share/apparmor/extra-profiles/*; do
            if [[ -f "$extra_profile" ]]; then
                profile_name=$(basename "$extra_profile")
                cp "$extra_profile" "/etc/apparmor.d/" 2>/dev/null && \
                aa-enforce "/etc/apparmor.d/$profile_name" 2>/dev/null && \
                log_action SUCCESS "Extra profile loaded: $profile_name" || \
                log_action INFO "Could not load extra profile: $profile_name"
            fi
        done
    fi
    
    # Ensure AppArmor is enabled in kernel
    if [[ -f /sys/kernel/security/apparmor/profiles ]]; then
        profile_count=$(wc -l < /sys/kernel/security/apparmor/profiles)
        log_action SUCCESS "AppArmor active with $profile_count profiles loaded"
    fi
    
    # Add AppArmor parameters to kernel cmdline if not present
    if [[ -f /etc/default/grub ]]; then
        if ! grep -q "apparmor=1" /etc/default/grub; then
            cp /etc/default/grub "$BACKUP_DIR/grub.backup.apparmor" 2>/dev/null || true
            sed -i 's/GRUB_CMDLINE_LINUX_DEFAULT="/GRUB_CMDLINE_LINUX_DEFAULT="apparmor=1 security=apparmor /' /etc/default/grub
            log_action SUCCESS "AppArmor kernel parameters added (requires update-grub and reboot)"
        fi
    fi
else
    log_action WARNING "AppArmor not installed - this is a critical security component for HARDN"
    log_action INFO "Install with: apt-get install apparmor apparmor-utils apparmor-profiles"
fi

# ═══════════════════════════════════════════════════════════════════
# SECURE MOUNT OPTIONS
# ═══════════════════════════════════════════════════════════════════
log_action SECTION "Filesystem Mount Security"

# Backup fstab
cp /etc/fstab "$BACKUP_DIR/fstab.backup" 2>/dev/null || true

# Function to add mount options
secure_mount() {
    local mount_point=$1
    local options=$2
    
    if mountpoint -q "$mount_point" 2>/dev/null; then
        if ! grep -q "$mount_point" /etc/fstab; then
            echo "tmpfs $mount_point tmpfs $options 0 0" >> /etc/fstab
            log_action SUCCESS "Secured mount point: $mount_point"
        else
            log_action INFO "Mount point already in fstab: $mount_point"
        fi
    fi
}

# Secure various mount points
secure_mount "/tmp" "defaults,nosuid,nodev,noexec,mode=1777"
secure_mount "/var/tmp" "defaults,nosuid,nodev,noexec,mode=1777"
secure_mount "/dev/shm" "defaults,nosuid,nodev,noexec"

# Add nodev to /home if it exists as separate partition
if mountpoint -q /home; then
    sed -i '/\/home/ s/defaults/defaults,nodev/' /etc/fstab 2>/dev/null || true
    log_action SUCCESS "Added nodev option to /home"
fi

# ═══════════════════════════════════════════════════════════════════
# SYSTEMD HARDENING
# ═══════════════════════════════════════════════════════════════════
log_action SECTION "Systemd Service Hardening"

# Create systemd hardening drop-in directory
mkdir -p /etc/systemd/system/sshd.service.d/

# SSH service hardening
cat > /etc/systemd/system/sshd.service.d/hardening.conf << 'EOF'
[Service]
# Security Hardening
PrivateTmp=yes
NoNewPrivileges=yes
PrivateDevices=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/log/
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
RestrictNamespaces=yes
EOF

systemctl daemon-reload
log_action SUCCESS "Systemd service hardening applied"

# ═══════════════════════════════════════════════════════════════════
# FILE INTEGRITY MONITORING
# ═══════════════════════════════════════════════════════════════════
log_action SECTION "File Integrity Monitoring"

# AIDE Configuration (if installed)
if command -v aide >/dev/null 2>&1; then
    # Create AIDE configuration
    cat > /etc/aide/aide.conf.d/99_hardn << 'EOF'
# HARDN AIDE Configuration

# Custom rules for monitoring
NORMAL = p+i+n+u+g+s+m+S+c+md5+sha256
PERMS = p+u+g
DATAONLY = p+n+u+g+s+m+S+md5+sha256

# Critical system files
/boot NORMAL
/etc NORMAL
!/etc/mtab
/bin NORMAL
/sbin NORMAL
/lib NORMAL
/lib64 NORMAL
/usr/bin NORMAL
/usr/sbin NORMAL
/usr/lib NORMAL
/usr/lib64 NORMAL

# Security-sensitive files
/etc/passwd NORMAL
/etc/shadow NORMAL
/etc/group NORMAL
/etc/gshadow NORMAL
/etc/ssh/sshd_config NORMAL
/etc/sudoers NORMAL
/etc/pam.d NORMAL

# Log files (size/time can change)
/var/log DATAONLY
!/var/log/journal
!/var/log/lastlog
EOF
    
    # Initialize AIDE database
    aideinit -y -f 2>/dev/null && \
        log_action SUCCESS "AIDE file integrity monitoring configured" || \
        log_action WARNING "AIDE initialization failed"
else
    log_action INFO "AIDE not installed - skipping file integrity setup"
fi

# ═══════════════════════════════════════════════════════════════════
# LOGGING ENHANCEMENTS
# ═══════════════════════════════════════════════════════════════════
log_action SECTION "Enhanced Logging Configuration"

# Configure rsyslog for security events
if [[ -f /etc/rsyslog.conf ]]; then
    cat > /etc/rsyslog.d/99-hardn-security.conf << 'EOF'
# HARDN Security Logging Configuration

# Log authentication messages
auth,authpriv.*                 /var/log/auth.log

# Log sudo commands
:programname, isequal, "sudo"   /var/log/sudo.log
& stop

# Log kernel messages
kern.*                           /var/log/kern.log

# Log security events
*.emerg                          /var/log/emergency.log
*.alert                          /var/log/alert.log
*.crit                           /var/log/critical.log

# Remote logging (uncomment and configure if needed)
# *.* @@remote-syslog-server:514
EOF
    
    systemctl restart rsyslog 2>/dev/null && \
        log_action SUCCESS "Enhanced logging configuration applied" || \
        log_action WARNING "Could not restart rsyslog"
fi

# Configure log rotation
cat > /etc/logrotate.d/hardn-security << 'EOF'
/var/log/auth.log
/var/log/sudo.log
/var/log/kern.log
/var/log/emergency.log
/var/log/alert.log
/var/log/critical.log
{
    daily
    rotate 90
    compress
    delaycompress
    missingok
    notifempty
    create 0600 root root
}
EOF

log_action SUCCESS "Log rotation configured for security logs"

# ═══════════════════════════════════════════════════════════════════
# GRUB BOOTLOADER SECURITY
# ═══════════════════════════════════════════════════════════════════
log_action SECTION "Bootloader Security"

# Backup GRUB config
cp /etc/default/grub "$BACKUP_DIR/grub.backup" 2>/dev/null || true

# Add security parameters to GRUB
if [[ -f /etc/default/grub ]]; then
    # Add kernel security parameters
    if ! grep -q "slab_nomerge" /etc/default/grub; then
        sed -i 's/GRUB_CMDLINE_LINUX_DEFAULT="/GRUB_CMDLINE_LINUX_DEFAULT="slab_nomerge slub_debug=FZP page_poison=1 pti=on /' /etc/default/grub
        
        # Additional mitigations
        sed -i 's/GRUB_CMDLINE_LINUX="/GRUB_CMDLINE_LINUX="spec_store_bypass_disable=seccomp spectre_v2=on /' /etc/default/grub
        
        log_action SUCCESS "GRUB security parameters added"
    else
        log_action INFO "GRUB already hardened"
    fi
fi

# ═══════════════════════════════════════════════════════════════════
# USER ENVIRONMENT HARDENING
# ═══════════════════════════════════════════════════════════════════
log_action SECTION "User Environment Security"

# Set secure defaults for new users
cat > /etc/skel/.bashrc_hardn << 'EOF'
# HARDN Security Settings for Users

# Secure umask
umask 077

# Logout on idle
TMOUT=900
readonly TMOUT
export TMOUT

# History security
HISTSIZE=1000
HISTFILESIZE=2000
HISTCONTROL=ignoreboth:erasedups
shopt -s histappend

# Disable core dumps
ulimit -c 0

# Aliases for security
alias rm='rm -i'
alias cp='cp -i'
alias mv='mv -i'
EOF

# Apply to existing users
for home in /home/*; do
    if [[ -d "$home" ]]; then
        username=$(basename "$home")
        if id "$username" >/dev/null 2>&1; then
            cp /etc/skel/.bashrc_hardn "$home/.bashrc_hardn" 2>/dev/null
            chown "$username:$username" "$home/.bashrc_hardn" 2>/dev/null
            echo "source ~/.bashrc_hardn" >> "$home/.bashrc" 2>/dev/null
        fi
    fi
done

log_action SUCCESS "User environment hardening applied"

# ═══════════════════════════════════════════════════════════════════
# CRON SECURITY
# ═══════════════════════════════════════════════════════════════════
log_action SECTION "Cron Job Security"

# Restrict cron to authorized users
if [[ ! -f /etc/cron.allow ]]; then
    echo "root" > /etc/cron.allow
    chmod 600 /etc/cron.allow
    log_action SUCCESS "Cron restricted to authorized users only"
fi

# Remove cron.deny if exists
if [[ -f /etc/cron.deny ]]; then
    rm /etc/cron.deny
    log_action SUCCESS "Removed cron.deny file"
fi

# Restrict at daemon
if [[ ! -f /etc/at.allow ]]; then
    echo "root" > /etc/at.allow
    chmod 600 /etc/at.allow
    log_action SUCCESS "At daemon restricted to root only"
fi

# ═══════════════════════════════════════════════════════════════════
# DISABLE UNUSED FILESYSTEMS
# ═══════════════════════════════════════════════════════════════════
log_action SECTION "Filesystem Security"

# Create modprobe configuration for unused filesystems
cat > /etc/modprobe.d/hardn-filesystems.conf << 'EOF'
# HARDN - Disable unused filesystems
install vfat /bin/true
install msdos /bin/true
install iso9660 /bin/true
install udf /bin/true
install cifs /bin/true
install nfs /bin/true
install nfsv3 /bin/true
install nfsv4 /bin/true
install gfs2 /bin/true
EOF

log_action SUCCESS "Unused filesystems disabled"

# ═══════════════════════════════════════════════════════════════════
# COREDUMP CONFIGURATION
# ═══════════════════════════════════════════════════════════════════
log_action SECTION "Core Dump Security"

# Disable core dumps system-wide
cat > /etc/security/limits.d/99-hardn-coredump.conf << 'EOF'
# Disable core dumps
* soft core 0
* hard core 0
EOF

# Disable via sysctl
echo "kernel.core_pattern=|/bin/false" > /etc/sysctl.d/50-coredump.conf
sysctl -p /etc/sysctl.d/50-coredump.conf >/dev/null 2>&1

# Disable systemd coredump
if [[ -f /etc/systemd/coredump.conf ]]; then
    sed -i 's/#Storage=.*/Storage=none/' /etc/systemd/coredump.conf
    sed -i 's/#ProcessSizeMax=.*/ProcessSizeMax=0/' /etc/systemd/coredump.conf
fi

log_action SUCCESS "Core dumps disabled system-wide"

# ═══════════════════════════════════════════════════════════════════
# FINAL SUMMARY
# ═══════════════════════════════════════════════════════════════════
log_action SECTION "Advanced Hardening Complete"

echo ""
echo -e "${GREEN}╔═══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║         HARDN Advanced Security Hardening Summary            ║${NC}"
echo -e "${GREEN}╠═══════════════════════════════════════════════════════════════╣${NC}"
echo -e "${GREEN}║${NC} Total Security Improvements: ${WHITE}$IMPROVEMENTS${NC}"
echo -e "${GREEN}║${NC} Backup Location: ${WHITE}$BACKUP_DIR${NC}"
echo -e "${GREEN}║${NC} Log File: ${WHITE}$LOG_FILE${NC}"
echo -e "${GREEN}╚═══════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${YELLOW}Important Actions Required:${NC}"
echo ""
echo "1. ${CYAN}Update GRUB:${NC}"
echo "   sudo update-grub"
echo ""
echo "2. ${CYAN}Reboot the system:${NC}"
echo "   sudo reboot"
echo ""
echo "3. ${CYAN}After reboot, run Lynis:${NC}"
echo "   sudo lynis audit system --quick"
echo ""
echo "4. ${CYAN}Check the hardening score:${NC}"
echo "   sudo lynis show report | grep 'Hardening index'"
echo ""
echo -e "${MAGENTA}Security Notes:${NC}"
echo "• Some services may need reconfiguration after these changes"
echo "• Review logs in $LOG_FILE for any warnings"
echo "• Test SSH access before closing current session"
echo "• Consider creating system restore point before production use"
echo ""
echo -e "${GREEN}Your system hardening is now at maximum level!${NC}"