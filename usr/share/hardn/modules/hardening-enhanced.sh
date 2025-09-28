#!/bin/bash
# HARDN Enhanced Security Hardening Module
# Advanced system hardening for improved Lynis compliance score

set -euo pipefail

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo "HARDN Enhanced Security Hardening Module"
echo "========================================="
echo ""

# Function to log actions with color
log_action() {
    echo -e "${GREEN}[$(date '+%Y-%m-%d %H:%M:%S')]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   log_error "This script must be run as root"
   exit 1
fi

# ==========================================
# 1. AUTHENTICATION AND PAM HARDENING
# ==========================================
log_action "Configuring PAM and authentication hardening..."

# Configure password quality requirements (addresses AUTH-9262)
if [ -f /etc/security/pwquality.conf ]; then
    cat > /etc/security/pwquality.conf <<EOF
# Enhanced password policy by HARDN
minlen = 14
minclass = 3
maxrepeat = 3
maxsequence = 3
ucredit = -1
lcredit = -1
dcredit = -1
ocredit = -1
difok = 8
gecoscheck = 1
dictcheck = 1
usercheck = 1
enforcing = 1
retry = 3
enforce_for_root
EOF
    log_action "Password quality requirements configured"
fi

# Configure login.defs for password aging (addresses AUTH-9286)
if [ -f /etc/login.defs ]; then
    sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/' /etc/login.defs
    sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   1/' /etc/login.defs
    sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE   14/' /etc/login.defs
    
    # Set secure umask
    sed -i 's/^UMASK.*/UMASK           027/' /etc/login.defs
    
    # Set minimum UID for regular users
    sed -i 's/^UID_MIN.*/UID_MIN          1000/' /etc/login.defs
    
    # Enable SHA512 for password hashing
    sed -i 's/^ENCRYPT_METHOD.*/ENCRYPT_METHOD SHA512/' /etc/login.defs
    
    log_action "Login.defs configured for password aging and security"
fi

# Configure account lockout policy (addresses AUTH-9328)
if [ -f /etc/pam.d/common-auth ]; then
    if ! grep -q "pam_tally2" /etc/pam.d/common-auth 2>/dev/null; then
        # Add account lockout after 5 failed attempts
        sed -i '1 a\auth required pam_tally2.so onerr=fail audit silent deny=5 unlock_time=900' /etc/pam.d/common-auth
    fi
    log_action "Account lockout policy configured"
fi

# Configure su access restriction (addresses AUTH-9218)
if [ -f /etc/pam.d/su ]; then
    if ! grep -q "pam_wheel.so" /etc/pam.d/su; then
        echo "auth required pam_wheel.so use_uid group=sudo" >> /etc/pam.d/su
    fi
    log_action "Su access restricted to sudo group"
fi

# ==========================================
# 2. SSH HARDENING (Comprehensive)
# ==========================================
log_action "Applying comprehensive SSH hardening..."

if [ -f /etc/ssh/sshd_config ]; then
    # Backup original config
    cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak.$(date +%Y%m%d)
    
    # Apply hardened SSH configuration
    cat > /etc/ssh/sshd_config.d/99-hardn-hardened.conf <<EOF
# HARDN Enhanced SSH Configuration
# Generated: $(date)

# Authentication
PermitRootLogin no
PubkeyAuthentication yes
PasswordAuthentication no
PermitEmptyPasswords no
ChallengeResponseAuthentication no
MaxAuthTries 3
MaxSessions 10

# Security
Protocol 2
StrictModes yes
IgnoreRhosts yes
HostbasedAuthentication no
X11Forwarding no
PermitUserEnvironment no
AllowAgentForwarding no
AllowTcpForwarding no
PermitTunnel no

# Crypto settings (addresses SSH-7408)
Ciphers chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com
MACs umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group-exchange-sha256

# Logging
LogLevel VERBOSE
SyslogFacility AUTH

# Session
ClientAliveInterval 300
ClientAliveCountMax 2
MaxStartups 10:30:60
LoginGraceTime 60

# Banner
Banner /etc/ssh/sshd_banner
EOF
    
    # Create SSH banner
    cat > /etc/ssh/sshd_banner <<EOF
***************************************************************************
                            NOTICE TO USERS

This computer system is for authorized use only. Users have no explicit or 
implicit expectation of privacy. Any or all uses of this system and all 
files on this system may be intercepted, monitored, recorded, copied, 
audited, inspected, and disclosed to authorized personnel.

By using this system, the user consents to such interception, monitoring,
recording, copying, auditing, inspection, and disclosure at the discretion
of authorized personnel.

Unauthorized or improper use of this system may result in administrative
disciplinary action and civil and criminal penalties. By continuing to use
this system you indicate your awareness of and consent to these terms and
conditions of use.

LOG OFF IMMEDIATELY if you do not agree to the conditions stated in this warning.
***************************************************************************
EOF
    
    systemctl reload sshd || service ssh reload || true
    log_action "SSH configuration hardened"
fi

# ==========================================
# 3. FILE PERMISSIONS AND OWNERSHIP
# ==========================================
log_action "Setting secure file permissions and ownership..."

# Critical system files (addresses FILE-6310, FILE-6430)
declare -A file_perms=(
    ["/etc/passwd"]="644:root:root"
    ["/etc/shadow"]="640:root:shadow"
    ["/etc/group"]="644:root:root"
    ["/etc/gshadow"]="640:root:shadow"
    ["/etc/passwd-"]="600:root:root"
    ["/etc/shadow-"]="600:root:root"
    ["/etc/group-"]="600:root:root"
    ["/etc/gshadow-"]="600:root:root"
    ["/etc/ssh/sshd_config"]="600:root:root"
    ["/boot/grub/grub.cfg"]="400:root:root"
    ["/etc/crontab"]="600:root:root"
    ["/etc/cron.d"]="700:root:root"
    ["/etc/cron.daily"]="700:root:root"
    ["/etc/cron.hourly"]="700:root:root"
    ["/etc/cron.weekly"]="700:root:root"
    ["/etc/cron.monthly"]="700:root:root"
)

for file in "${!file_perms[@]}"; do
    if [ -e "$file" ]; then
        IFS=':' read -r perms owner group <<< "${file_perms[$file]}"
        chmod "$perms" "$file" 2>/dev/null || true
        chown "$owner:$group" "$file" 2>/dev/null || true
    fi
done

log_action "File permissions secured"

# ==========================================
# 4. KERNEL HARDENING (Comprehensive)
# ==========================================
log_action "Applying comprehensive kernel hardening..."

cat > /etc/sysctl.d/99-hardn-hardening.conf <<EOF
# HARDN Enhanced Kernel Security Parameters
# Generated: $(date)

# Network Security
net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.tcp_syncookies = 1
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.default.accept_ra = 0

# Kernel Security
kernel.randomize_va_space = 2
fs.suid_dumpable = 0
kernel.exec-shield = 1
kernel.panic = 60
kernel.panic_on_oops = 1
kernel.sysrq = 0
kernel.core_uses_pid = 1
kernel.kptr_restrict = 2
kernel.yama.ptrace_scope = 1
kernel.dmesg_restrict = 1
kernel.unprivileged_userns_clone = 0
kernel.unprivileged_bpf_disabled = 1
net.core.bpf_jit_harden = 2

# File System Security
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.protected_fifos = 2
fs.protected_regular = 2

# Process Security
kernel.pid_max = 65536
kernel.modules_disabled = 0
kernel.perf_event_paranoid = 3
EOF

sysctl -p /etc/sysctl.d/99-hardn-hardening.conf 2>/dev/null || log_warning "Some sysctl settings failed to apply"

# ==========================================
# 5. DISABLE UNNECESSARY SERVICES
# ==========================================
log_action "Disabling unnecessary services..."

# List of services to disable (addresses BOOT-5122, BOOT-5260)
unnecessary_services=(
    "bluetooth"
    "cups"
    "avahi-daemon"
    "rpcbind"
    "nfs-client"
    "nfs-server"
    "snmpd"
    "telnet"
    "vsftpd"
    "xinetd"
    "nis"
    "rsh"
    "talk"
    "ntalk"
    "rdisk"
)

for service in "${unnecessary_services[@]}"; do
    if systemctl list-unit-files | grep -q "^$service"; then
        systemctl disable --now "$service" 2>/dev/null || true
        log_action "Disabled service: $service"
    fi
done

# ==========================================
# 6. MOUNT OPTIONS HARDENING
# ==========================================
log_action "Configuring secure mount options..."

# Add nodev,nosuid,noexec to /tmp if it's a separate partition
if mount | grep -q " /tmp "; then
    mount -o remount,nodev,nosuid,noexec /tmp 2>/dev/null || log_warning "Failed to remount /tmp"
fi

# Add nodev to /home if it's a separate partition
if mount | grep -q " /home "; then
    mount -o remount,nodev /home 2>/dev/null || log_warning "Failed to remount /home"
fi

# Create /etc/modprobe.d/hardn-blacklist.conf
cat > /etc/modprobe.d/hardn-blacklist.conf <<EOF
# HARDN: Disable rarely used filesystems and protocols
install dccp /bin/false
install sctp /bin/false
install rds /bin/false
install tipc /bin/false
install cramfs /bin/false
install freevxfs /bin/false
install jffs2 /bin/false
install hfs /bin/false
install hfsplus /bin/false
install udf /bin/false
install vfat /bin/false
# Disable USB storage if not needed
# install usb-storage /bin/false
EOF

# ==========================================
# 7. AUDIT RULES (Enhanced)
# ==========================================
log_action "Configuring enhanced audit rules..."

if command -v auditctl >/dev/null 2>&1; then
    cat > /etc/audit/rules.d/99-hardn-hardening.rules <<EOF
# HARDN Enhanced Audit Rules
# Delete all rules
-D

# Buffer Size
-b 8192

# Failure Mode
-f 1

# Monitor authentication events
-w /var/log/faillog -p wa -k auth_failures
-w /var/log/lastlog -p wa -k logins
-w /var/log/tallylog -p wa -k logins

# Monitor user/group changes
-w /etc/group -p wa -k identity
-w /etc/passwd -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity

# Monitor sudoers
-w /etc/sudoers -p wa -k sudoers
-w /etc/sudoers.d/ -p wa -k sudoers

# Monitor SSH configuration
-w /etc/ssh/sshd_config -p wa -k sshd_config

# Monitor system calls
-a always,exit -F arch=b64 -S execve -F success=1 -k execve
-a always,exit -F arch=b64 -S socket -F success=1 -k socket
-a always,exit -F arch=b64 -S connect -F success=1 -k connect

# Monitor privileged commands
-a always,exit -F path=/usr/bin/passwd -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged

# Make configuration immutable
-e 2
EOF
    
    # Reload audit rules
    augenrules --load 2>/dev/null || true
    systemctl restart auditd 2>/dev/null || true
    log_action "Audit rules configured"
fi

# ==========================================
# 8. FIREWALL HARDENING
# ==========================================
log_action "Configuring firewall with strict rules..."

if command -v ufw >/dev/null 2>&1; then
    # Reset UFW to defaults
    ufw --force disable
    ufw --force reset
    
    # Default policies
    ufw default deny incoming
    ufw default allow outgoing
    ufw default deny routed
    
    # Allow SSH (rate limited)
    ufw limit ssh/tcp comment 'SSH rate limit'
    
    # Allow DNS
    ufw allow out 53 comment 'DNS'
    
    # Allow HTTP/HTTPS out
    ufw allow out 80/tcp comment 'HTTP'
    ufw allow out 443/tcp comment 'HTTPS'
    
    # Allow NTP
    ufw allow out 123/udp comment 'NTP'
    
    # Enable UFW
    ufw --force enable
    log_action "UFW firewall configured with strict rules"
fi

# ==========================================
# 9. LOGROTATE CONFIGURATION
# ==========================================
log_action "Configuring log rotation..."

cat > /etc/logrotate.d/hardn <<EOF
# HARDN log rotation configuration
/var/log/hardn/*.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    create 0640 root adm
}

/var/log/audit/audit.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    create 0600 root root
    postrotate
        /usr/sbin/service auditd rotate
    endscript
}
EOF

# ==========================================
# 10. CORE DUMP RESTRICTIONS
# ==========================================
log_action "Restricting core dumps..."

echo "* hard core 0" >> /etc/security/limits.conf
echo "fs.suid_dumpable = 0" >> /etc/sysctl.conf
sysctl -w fs.suid_dumpable=0 2>/dev/null || true

# Disable core dumps in systemd
if [ -d /etc/systemd/coredump.conf.d ]; then
    cat > /etc/systemd/coredump.conf.d/99-hardn-disable.conf <<EOF
[Coredump]
Storage=none
ProcessSizeMax=0
EOF
fi

# ==========================================
# 11. APPARMOR PROFILES
# ==========================================
log_action "Enabling AppArmor profiles..."

if command -v aa-enforce >/dev/null 2>&1; then
    # Install apparmor-profiles if not present
    apt-get install -y apparmor-profiles apparmor-utils 2>/dev/null || true
    
    # Enforce all profiles
    aa-enforce /etc/apparmor.d/* 2>/dev/null || log_warning "Some AppArmor profiles failed to enforce"
fi

# ==========================================
# 12. COMPILER RESTRICTIONS
# ==========================================
log_action "Restricting compiler access..."

compilers=("/usr/bin/gcc" "/usr/bin/g++" "/usr/bin/as" "/usr/bin/cc")
for compiler in "${compilers[@]}"; do
    if [ -f "$compiler" ]; then
        chmod 750 "$compiler" 2>/dev/null || true
        chown root:adm "$compiler" 2>/dev/null || true
    fi
done

# ==========================================
# 13. NETWORK PARAMETER TUNING
# ==========================================
log_action "Tuning network parameters..."

cat >> /etc/sysctl.d/99-hardn-network-tuning.conf <<EOF
# Network performance and security tuning
net.core.netdev_max_backlog = 5000
net.ipv4.tcp_max_syn_backlog = 4096
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 3
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_keepalive_time = 300
net.ipv4.tcp_keepalive_probes = 5
net.ipv4.tcp_keepalive_intvl = 15
net.ipv4.tcp_timestamps = 1
net.ipv4.tcp_sack = 1
net.ipv4.tcp_fack = 1
net.ipv4.tcp_congestion_control = htcp
net.ipv4.tcp_no_metrics_save = 1
EOF

sysctl -p /etc/sysctl.d/99-hardn-network-tuning.conf 2>/dev/null || true

# ==========================================
# 14. SUMMARY REPORT
# ==========================================
echo ""
echo "========================================="
echo -e "${GREEN}HARDN Enhanced Hardening Complete!${NC}"
echo "========================================="
echo ""
echo "Applied hardening measures:"
echo "  ✓ PAM and authentication hardening"
echo "  ✓ Comprehensive SSH configuration"
echo "  ✓ Secure file permissions"
echo "  ✓ Kernel security parameters"
echo "  ✓ Disabled unnecessary services"
echo "  ✓ Secure mount options"
echo "  ✓ Enhanced audit rules"
echo "  ✓ Strict firewall configuration"
echo "  ✓ Log rotation configured"
echo "  ✓ Core dumps disabled"
echo "  ✓ AppArmor profiles enforced"
echo "  ✓ Compiler access restricted"
echo "  ✓ Network parameters tuned"
echo ""
echo -e "${YELLOW}Note:${NC} System reboot recommended for all changes to take effect."
echo -e "${YELLOW}Note:${NC} Run 'lynis audit system' to verify improvements."
echo ""

log_action "Enhanced hardening module completed successfully!"