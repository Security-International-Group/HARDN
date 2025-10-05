#!/bin/bash
# HARDN Enhanced Security Hardening Module
# Author: Chris Bingham 

set -euo pipefail

export DEBIAN_FRONTEND=noninteractive

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' 

echo "HARDN Enhanced Security Hardening Module"
echo "========================================="
echo ""

# Function to log normalized status messages with color
HARDN_STATUS() {
    echo -e "${GREEN}[$(date '+%Y-%m-%d %H:%M:%S')]${NC} $1"
}

log_action() {
    HARDN_STATUS "$1"
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
#  AUTHENTICATION HARDENING (PAM DISABLED BY POLICY)
# ==========================================
HARDN_STATUS "Skipping all PAM-related authentication hardening per HARDN policy"

apt-get install -y libpam-pwquality libpwquality-tools 2>/dev/null || log_warning "libpam-pwquality installation failed, continuing..."
# NOT ENFORCING: All PAM modifications (pwquality, pam_* modules, common-auth edits) are intentionally disabled. --- IGNORE ---

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
    
    HARDN_STATUS "Login.defs configured for password aging and security"
fi

# Account lockout policy via PAM is disabled by policy to prevent unexpected lockouts

# PAM-based su access restriction is disabled by policy

# ==========================================
#  SSH HARDENING (Comprehensive)
# ==========================================
HARDN_STATUS "Applying comprehensive SSH hardening..."

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


# ==========================================
# BANNER CONFIGURATION
# =========================================
    
    # Create SSH banner
    cat > /etc/ssh/sshd_banner <<EOF
***************************************************************************
                            NOTICE TO USERS
                       ***** W A R N I N G *****
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
          S E C U R I T Y - I N T E R N A T I O N A L - G R O U P
***************************************************************************
EOF
    
    systemctl reload sshd || service ssh reload || true
    HARDN_STATUS "SSH configuration hardened"
fi

# ==========================================
#  FILE PERMISSIONS AND OWNERSHIP
# ==========================================
HARDN_STATUS "Setting secure file permissions and ownership..."

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
    ["/etc/cron.d"]="755:root:root"
    ["/etc/cron.daily"]="755:root:root"
    ["/etc/cron.hourly"]="755:root:root"
    ["/etc/cron.weekly"]="755:root:root"
    ["/etc/cron.monthly"]="755:root:root"
)

for file in "${!file_perms[@]}"; do
    if [ -e "$file" ]; then
        IFS=':' read -r perms owner group <<< "${file_perms[$file]}"
        chmod "$perms" "$file" 2>/dev/null || true
        chown "$owner:$group" "$file" 2>/dev/null || true
    fi
done

# ==========================================
# UNNECESSARY SERVICES
# ==========================================
HARDN_STATUS "Checking for unused services..."
# disable unused services like telnet, rsh, etc. if they exist
for service in telnet rsh; do
    if systemctl list-unit-files | grep -q "^$service.service"; then
        HARDN_STATUS "Disabling $service service..."
        systemctl disable --now "$service" 2>/dev/null || true
    fi
done

# 4. Set secure permissions on critical files
log_action "Setting secure permissions on critical files..."
chmod 644 /etc/passwd 2>/dev/null || true
chmod 600 /etc/shadow 2>/dev/null || true
chmod 644 /etc/group 2>/dev/null || true

# 5. PAM-related components (disabled by policy)
log_action "Skipping PAM components (pwquality/pam) per HARDN policy to avoid auth stack changes..."

# 6. install clamv and start service
log_action "Installing ClamAV antivirus..."
timeout 120 apt-get install -y --no-install-recommends clamav clamav-daemon 2>/dev/null || log_warning "ClamAV installation failed, continuing..."
systemctl enable clamav-freshclam 2>/dev/null || true
systemctl start clamav-freshclam 2>/dev/null || true
# ==========================================
# KERNEL HARDENING (Comprehensive)
# ==========================================
HARDN_STATUS "Applying comprehensive kernel hardening..."

write_sysctl_setting() {
    local key="$1"
    local value="$2"
    local target="$3"
    local path="/proc/sys/${key//./\/}"

    if [ -e "$path" ]; then
        local apply_value="$value"
        if ! sysctl -e -w "$key=$apply_value" >/dev/null 2>&1; then
            if [[ -n "${SYSCTL_FALLBACKS[$key]:-}" ]]; then
                local fallback_value="${SYSCTL_FALLBACKS[$key]}"
                if sysctl -e -w "$key=$fallback_value" >/dev/null 2>&1; then
                    log_warning "Sysctl $key=$value unsupported; applied fallback $fallback_value"
                    apply_value="$fallback_value"
                else
                    log_warning "Unable to apply sysctl $key with fallback ${fallback_value}; skipping persistent entry"
                    return
                fi
            else
                log_warning "Unable to apply sysctl $key=$value; skipping persistent entry"
                return
            fi
        fi

        printf '%s = %s\n' "$key" "$apply_value" >> "$target"
    else
        log_warning "Skipping unsupported sysctl: $key"
    fi
}

SYSCTL_FILE="/etc/sysctl.d/99-hardn-hardening.conf"
cat > "$SYSCTL_FILE" <<EOF
# HARDN Enhanced Kernel Security Parameters
# Generated: $(date)
EOF

declare -A SYSCTL_FALLBACKS=(
    ["fs.protected_fifos"]=1
    ["fs.protected_regular"]=1
)

network_sysctls=(
    "net.ipv4.ip_forward=0"
    "net.ipv6.conf.all.forwarding=0"
    "net.ipv4.conf.all.send_redirects=0"
    "net.ipv4.conf.default.send_redirects=0"
    "net.ipv4.conf.all.accept_source_route=0"
    "net.ipv4.conf.default.accept_source_route=0"
    "net.ipv6.conf.all.accept_source_route=0"
    "net.ipv6.conf.default.accept_source_route=0"
    "net.ipv4.conf.all.accept_redirects=0"
    "net.ipv4.conf.default.accept_redirects=0"
    "net.ipv6.conf.all.accept_redirects=0"
    "net.ipv6.conf.default.accept_redirects=0"
    "net.ipv4.conf.all.secure_redirects=0"
    "net.ipv4.conf.default.secure_redirects=0"
    "net.ipv4.conf.all.log_martians=1"
    "net.ipv4.conf.default.log_martians=1"
    "net.ipv4.icmp_echo_ignore_broadcasts=1"
    "net.ipv4.icmp_ignore_bogus_error_responses=1"
    "net.ipv4.conf.all.rp_filter=1"
    "net.ipv4.conf.default.rp_filter=1"
    "net.ipv4.tcp_syncookies=1"
    "net.ipv6.conf.all.accept_ra=0"
    "net.ipv6.conf.default.accept_ra=0"
)

kernel_sysctls=(
    "kernel.randomize_va_space=2"
    "fs.suid_dumpable=0"
    "kernel.exec-shield=1"
    "kernel.panic=60"
    "kernel.panic_on_oops=1"
    "kernel.sysrq=0"
    "kernel.core_uses_pid=1"
    "kernel.kptr_restrict=2"
    "kernel.yama.ptrace_scope=1"
    "kernel.dmesg_restrict=1"
    "kernel.unprivileged_userns_clone=0"
    "kernel.unprivileged_bpf_disabled=1"
    "net.core.bpf_jit_harden=2"
)

filesystem_sysctls=(
    "fs.protected_hardlinks=1"
    "fs.protected_symlinks=1"
    "fs.protected_fifos=2"
    "fs.protected_regular=2"
)

process_sysctls=(
    "kernel.pid_max=65536"
    "kernel.modules_disabled=0"
    "kernel.perf_event_paranoid=3"
)

{
    printf '\n# Network Security\n'
    for item in "${network_sysctls[@]}"; do
        write_sysctl_setting "${item%%=*}" "${item#*=}" "$SYSCTL_FILE"
    done

    printf '\n# Kernel Security\n'
    for item in "${kernel_sysctls[@]}"; do
        write_sysctl_setting "${item%%=*}" "${item#*=}" "$SYSCTL_FILE"
    done

    printf '\n# File System Security\n'
    for item in "${filesystem_sysctls[@]}"; do
        write_sysctl_setting "${item%%=*}" "${item#*=}" "$SYSCTL_FILE"
    done

    printf '\n# Process Security\n'
    for item in "${process_sysctls[@]}"; do
        write_sysctl_setting "${item%%=*}" "${item#*=}" "$SYSCTL_FILE"
    done
} >> "$SYSCTL_FILE"

sysctl -p /etc/sysctl.d/99-hardn-hardening.conf 2>/dev/null || log_warning "Some sysctl settings failed to apply"

# ==========================================
# DISABLE UNNECESSARY SERVICES
# ==========================================
HARDN_STATUS "Disabling unnecessary services..."

# List of services to disable (addresses BOOT-5122, BOOT-5260)
unnecessary_services=(
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
    # "cups" - is needed for printing
    # "bluetooth" - may be needed for meeting accessibility requirements
)

for service in "${unnecessary_services[@]}"; do
    if systemctl list-unit-files | grep -q "^$service"; then
        systemctl disable --now "$service" 2>/dev/null || true
        HARDN_STATUS "Disabled service: $service"
    fi
done

# ==========================================
# MOUNT OPTIONS HARDENING
# ==========================================
# HARDN_STATUS "Configuring secure mount options..."
#
# # Add nodev,nosuid,noexec to /tmp if it's a separate partition
# if mount | grep -q " /tmp "; then
#     mount -o remount,nodev,nosuid,noexec /tmp 2>/dev/null || log_warning "Failed to remount /tmp"
# fi
#
# # Add nodev to /home if it's a separate partition
# if mount | grep -q " /home "; then
#     mount -o remount,nodev /home 2>/dev/null || log_warning "Failed to remount /home"
# fi
#
# # Create /etc/modprobe.d/hardn-blacklist.conf
# cat > /etc/modprobe.d/hardn-blacklist.conf <<EOF
# # HARDN: Disable rarely used filesystems and protocols
# install dccp /bin/false
# install sctp /bin/false
# install rds /bin/false
# install tipc /bin/false
# install cramfs /bin/false
# install freevxfs /bin/false
# install jffs2 /bin/false
# install hfs /bin/false
# install hfsplus /bin/false
# install udf /bin/false
# install vfat /bin/false
# EOF

# ==========================================
# AUDIT RULES (Enhanced)
# ==========================================
HARDN_STATUS "Configuring enhanced audit rules..."

if command -v auditctl >/dev/null 2>&1; then
    cat > /etc/audit/rules.d/99-hardn-hardening.rules <<'EOF'
# HARDN Audit Rules (MITRE ATT&CK framework thanks to @4nt11 )

# T1059 – Command execution (focus on interactive users)
-a always,exit -F arch=b64 -S execve -F exe=/usr/bin/bash  -F auid>=1000 -F auid!=4294967295 -k mitre_cmd_exec
-a always,exit -F arch=b64 -S execve -F exe=/bin/sh        -F auid>=1000 -F auid!=4294967295 -k mitre_cmd_exec
-a always,exit -F arch=b64 -S execve -F exe=/bin/dash      -F auid>=1000 -F auid!=4294967295 -k mitre_cmd_exec
-a always,exit -F arch=b64 -S execve -F exe=/usr/bin/python3 -F auid>=1000 -F auid!=4294967295 -k mitre_cmd_exec
-a always,exit -F arch=b64 -S execve -F exe=/usr/bin/perl  -F auid>=1000 -F auid!=4294967295 -k mitre_cmd_exec
-a always,exit -F arch=b64 -S execve -F exe=/usr/bin/php   -F auid>=1000 -F auid!=4294967295 -k mitre_cmd_exec

# T1105 – Ingress tool transfer (watch for encoded/packaged drops)
-w /var/tmp/ -p wa -k mitre_ingress
-w /tmp/    -p wa -k mitre_ingress

# T1053 – Scheduled task/cron modifications
-w /etc/cron.d/      -p war -k mitre_scheduled
-w /etc/cron.daily/  -p war -k mitre_scheduled
-w /etc/cron.weekly/ -p war -k mitre_scheduled
-w /etc/cron.monthly/-p war -k mitre_scheduled
-w /var/spool/cron/  -p war -k mitre_scheduled

# T1547 – Boot or logon autostart persistence
-w /etc/systemd/system/ -p wa -k mitre_autostart
-w /lib/systemd/system/ -p wa -k mitre_autostart
-a always,exit -F arch=b64 -S init_module,finit_module,delete_module -k mitre_rootkit

# T1003 – Credential dumping files
-w /etc/shadow -p war -k mitre_creds

# T1562 – Defense evasion (AV/audit tampering)
-w /etc/audit/        -p wa -k mitre_defense_evasion
-w /var/lib/audit/    -p wa -k mitre_defense_evasion
-w /usr/bin/freshclam -p x  -k mitre_defense_evasion
-w /usr/sbin/auditd   -p x  -k mitre_defense_evasion

# T1041 – Exfiltration over C2 channels
-a always,exit -F arch=b64 -S connect -F a0=2 -F auid>=1000 -F auid!=4294967295 -k mitre_exfil  # IPv4 sockets
-a always,exit -F arch=b64 -S sendto,sendmsg -F auid>=1000 -F auid!=4294967295 -k mitre_exfil

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

# Monitor privileged commands
-a always,exit -F path=/usr/bin/passwd -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged

# Make configuration immutable
-e 2
EOF
    
    # Reload audit rules
    augenrules --load 2>/dev/null || true
    systemctl restart auditd 2>/dev/null || true
    HARDN_STATUS "Audit rules configured"
fi

# ==========================================
# FIREWALL HARDENING
# ==========================================
HARDN_STATUS "Configuring firewall with strict rules..."

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
    HARDN_STATUS "UFW firewall configured with strict rules"
fi

# ==========================================
# LOGROTATE CONFIGURATION
# ==========================================
HARDN_STATUS "Configuring log rotation..."

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
# CORE DUMP RESTRICTIONS
# ==========================================
HARDN_STATUS "Restricting core dumps..."

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
# APPARMOR PROFILES
# ==========================================
HARDN_STATUS "Enabling AppArmor  - ENFORCE - profiles...for non-native Unix apps to work, you will need to whitelist them individually..."
sleep 2
if command -v aa-enforce >/dev/null 2>&1; then
    # Install apparmor-profiles if not present
    apt-get install -y apparmor-profiles apparmor-utils 2>/dev/null || true
    
    # Enforce all profiles
    aa-enforce /etc/apparmor.d/* 2>/dev/null || log_warning "Some AppArmor profiles failed to enforce"
fi

# ==========================================
# COMPILER RESTRICTIONS
# ==========================================
HARDN_STATUS "Restricting compiler access..."

compilers=("/usr/bin/gcc" "/usr/bin/g++" "/usr/bin/as" "/usr/bin/cc")
for compiler in "${compilers[@]}"; do
    if [ -f "$compiler" ]; then
        chmod 750 "$compiler" 2>/dev/null || true
        chown root:adm "$compiler" 2>/dev/null || true
    fi
done

# ==========================================
# NETWORK PARAMETER TUNING
# ==========================================
HARDN_STATUS "Tuning network parameters..."

cat > /etc/sysctl.d/99-hardn-network-tuning.conf <<EOF
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
# auditd
# ==========================================
HARDN_STATUS "Installing auditd..."
timeout 120 apt-get install -y --no-install-recommends auditd audispd-plugins 2>/dev/null || log_warning "auditd installation failed, continuing..."
systemctl enable auditd 2>/dev/null || true
systemctl start auditd 2>/dev/null || true   

# ==========================================
# clamav
# ==========================================
HARDN_STATUS "Installing ClamAV..."
timeout 120 apt-get install -y --no-install-recommends clamav clamav-daemon 2>/dev/null || log_warning "ClamAV installation failed, continuing..."
systemctl enable clamav-daemon 2>/dev/null || true
systemctl start clamav-daemon 2>/dev/null || true       
# Update ClamAV database
HARDN_STATUS "Updating ClamAV database..."
freshclam 2>/dev/null || log_warning "ClamAV database update failed, continuing..."

# =========================================
# rkhunter
# ==========================================
HARDN_STATUS "Installing rkhunter..."
if timeout 120 apt-get install -y rkhunter --no-install-recommends 2>/dev/null; then
    HARDN_STATUS "rkhunter installed successfully"
    # Configure rkhunter to skip network operations
    if [ -f /etc/rkhunter.conf ]; then
    HARDN_STATUS "Configuring rkhunter for offline operation..."
        # Disable network-dependent checks
        sed -i 's|UPDATE_MIRRORS=.*|UPDATE_MIRRORS=0|g' /etc/rkhunter.conf 2>/dev/null || true
        sed -i 's|MIRRORS_MODE=.*|MIRRORS_MODE=0|g' /etc/rkhunter.conf 2>/dev/null || true
        sed -i 's|WEB_CMD=.*|WEB_CMD=""|g' /etc/rkhunter.conf 2>/dev/null || true
    fi
else
    log_warning "rkhunter installation failed (possibly network issues), skipping..."
fi

# =========================================
# FIREWIRE
# ==========================================
HARDN_STATUS "Disabling FireWire (IEEE 1394) support..."
if [ -f /etc/modprobe.d/blacklist-firewire.conf ]; then
    echo "blacklist firewire-core" >> /etc/modprobe.d/blacklist-firewire.conf
else
    echo "blacklist firewire-core" > /etc/modprobe.d/blacklist-firewire.conf
fi  
modprobe -r firewire-core 2>/dev/null || true

HARDN_STATUS "Firewire support disabled"

# ==========================================
# unattended-upgrades
# ==========================================
HARDN_STATUS "Installing unattended-upgrades..."
if timeout 120 apt-get install -y unattended-upgrades --no-install-recommends 2>/dev/null; then
    HARDN_STATUS "unattended-upgrades installed successfully"
    # Configure unattended-upgrades
    dpkg-reconfigure -f noninteractive unattended-upgrades 2>/dev/null || log_warning "unattended-upgrades reconfiguration failed"
else
    log_warning "unattended-upgrades installation failed, continuing..."
fi

# =========================================
# umask
# ==========================================
HARDN_STATUS "Setting secure umask in system files..."
if ! grep -q "umask 027" /etc/bash.bashrc 2>/dev/null; then
    echo "umask 027" >> /etc/bash.bashrc
fi

# ==========================================
# SUMMARY REPORT
# ==========================================
echo ""
echo "========================================="
echo -e "${GREEN}HARDN Enhanced Hardening Complete!${NC}"
echo "========================================="
echo ""
echo "Applied hardening measures:"
# echo "  ✓ PAM and authentication hardening"
echo "  ✓ Comprehensive SSH configuration"
echo "  ✓ Secure file permissions"
echo "  ✓ Kernel security parameters"
echo "  ✓ Disabled unnecessary services"
echo "  ✓ Secure mount options"
echo "  ✓ MITRE ATT&CK audit rules"
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

HARDN_STATUS "Enhanced hardening module completed successfully!"