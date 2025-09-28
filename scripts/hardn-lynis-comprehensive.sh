#!/bin/bash
# HARDN Comprehensive Lynis Hardening Script
# Combines basic and advanced hardening measures for maximum security score
# Test this script ONLY on your Virtual Machine, not on the host!

set -euo pipefail

# ============================================================================
# CONFIGURATION & SETUP
# ============================================================================

# Color codes for output
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
LOG_FILE="/var/log/hardn-comprehensive.log"
SCORE_IMPROVEMENTS=0
TOTAL_FIXES=0

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

# Unified logging function
log_action() {
    local level=$1
    local message=$2
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    case $level in
        SUCCESS)
            echo -e "${GREEN}[✓]${NC} $message"
            echo "[$timestamp] SUCCESS: $message" >> "$LOG_FILE"
            ((SCORE_IMPROVEMENTS++))
            ((TOTAL_FIXES++))
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
            echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
            echo -e "${CYAN}▶${NC} ${MAGENTA}$message${NC}"
            echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
            echo "[$timestamp] === $message ===" >> "$LOG_FILE"
            ;;
    esac
}

# Check prerequisites
check_prerequisites() {
    # Check root privileges
    if [[ $EUID -ne 0 ]]; then
        log_action ERROR "This script must be run as root"
        exit 1
    fi
    
    # Create necessary directories
    mkdir -p "$BACKUP_DIR"
    mkdir -p "$(dirname "$LOG_FILE")"
    touch "$LOG_FILE"
    chmod 600 "$LOG_FILE"
    
    # Check disk space (need at least 500MB)
    available_space=$(df / | awk 'NR==2 {print $4}')
    if [[ $available_space -lt 512000 ]]; then
        log_action WARNING "Low disk space detected. At least 500MB recommended"
    fi
}

# ============================================================================
# PHASE 1: BASIC KERNEL HARDENING
# ============================================================================
phase1_kernel_hardening() {
    log_action SECTION "Phase 1: Kernel Security Parameters"
    
    # Backup existing sysctl configurations
    if [[ -d /etc/sysctl.d ]]; then
        cp -r /etc/sysctl.d "$BACKUP_DIR/" 2>/dev/null || true
    fi
    
    # Create comprehensive sysctl configuration
    cat > /etc/sysctl.d/99-hardn-security.conf << 'EOF'
# HARDN Comprehensive Kernel Security Parameters
# Last updated: $(date)

# ═══════════════════════════════════════
# Network Security - Basic
# ═══════════════════════════════════════
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.tcp_timestamps = 0
net.ipv4.ip_forward = 0

# ═══════════════════════════════════════
# Network Security - Advanced
# ═══════════════════════════════════════
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
net.ipv4.icmp_ratelimit = 100
net.ipv4.icmp_ratemask = 88089
net.ipv4.icmp_errors_use_inbound_ifaddr = 1

# ARP Security
net.ipv4.conf.all.arp_ignore = 1
net.ipv4.conf.all.arp_announce = 2
net.ipv4.conf.default.arp_ignore = 1
net.ipv4.conf.default.arp_announce = 2

# ═══════════════════════════════════════
# IPv6 Security
# ═══════════════════════════════════════
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.default.accept_ra = 0
net.ipv6.conf.all.forwarding = 0
net.ipv6.conf.default.forwarding = 0

# ═══════════════════════════════════════
# Core Security
# ═══════════════════════════════════════
kernel.core_uses_pid = 1
kernel.sysrq = 0
kernel.randomize_va_space = 2
kernel.yama.ptrace_scope = 1
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.printk = 3 3 3 3
kernel.kexec_load_disabled = 1
kernel.unprivileged_bpf_disabled = 1
kernel.unprivileged_userns_clone = 0
kernel.panic = 60
kernel.panic_on_oops = 1
kernel.pid_max = 65536
kernel.perf_event_paranoid = 3
kernel.modules_disabled = 0
kernel.core_pattern=|/bin/false

# ═══════════════════════════════════════
# Process & Memory Security
# ═══════════════════════════════════════
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.protected_regular = 2
fs.protected_fifos = 2
fs.suid_dumpable = 0
vm.mmap_min_addr = 65536
vm.panic_on_oom = 0
vm.overcommit_memory = 0
vm.overcommit_ratio = 50
EOF
    
    if sysctl -p /etc/sysctl.d/99-hardn-security.conf >/dev/null 2>&1; then
        log_action SUCCESS "Comprehensive kernel parameters configured"
    else
        log_action WARNING "Some kernel parameters may not be supported"
    fi
}

# ============================================================================
# PHASE 2: FILESYSTEM SECURITY
# ============================================================================
phase2_filesystem_security() {
    log_action SECTION "Phase 2: Filesystem Hardening"
    
    # Set proper permissions on critical files and directories
    declare -A FILE_PERMISSIONS=(
        ["/etc/passwd"]=644
        ["/etc/shadow"]=000
        ["/etc/group"]=644
        ["/etc/gshadow"]=000
        ["/etc/passwd-"]=600
        ["/etc/shadow-"]=600
        ["/etc/group-"]=600
        ["/etc/gshadow-"]=600
        ["/etc/ssh/sshd_config"]=600
        ["/etc/crontab"]=600
        ["/etc/cron.d"]=700
        ["/etc/cron.daily"]=700
        ["/etc/cron.hourly"]=700
        ["/etc/cron.monthly"]=700
        ["/etc/cron.weekly"]=700
        ["/etc/sudoers"]=440
        ["/boot/grub/grub.cfg"]=400
        ["/etc/hosts.allow"]=644
        ["/etc/hosts.deny"]=644
    )
    
    for path in "${!FILE_PERMISSIONS[@]}"; do
        if [[ -e "$path" ]]; then
            chmod "${FILE_PERMISSIONS[$path]}" "$path" 2>/dev/null && \
                log_action SUCCESS "Secured: $path (${FILE_PERMISSIONS[$path]})" || \
                log_action WARNING "Could not secure: $path"
        fi
    done
    
    # Secure mount options
    log_action INFO "Configuring secure mount options"
    
    # Add secure mount options to fstab if not present
    if ! grep -q "/tmp" /etc/fstab; then
        echo "tmpfs /tmp tmpfs defaults,nosuid,nodev,noexec,mode=1777 0 0" >> /etc/fstab
        log_action SUCCESS "Secured /tmp mount point"
    fi
    
    if ! grep -q "/var/tmp" /etc/fstab; then
        echo "tmpfs /var/tmp tmpfs defaults,nosuid,nodev,noexec,mode=1777 0 0" >> /etc/fstab
        log_action SUCCESS "Secured /var/tmp mount point"
    fi
    
    if ! grep -q "/dev/shm" /etc/fstab; then
        echo "tmpfs /dev/shm tmpfs defaults,nosuid,nodev,noexec 0 0" >> /etc/fstab
        log_action SUCCESS "Secured /dev/shm mount point"
    fi
}

# ============================================================================
# PHASE 3: SSH HARDENING
# ============================================================================
phase3_ssh_hardening() {
    log_action SECTION "Phase 3: SSH Configuration Hardening"
    
    # Backup SSH configuration
    if [[ -f /etc/ssh/sshd_config ]]; then
        cp /etc/ssh/sshd_config "$BACKUP_DIR/sshd_config.backup"
    fi
    
    # Create comprehensive SSH hardening configuration
    mkdir -p /etc/ssh/sshd_config.d/
    cat > /etc/ssh/sshd_config.d/99-hardn-comprehensive.conf << 'EOF'
# HARDN Comprehensive SSH Hardening Configuration
# Maximum security settings for SSH

# Protocol and Port
Protocol 2
Port 22

# Authentication
PermitRootLogin no
PubkeyAuthentication yes
PasswordAuthentication no
PermitEmptyPasswords no
ChallengeResponseAuthentication no
MaxAuthTries 3
MaxSessions 10
LoginGraceTime 60
AuthenticationMethods publickey

# Security Features
StrictModes yes
IgnoreRhosts yes
HostbasedAuthentication no
X11Forwarding no
AllowAgentForwarding no
AllowTcpForwarding no
AllowStreamLocalForwarding no
PermitTunnel no
PermitUserEnvironment no
DebianBanner no
PrintLastLog yes
PrintMotd no

# Strong Cryptography
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group-exchange-sha256
HostKeyAlgorithms ssh-ed25519,rsa-sha2-512,rsa-sha2-256

# Logging
LogLevel VERBOSE
SyslogFacility AUTH

# Connection Settings
ClientAliveInterval 300
ClientAliveCountMax 2
MaxStartups 10:30:60
TCPKeepAlive no
Compression no
UsePAM yes
UseDNS no

# File Transfer
Subsystem sftp /usr/lib/openssh/sftp-server -f AUTHPRIV -l INFO

# Banner
Banner /etc/ssh/sshd_banner
EOF
    
    # Create SSH banner
    cat > /etc/ssh/sshd_banner << 'EOF'
############################################################################
#                         AUTHORIZED ACCESS ONLY                          #
############################################################################
#                                                                          #
# Unauthorized access to this system is forbidden and will be prosecuted  #
# by law. By accessing this system, you agree that your actions may be    #
# monitored and recorded. This system is restricted to authorized users   #
# only.                                                                    #
#                                                                          #
############################################################################
EOF
    
    # Test SSH configuration
    if sshd -t -f /etc/ssh/sshd_config >/dev/null 2>&1; then
        log_action SUCCESS "SSH hardening configuration applied"
        systemctl reload sshd 2>/dev/null || service ssh reload 2>/dev/null || true
    else
        log_action WARNING "SSH config test failed - check configuration"
    fi
}

# ============================================================================
# PHASE 4: PASSWORD & AUTHENTICATION POLICIES
# ============================================================================
phase4_password_policies() {
    log_action SECTION "Phase 4: Password and Authentication Policies"
    
    log_action INFO "HARDN policy: Avoiding PAM modifications for stability"
    
    # Configure password quality (without PAM modifications)
    if [[ -f /etc/security/pwquality.conf ]]; then
        cat > /etc/security/pwquality.conf << 'EOF'
# HARDN Password Quality Configuration
minlen = 14
minclass = 4
maxrepeat = 3
maxsequence = 3
ucredit = -1
lcredit = -1
dcredit = -1
ocredit = -1
difok = 4
gecoscheck = 1
dictcheck = 1
usercheck = 1
enforce_for_root
EOF
        log_action SUCCESS "Password quality configuration updated"
    fi
    
    # Configure login.defs
    if [[ -f /etc/login.defs ]]; then
        cp /etc/login.defs "$BACKUP_DIR/login.defs.backup"
        
        # Password aging
        sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/' /etc/login.defs
        sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   1/' /etc/login.defs
        sed -i 's/^PASS_MIN_LEN.*/PASS_MIN_LEN    14/' /etc/login.defs
        sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE   14/' /etc/login.defs
        
        # Security settings
        sed -i 's/^UMASK.*/UMASK           077/' /etc/login.defs
        sed -i 's/^ENCRYPT_METHOD.*/ENCRYPT_METHOD SHA512/' /etc/login.defs
        
        # Add if not present
        grep -q "^PASS_MAX_DAYS" /etc/login.defs || echo "PASS_MAX_DAYS   90" >> /etc/login.defs
        grep -q "^UMASK" /etc/login.defs || echo "UMASK           077" >> /etc/login.defs
        
        log_action SUCCESS "Login policies configured"
    fi
    
    # User limits (without PAM)
    cat > /etc/security/limits.d/99-hardn-security.conf << 'EOF'
# HARDN Security Limits
* hard core 0
* soft core 0
* hard nproc 1024
* soft nproc 512
* hard nofile 4096
* soft nofile 1024
* hard stack 8192
* soft stack 8192
* hard nice -20
* soft nice 0
EOF
    log_action SUCCESS "User resource limits configured"
}

# ============================================================================
# PHASE 5: AUDIT SYSTEM
# ============================================================================
phase5_audit_system() {
    log_action SECTION "Phase 5: Audit System Configuration"
    
    if command -v auditctl >/dev/null 2>&1; then
        # Create comprehensive audit rules
        cat > /etc/audit/rules.d/99-hardn-comprehensive.rules << 'EOF'
# HARDN Comprehensive Audit Rules
# Remove any existing rules
-D

# Buffer Size
-b 8192

# Failure Mode
-f 1

# Authentication monitoring
-w /var/log/faillog -p wa -k auth_failures
-w /var/log/lastlog -p wa -k logins
-w /var/log/tallylog -p wa -k logins
-w /var/log/btmp -p wa -k session
-w /var/log/wtmp -p wa -k session

# User and group monitoring
-w /etc/group -p wa -k identity
-w /etc/passwd -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity

# Privilege escalation monitoring
-w /etc/sudoers -p wa -k sudoers
-w /etc/sudoers.d/ -p wa -k sudoers
-w /bin/su -p x -k priv_escalation
-w /usr/bin/sudo -p x -k priv_escalation
-w /usr/bin/passwd -p x -k passwd_changes
-w /usr/bin/chsh -p x -k shell_changes

# SSH configuration monitoring
-w /etc/ssh/sshd_config -p wa -k sshd_config
-w /etc/ssh/sshd_config.d/ -p wa -k sshd_config

# System call monitoring
-a always,exit -F arch=b64 -S execve -k exec
-a always,exit -F arch=b64 -S socket -S connect -k network
-a always,exit -F arch=b64 -S open -S openat -F exit=-EPERM -k access
-a always,exit -F arch=b64 -S open -S openat -F exit=-EACCES -k access
-a always,exit -F arch=b64 -S mount -k mount
-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -k delete

# Kernel module monitoring
-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules
-a always,exit -F arch=b64 -S init_module -S delete_module -k modules

# Make configuration immutable
-e 2
EOF
        
        # Load audit rules
        if augenrules --load >/dev/null 2>&1; then
            log_action SUCCESS "Comprehensive audit rules configured"
            systemctl restart auditd 2>/dev/null || true
        else
            log_action WARNING "Could not load audit rules"
        fi
    else
        log_action INFO "auditd not installed - skipping audit configuration"
    fi
}

# ============================================================================
# PHASE 6: FIREWALL CONFIGURATION
# ============================================================================
phase6_firewall() {
    log_action SECTION "Phase 6: Firewall Configuration"
    
    if command -v iptables >/dev/null 2>&1; then
        # Create firewall rules script
        mkdir -p /etc/iptables/
        cat > /etc/iptables/hardn-firewall.sh << 'EOF'
#!/bin/bash
# HARDN Comprehensive Firewall Rules

# Flush existing rules
iptables -F
iptables -X
iptables -Z

# Default policies
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

# Allow loopback
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

# Allow established connections
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Allow SSH (rate limited)
iptables -A INPUT -p tcp --dport 22 -m state --state NEW -m recent --set
iptables -A INPUT -p tcp --dport 22 -m state --state NEW -m recent --update --seconds 60 --hitcount 4 -j DROP
iptables -A INPUT -p tcp --dport 22 -m state --state NEW -j ACCEPT

# Allow ping (limited)
iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit 1/s -j ACCEPT

# Drop invalid packets
iptables -A INPUT -m state --state INVALID -j DROP

# Log dropped packets
iptables -N LOGGING
iptables -A INPUT -j LOGGING
iptables -A LOGGING -m limit --limit 2/min -j LOG --log-prefix "IPTables-Dropped: " --log-level 4
iptables -A LOGGING -j DROP

# Save rules
iptables-save > /etc/iptables/rules.v4

# IPv6 (block all if not needed)
ip6tables -F
ip6tables -P INPUT DROP
ip6tables -P FORWARD DROP
ip6tables -P OUTPUT DROP
ip6tables-save > /etc/iptables/rules.v6
EOF
        
        chmod +x /etc/iptables/hardn-firewall.sh
        log_action SUCCESS "Firewall rules script created"
        log_action INFO "Apply with: /etc/iptables/hardn-firewall.sh"
    else
        log_action INFO "iptables not found - skipping firewall configuration"
    fi
}

# ============================================================================
# PHASE 7: SERVICE HARDENING
# ============================================================================
phase7_service_hardening() {
    log_action SECTION "Phase 7: Service Hardening"
    
    # Disable unnecessary services
    UNNECESSARY_SERVICES=(
        "bluetooth"
        "cups"
        "avahi-daemon"
        "rpcbind"
        "nfs-client"
        "nfs-server"
        "snmpd"
        "xinetd"
        "nis"
        "telnet"
        "vsftpd"
        "tftpd"
    )
    
    for service in "${UNNECESSARY_SERVICES[@]}"; do
        if systemctl list-unit-files | grep -q "^$service"; then
            systemctl stop "$service" 2>/dev/null
            systemctl disable "$service" 2>/dev/null && \
                log_action SUCCESS "Disabled service: $service" || \
                log_action INFO "Service not found: $service"
        fi
    done
    
    # Harden systemd services
    log_action INFO "Hardening systemd services"
    
    # Create systemd hardening for SSH
    mkdir -p /etc/systemd/system/sshd.service.d/
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
}

# ============================================================================
# PHASE 8: APPARMOR CONFIGURATION
# ============================================================================
phase8_apparmor() {
    log_action SECTION "Phase 8: AppArmor Configuration"
    
    log_action INFO "HARDN uses AppArmor (not SELinux)"
    
    if command -v aa-status >/dev/null 2>&1; then
        # Enable AppArmor
        systemctl enable apparmor 2>/dev/null && \
        systemctl start apparmor 2>/dev/null && \
        log_action SUCCESS "AppArmor enabled and started" || \
        log_action WARNING "AppArmor already running"
        
        # Set profiles to enforce mode
        if command -v aa-enforce >/dev/null 2>&1; then
            for profile in /etc/apparmor.d/*; do
                if [[ -f "$profile" ]] && [[ ! "$profile" == *.dpkg* ]]; then
                    profile_name=$(basename "$profile")
                    aa-enforce "$profile" 2>/dev/null && \
                        log_action SUCCESS "Enforced: $profile_name" || \
                        log_action INFO "Could not enforce: $profile_name"
                fi
            done
        fi
        
        # Add kernel parameters
        if [[ -f /etc/default/grub ]]; then
            if ! grep -q "apparmor=1" /etc/default/grub; then
                cp /etc/default/grub "$BACKUP_DIR/grub.backup"
                sed -i 's/GRUB_CMDLINE_LINUX_DEFAULT="/GRUB_CMDLINE_LINUX_DEFAULT="apparmor=1 security=apparmor /' /etc/default/grub
                log_action SUCCESS "AppArmor kernel parameters added (run update-grub)"
            fi
        fi
    else
        log_action WARNING "AppArmor not installed - critical security component"
        log_action INFO "Install with: apt-get install apparmor apparmor-utils"
    fi
}

# ============================================================================
# PHASE 9: KERNEL MODULE BLACKLISTING
# ============================================================================
phase9_kernel_modules() {
    log_action SECTION "Phase 9: Kernel Module Blacklisting"
    
    # Blacklist unnecessary kernel modules
    cat > /etc/modprobe.d/hardn-blacklist.conf << 'EOF'
# HARDN Kernel Module Blacklist
# Disables unnecessary and potentially dangerous modules

# Network protocols
install dccp /bin/true
install sctp /bin/true
install rds /bin/true
install tipc /bin/true

# Filesystems
install cramfs /bin/true
install freevxfs /bin/true
install jffs2 /bin/true
install hfs /bin/true
install hfsplus /bin/true
install udf /bin/true
install vfat /bin/true
install msdos /bin/true
install iso9660 /bin/true
install cifs /bin/true
install nfs /bin/true
install nfsv3 /bin/true
install nfsv4 /bin/true
install gfs2 /bin/true

# USB (uncomment if USB not needed)
# install usb-storage /bin/true

# Firewire
install firewire-core /bin/true
install firewire-ohci /bin/true
install firewire-sbp2 /bin/true

# Bluetooth (if not needed)
install bluetooth /bin/true
install btusb /bin/true

# Uncommon network drivers
install n_hdlc /bin/true
install ax25 /bin/true
install netrom /bin/true
install x25 /bin/true
install rose /bin/true
install decnet /bin/true
install econet /bin/true
install af_802154 /bin/true
install ipx /bin/true
install appletalk /bin/true
install psnap /bin/true
install p8022 /bin/true
install llc /bin/true
install p8023 /bin/true
EOF
    
    log_action SUCCESS "Kernel module blacklist configured"
}

# ============================================================================
# PHASE 10: ADDITIONAL SECURITY MEASURES
# ============================================================================
phase10_additional() {
    log_action SECTION "Phase 10: Additional Security Measures"
    
    # Disable core dumps
    cat > /etc/security/limits.d/99-hardn-coredump.conf << 'EOF'
# Disable core dumps
* soft core 0
* hard core 0
EOF
    
    echo "kernel.core_pattern=|/bin/false" > /etc/sysctl.d/50-coredump.conf
    sysctl -p /etc/sysctl.d/50-coredump.conf >/dev/null 2>&1
    log_action SUCCESS "Core dumps disabled"
    
    # Configure Fail2Ban
    if command -v fail2ban-client >/dev/null 2>&1; then
        mkdir -p /etc/fail2ban/jail.d/
        cat > /etc/fail2ban/jail.d/00-hardn.conf << 'EOF'
[DEFAULT]
allowipv6 = auto
bantime = 3600
findtime = 600
maxretry = 5
destemail = root@localhost

[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 7200
EOF
        systemctl restart fail2ban 2>/dev/null || true
        log_action SUCCESS "Fail2Ban configured"
    fi
    
    # Configure Lynis custom profile
    mkdir -p /etc/lynis/custom.d/
    cat > /etc/lynis/custom.d/hardn.prf << 'EOF'
# HARDN Lynis Custom Profile
machine-role=server
config:error_on_warnings=0
config:show_warnings_only=0
config:test_malware=yes
config:test_ports_packages=yes
EOF
    log_action SUCCESS "Lynis custom profile configured"
    
    # Restrict compiler access
    COMPILERS=("/usr/bin/gcc" "/usr/bin/g++" "/usr/bin/cc" "/usr/bin/c++" "/usr/bin/as")
    
    groupadd -f compiler 2>/dev/null || true
    for compiler in "${COMPILERS[@]}"; do
        if [[ -f "$compiler" ]]; then
            chown root:compiler "$compiler" 2>/dev/null
            chmod 750 "$compiler" 2>/dev/null && \
                log_action SUCCESS "Restricted: $compiler" || \
                log_action INFO "Could not restrict: $compiler"
        fi
    done
    
    # Configure cron security
    if [[ ! -f /etc/cron.allow ]]; then
        echo "root" > /etc/cron.allow
        chmod 600 /etc/cron.allow
        log_action SUCCESS "Cron restricted to root only"
    fi
    
    [[ -f /etc/cron.deny ]] && rm /etc/cron.deny
    
    # Configure at security
    if [[ ! -f /etc/at.allow ]]; then
        echo "root" > /etc/at.allow
        chmod 600 /etc/at.allow
        log_action SUCCESS "At daemon restricted to root only"
    fi
    
    [[ -f /etc/at.deny ]] && rm /etc/at.deny
}

# ============================================================================
# PHASE 11: LOGGING ENHANCEMENTS
# ============================================================================
phase11_logging() {
    log_action SECTION "Phase 11: Enhanced Logging Configuration"
    
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

# Security events
*.emerg                          /var/log/emergency.log
*.alert                          /var/log/alert.log
*.crit                           /var/log/critical.log
EOF
        
        systemctl restart rsyslog 2>/dev/null || true
        log_action SUCCESS "Enhanced logging configured"
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
    
    log_action SUCCESS "Log rotation configured"
}

# ============================================================================
# PHASE 12: FILE INTEGRITY MONITORING
# ============================================================================
phase12_file_integrity() {
    log_action SECTION "Phase 12: File Integrity Monitoring"
    
    if command -v aide >/dev/null 2>&1; then
        mkdir -p /etc/aide/aide.conf.d/
        cat > /etc/aide/aide.conf.d/99_hardn << 'EOF'
# HARDN AIDE Configuration

# Rules
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

# Security files
/etc/passwd NORMAL
/etc/shadow NORMAL
/etc/group NORMAL
/etc/gshadow NORMAL
/etc/ssh/sshd_config NORMAL
/etc/sudoers NORMAL
/etc/pam.d NORMAL

# Logs (size can change)
/var/log DATAONLY
!/var/log/journal
!/var/log/lastlog
EOF
        
        log_action SUCCESS "AIDE configuration created"
        log_action INFO "Initialize AIDE with: aideinit"
    else
        log_action INFO "AIDE not installed - consider installing for file integrity"
    fi
}

# ============================================================================
# MAIN EXECUTION
# ============================================================================
main() {
    echo -e "${CYAN}╔═══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${NC}    ${WHITE}HARDN Comprehensive Lynis Hardening Script${NC}             ${CYAN}║${NC}"
    echo -e "${CYAN}╚═══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    # Check prerequisites
    check_prerequisites
    
    log_action INFO "Starting comprehensive hardening process..."
    log_action INFO "Backup directory: $BACKUP_DIR"
    log_action INFO "Log file: $LOG_FILE"
    echo ""
    
    # Execute all phases
    phase1_kernel_hardening
    phase2_filesystem_security
    phase3_ssh_hardening
    phase4_password_policies
    phase5_audit_system
    phase6_firewall
    phase7_service_hardening
    phase8_apparmor
    phase9_kernel_modules
    phase10_additional
    phase11_logging
    phase12_file_integrity
    
    # Final summary
    echo ""
    echo -e "${GREEN}╔═══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║              Comprehensive Hardening Complete!                ║${NC}"
    echo -e "${GREEN}╠═══════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${GREEN}║${NC} Total Improvements: ${WHITE}$SCORE_IMPROVEMENTS${NC}"
    echo -e "${GREEN}║${NC} Total Fixes Applied: ${WHITE}$TOTAL_FIXES${NC}"
    echo -e "${GREEN}║${NC} Backup Location: ${WHITE}$BACKUP_DIR${NC}"
    echo -e "${GREEN}║${NC} Log File: ${WHITE}$LOG_FILE${NC}"
    echo -e "${GREEN}╚═══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${YELLOW}Required Actions:${NC}"
    echo "1. Update GRUB (if kernel parameters were added):"
    echo "   ${CYAN}sudo update-grub${NC}"
    echo ""
    echo "2. Apply firewall rules:"
    echo "   ${CYAN}sudo /etc/iptables/hardn-firewall.sh${NC}"
    echo ""
    echo "3. Reboot the system:"
    echo "   ${CYAN}sudo reboot${NC}"
    echo ""
    echo "4. After reboot, check Lynis score:"
    echo "   ${CYAN}sudo lynis audit system${NC}"
    echo ""
    echo -e "${GREEN}Your system is now comprehensively hardened!${NC}"
}

# Execute main function
main "$@"