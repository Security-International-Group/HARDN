#!/bin/bash
# HARDN Enhanced Security Hardening Module


set -euo pipefail

export DEBIAN_FRONTEND=noninteractive

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' 

echo "HARDN Enhanced Security Hardening Module"
echo "========================================="
echo ""

# ==========================================
# LOGGING
# =========================================
HARDN_STATUS() {
    local color="$GREEN"
    local label="[INFO]"
    local timestamp="$(date '+%Y-%m-%d %H:%M:%S')"

    if [ $# -gt 1 ]; then
        case "$1" in
            INFO)
                color="$GREEN"
                label="[INFO]"
                shift
                ;;
            WARN)
                color="$YELLOW"
                label="[WARN]"
                shift
                ;;
            UPDATE)
                color="$CYAN"
                label="[UPDATE]"
                shift
                ;;
            ERROR)
                color="$RED"
                label="[ERROR]"
                shift
                ;;
            DEBUG)
                color="$BLUE"
                label="[DEBUG]"
                shift
                ;;
        esac
    fi

    echo -e "${color}[${timestamp}] ${label}${NC} $*"
}

log_action() {
    HARDN_STATUS INFO "$1"
}

log_warning() {
    HARDN_STATUS WARN "$1"
}

log_update() {
    HARDN_STATUS UPDATE "$1"
}

log_error() {
    HARDN_STATUS ERROR "$1"
}

APT_TIMEOUT_DEFAULT=${APT_TIMEOUT_DEFAULT:-120}
APT_LOG_DIR="/var/log/hardn/apt"
APT_INSTALL_FLAGS=(-y --no-install-recommends -o Dpkg::Progress-Fancy=0)
mkdir -p /var/log/hardn 2>/dev/null || true
mkdir -p "$APT_LOG_DIR" 2>/dev/null || true

apt_install() {
    local log_key="$1"; shift
    local description="$1"; shift
    local timeout="$APT_TIMEOUT_DEFAULT"
    local maybe_timeout="${1:-}"

    if [[ -n "$maybe_timeout" && "$maybe_timeout" =~ ^[0-9]+$ ]]; then
        timeout="$maybe_timeout"
        shift
    fi

    if [ "$#" -eq 0 ]; then
        log_error "apt_install called without packages for $description"
        return 1
    fi

    local log_file="$APT_LOG_DIR/${log_key}.log"
    HARDN_STATUS "$description (details: $log_file)"
    if timeout "$timeout" apt-get install "${APT_INSTALL_FLAGS[@]}" "$@" >"$log_file" 2>&1; then
        HARDN_STATUS "$description completed"
        return 0
    else
        log_warning "$description failed; see $log_file"
        return 1
    fi
}

hardn_services_lockdown() {
    local api_port="${HARDN_API_PORT:-8000}"
    local grafana_port="${HARDN_GRAFANA_PORT:-3000}"
    local api_allow_list="${HARDN_API_ALLOWED_CIDRS:-}"
    local grafana_allow_list="${HARDN_GRAFANA_ALLOWED_CIDRS:-}"
    local permitted_outbound_cidrs="${HARDN_PERMITTED_OUTBOUND_CIDRS:-}"

    HARDN_STATUS INFO "Applying HARDN services lockdown perimeter"

    if ! command -v ufw >/dev/null 2>&1; then
        apt_install "ufw" "Installing UFW firewall" 180 ufw || log_warning "Failed to install UFW; continuing with existing firewall"
    fi

    if ! command -v iptables >/dev/null 2>&1; then
        apt_install "iptables" "Installing iptables tools" 120 iptables iptables-persistent netfilter-persistent || true
    fi

    # Disable SSH entry points – Fail2Ban will still monitor for unexpected activations
    if systemctl list-unit-files | grep -q '^ssh\.service'; then
        systemctl stop ssh.service 2>/dev/null || true
        systemctl disable ssh.service 2>/dev/null || true
        systemctl mask ssh.service 2>/dev/null || true
    fi
    if systemctl list-unit-files | grep -q '^ssh\.socket'; then
        systemctl stop ssh.socket 2>/dev/null || true
        systemctl disable ssh.socket 2>/dev/null || true
    fi

    if command -v ufw >/dev/null 2>&1; then
        ufw --force disable
        ufw --force reset
        ufw default deny incoming
        ufw default allow outgoing
        ufw default deny routed
        ufw allow in on lo comment 'Loopback inbound'
        ufw allow out on lo comment 'Loopback outbound'

        if [ -n "$api_allow_list" ]; then
            for cidr in $api_allow_list; do
                ufw allow proto tcp from "$cidr" to any port "$api_port" comment 'HARDN API access (scoped)'
            done
        else
            ufw allow "$api_port"/tcp comment 'HARDN API access'
        fi

        if [ -n "$grafana_allow_list" ]; then
            for cidr in $grafana_allow_list; do
                ufw allow proto tcp from "$cidr" to any port "$grafana_port" comment 'Grafana access (scoped)'
            done
        else
            ufw allow "$grafana_port"/tcp comment 'Grafana access'
        fi

        ufw allow out 53 comment 'DNS'
        ufw allow out 80/tcp comment 'HTTP'
        ufw allow out 443/tcp comment 'HTTPS'
        ufw allow out 123/udp comment 'NTP'

        if [ -n "$permitted_outbound_cidrs" ]; then
            for cidr in $permitted_outbound_cidrs; do
                ufw allow out to "$cidr" comment 'Approved outbound range'
            done
        fi

        ufw --force enable
        ufw reload >/dev/null 2>&1 || true
        HARDN_STATUS INFO "UFW restricted to HARDN API port ${api_port} and Grafana port ${grafana_port}"
    else
        log_warning "UFW firewall not available; skipping UFW lockdown"
    fi

    local ipt_cmd=""
    if command -v iptables-nft >/dev/null 2>&1; then
        ipt_cmd="iptables-nft"
    elif command -v iptables >/dev/null 2>&1; then
        ipt_cmd="iptables"
    fi

    if [ -n "$ipt_cmd" ]; then
        $ipt_cmd -N HARDN-LOCKDOWN 2>/dev/null || true
        $ipt_cmd -F HARDN-LOCKDOWN
        $ipt_cmd -A HARDN-LOCKDOWN -i lo -j ACCEPT
        $ipt_cmd -A HARDN-LOCKDOWN -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

        if [ -n "$api_allow_list" ]; then
            for cidr in $api_allow_list; do
                $ipt_cmd -A HARDN-LOCKDOWN -p tcp --dport "$api_port" -s "$cidr" -j ACCEPT
            done
        else
            $ipt_cmd -A HARDN-LOCKDOWN -p tcp --dport "$api_port" -j ACCEPT
        fi

        if [ -n "$grafana_allow_list" ]; then
            for cidr in $grafana_allow_list; do
                $ipt_cmd -A HARDN-LOCKDOWN -p tcp --dport "$grafana_port" -s "$cidr" -j ACCEPT
            done
        else
            $ipt_cmd -A HARDN-LOCKDOWN -p tcp --dport "$grafana_port" -j ACCEPT
        fi

        $ipt_cmd -A HARDN-LOCKDOWN -p icmp --icmp-type echo-request -j DROP
        $ipt_cmd -A HARDN-LOCKDOWN -j DROP

        if ! $ipt_cmd -C INPUT -j HARDN-LOCKDOWN 2>/dev/null; then
            $ipt_cmd -I INPUT 1 -j HARDN-LOCKDOWN
        fi

        HARDN_STATUS INFO "iptables HARDN-LOCKDOWN chain applied"

        if command -v ip6tables >/dev/null 2>&1; then
            ip6tables -N HARDN-LOCKDOWN 2>/dev/null || true
            ip6tables -F HARDN-LOCKDOWN
            ip6tables -A HARDN-LOCKDOWN -i lo -j ACCEPT
            ip6tables -A HARDN-LOCKDOWN -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

            if [ -n "$api_allow_list" ]; then
                for cidr in $api_allow_list; do
                    ip6tables -A HARDN-LOCKDOWN -p tcp --dport "$api_port" -s "$cidr" -j ACCEPT
                done
            else
                ip6tables -A HARDN-LOCKDOWN -p tcp --dport "$api_port" -j ACCEPT
            fi

            if [ -n "$grafana_allow_list" ]; then
                for cidr in $grafana_allow_list; do
                    ip6tables -A HARDN-LOCKDOWN -p tcp --dport "$grafana_port" -s "$cidr" -j ACCEPT
                done
            else
                ip6tables -A HARDN-LOCKDOWN -p tcp --dport "$grafana_port" -j ACCEPT
            fi

            ip6tables -A HARDN-LOCKDOWN -j DROP

            if ! ip6tables -C INPUT -j HARDN-LOCKDOWN 2>/dev/null; then
                ip6tables -I INPUT 1 -j HARDN-LOCKDOWN
            fi

            HARDN_STATUS INFO "ip6tables HARDN-LOCKDOWN chain applied"
        fi

        if command -v netfilter-persistent >/dev/null 2>&1; then
            netfilter-persistent save >/dev/null 2>&1 || true
        fi
    else
        log_warning "iptables not available; skipping low-level firewall sync"
    fi

    HARDN_STATUS INFO "HARDN services lockdown perimeter enforced"
}

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    log_error "This script must be run as root"
   exit 1
fi

# Enforce network perimeter before additional hardening
hardn_services_lockdown

# ==========================================
# TIME - NTP
# ==========================================
HARDN_STATUS "Configuring secure time synchronization..."
if apt_install "chrony" "Installing chrony" 120 chrony; then
    if [ -f /etc/chrony/chrony.conf ]; then
        cp /etc/chrony/chrony.conf /etc/chrony/chrony.conf.bak.$(date +%Y%m%d%H%M%S) 2>/dev/null || true
    fi
    cat > /etc/chrony/chrony.conf <<'EOF'
# HARDN Chrony configuration
pool pool.ntp.org iburst maxsources 4
pool time.google.com iburst maxsources 2

# Hardened restrictions
cmdport 0
noclientlog
rtcsync
makestep 1.0 3

allow 127.0.0.1/32
allow ::1/128

logchange 0.5

# Log location
logdir /var/log/chrony
EOF
    mkdir -p /var/log/chrony 2>/dev/null || true
    systemctl enable chrony 2>/dev/null || true
    systemctl restart chrony 2>/dev/null || true
    HARDN_STATUS "Chrony configured and running"
else
    log_warning "Chrony installation failed; falling back to systemd-timesyncd"
    if systemctl list-unit-files | grep -q '^systemd-timesyncd.service'; then
        mkdir -p /etc/systemd/timesyncd.conf.d 2>/dev/null || true
        cat > /etc/systemd/timesyncd.conf.d/99-hardn.conf <<'EOF'
[Time]
NTP=pool.ntp.org time.google.com
FallbackNTP=
RootDistanceMaxSec=5
PollIntervalMinSec=32
PollIntervalMaxSec=2048
EOF
        systemctl enable systemd-timesyncd 2>/dev/null || true
        systemctl restart systemd-timesyncd 2>/dev/null || true
    fi
fi

# ==========================================
# LOGGING HARDENING
# ==========================================
HARDN_STATUS "Ensuring persistent journald storage..."
mkdir -p /var/log/journal 2>/dev/null || true
mkdir -p /etc/systemd/journald.conf.d 2>/dev/null || true
cat > /etc/systemd/journald.conf.d/99-hardn.conf <<'EOF'
[Journal]
Storage=persistent
SystemMaxUse=500M
SystemKeepFree=100M
Compress=yes
Seal=yes
SplitMode=uid
EOF
systemctl restart systemd-journald 2>/dev/null || true

HARDN_STATUS "Configuring remote syslog forwarding..."
mkdir -p /etc/hardn 2>/dev/null || true
REMOTE_SYSLOG_FILE="/etc/hardn/remote-syslog.target"
REMOTE_SYSLOG_TARGET="${HARDN_REMOTE_SYSLOG_TARGET:-}"

if [ -z "$REMOTE_SYSLOG_TARGET" ] && [ -f "$REMOTE_SYSLOG_FILE" ]; then
    REMOTE_SYSLOG_TARGET="$(awk 'NF && $0 !~ /^#/ {gsub(/[[:space:]]/, ""); print; exit}' "$REMOTE_SYSLOG_FILE" 2>/dev/null || true)"
fi

if [ -z "$REMOTE_SYSLOG_TARGET" ]; then
    if [ ! -f "$REMOTE_SYSLOG_FILE" ]; then
        cat > "$REMOTE_SYSLOG_FILE" <<'EOF'
# Specify remote syslog target in the format @hostname:port or @@hostname:port for TCP.
# Example: @@log-aggregator.internal:6514
EOF
    fi
    HARDN_STATUS "Remote syslog target not defined; update $REMOTE_SYSLOG_FILE or set HARDN_REMOTE_SYSLOG_TARGET to enable forwarding."
else
    echo "$REMOTE_SYSLOG_TARGET" > "$REMOTE_SYSLOG_FILE"
    mkdir -p /etc/rsyslog.d 2>/dev/null || true
    cat > /etc/rsyslog.d/99-hardn-remote.conf <<EOF
# HARDN remote syslog forwarding
*.*\t$REMOTE_SYSLOG_TARGET
& stop
EOF
    systemctl restart rsyslog 2>/dev/null || true
    HARDN_STATUS "Remote syslog forwarding enabled to $REMOTE_SYSLOG_TARGET"
fi

# ==========================================
#  AUTHENTICATION HARDENING 
# ==========================================
HARDN_STATUS "Applying authentication hardening"

if ! apt_install "pam_quality" "Installing password quality libraries" libpam-pwquality libpwquality-tools; then
    log_warning "libpam-pwquality installation failed, continuing..."
fi

# Configure login.defs for password aging (addresses AUTH-9286)
if [ -f /etc/login.defs ]; then
    sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/' /etc/login.defs
    sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   1/' /etc/login.defs
    sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE   14/' /etc/login.defs
    
    # Set reasonable default umask that balances security with usability
    sed -i 's/^UMASK.*/UMASK           022/' /etc/login.defs
    
    # Set minimum UID for regular users
    sed -i 's/^UID_MIN.*/UID_MIN          1000/' /etc/login.defs
    
    # Enable SHA512 for password hashing
    sed -i 's/^ENCRYPT_METHOD.*/ENCRYPT_METHOD SHA512/' /etc/login.defs
    
    HARDN_STATUS "Login.defs configured for password aging and security"
fi


# Enforce password history to prevent reuse (AUTH-1174)
if [ -f /etc/pam.d/common-password ]; then
    if grep -qE 'pam_unix.so' /etc/pam.d/common-password; then
        sed -ri 's|^password\s+\[success=1 default=ignore\]\s+pam_unix.so.*|password    [success=1 default=ignore]    pam_unix.so obscure sha512 remember=5|g' /etc/pam.d/common-password
    else
        echo 'password    [success=1 default=ignore]    pam_unix.so obscure sha512 remember=5' >> /etc/pam.d/common-password
    fi
    HARDN_STATUS "Password history enforced via pam_unix remember=5"
else
    log_warning "/etc/pam.d/common-password not found; password history not enforced"
fi

# Set default inactivity timeout for new accounts
if [ -f /etc/default/useradd ]; then
    if grep -q '^INACTIVE=' /etc/default/useradd; then
        sed -i 's/^INACTIVE=.*/INACTIVE=30/' /etc/default/useradd
    else
        echo 'INACTIVE=30' >> /etc/default/useradd
    fi
    HARDN_STATUS "Default user inactivity set to 30 days"
else
    log_warning "/etc/default/useradd missing; cannot set INACTIVE default"
fi

# Apply inactivity timeout to existing human accounts
awk -F: '($3 >= 1000 && $1 != "nobody" && $7 !~ /(nologin|false)/) {print $1}' /etc/passwd | while read -r user; do
    chage --inactive 30 "$user" 2>/dev/null || log_warning "Failed to set inactivity for $user"
done

# Audit world-writable directories and log results
mkdir -p /var/log/hardn 2>/dev/null || true
WORLD_WRITABLE_REPORT="/var/log/hardn/world-writable-dirs.txt"
HARDN_STATUS "Auditing world-writable directories..."
if timeout 180 find / -xdev -type d -perm -0002 2>/dev/null | sort -u > "$WORLD_WRITABLE_REPORT"; then
    HARDN_STATUS "World-writable directory audit saved to $WORLD_WRITABLE_REPORT"
else
    log_warning "World-writable directory audit incomplete; check permissions or increase timeout"
fi

# Ensure sudo activity is logged
HARDN_STATUS "Configuring sudo logging..."
cat > /etc/sudoers.d/99-hardn-logging <<'EOF'
Defaults logfile="/var/log/sudo.log"
Defaults loglinelen=0
EOF
chmod 440 /etc/sudoers.d/99-hardn-logging 2>/dev/null || true

# Ensure system/service accounts have non-interactive shells
awk -F: '($3 < 1000 && $1 != "root" && $7 ~ /(bash|sh|dash|zsh)$/)' /etc/passwd | while read -r svc; do
    chsh -s /usr/sbin/nologin "$svc" 2>/dev/null || log_warning "Failed to set nologin shell for $svc"
done
HARDN_STATUS "Service accounts restricted to nologin where applicable"



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

# Document IPv6 policy stance
mkdir -p /etc/hardn 2>/dev/null || true
cat > /etc/hardn/ipv6-policy.txt <<EOF
HARDN IPv6 Posture
==================

Date: $(date -u)

IPv6 remains enabled to support modern networking while router advertisements,
source routing, and redirect acceptance are disabled to minimize attack surface.
The hardening sysctl policy is defined in /etc/sysctl.d/99-hardn-hardening.conf.
EOF
HARDN_STATUS "IPv6 policy documented at /etc/hardn/ipv6-policy.txt"

# Ensure adequate entropy source
HARDN_STATUS "Ensuring entropy daemon is available..."
if ! systemctl list-unit-files | grep -q '^haveged.service'; then
    if ! apt_install "haveged" "Installing haveged entropy daemon" 120 haveged; then
        log_warning "haveged not available; attempting rng-tools"
        apt_install "rng_tools" "Installing rng-tools entropy daemon" 120 rng-tools || log_warning "Entropy daemon installation failed"
    fi
fi

entropy_candidates=(
    "haveged:haveged"
    "rngd:rngd"
    "rng-tools:rngd"
    "rng-tools-debian:rngd"
)

entropy_service=""
entropy_process=""
entropy_uses_systemd=0

for candidate in "${entropy_candidates[@]}"; do
    svc="${candidate%%:*}"
    proc="${candidate##*:}"
    svc_unit="${svc}.service"

    if command -v systemctl >/dev/null 2>&1 && systemctl cat "$svc_unit" >/dev/null 2>&1; then
        entropy_service="$svc"
        entropy_process="$proc"
        entropy_uses_systemd=1
        break
    fi

    if [ -x "/etc/init.d/$svc" ]; then
        entropy_service="$svc"
        entropy_process="$proc"
        entropy_uses_systemd=0
        break
    fi
done

if [ -n "$entropy_service" ]; then
    if [ $entropy_uses_systemd -eq 1 ]; then
        systemctl enable "${entropy_service}" 2>/dev/null || true
        systemctl start "${entropy_service}" 2>/dev/null || true
        if systemctl is-active --quiet "${entropy_service}"; then
            HARDN_STATUS "${entropy_service} entropy service enabled and running"
        elif pgrep -f "${entropy_process}" >/dev/null 2>&1; then
            HARDN_STATUS "${entropy_process} entropy process running"
        else
            log_warning "${entropy_service} entropy service detected but inactive; review system logs"
        fi
    else
        service "${entropy_service}" start 2>/dev/null || /etc/init.d/"${entropy_service}" start 2>/dev/null || true
        if pgrep -f "${entropy_process}" >/dev/null 2>&1; then
            HARDN_STATUS "${entropy_process} entropy daemon running"
        else
            log_warning "${entropy_service} entropy daemon not running; manual intervention required"
        fi
    fi
else
    log_warning "No entropy daemon package detected after installation attempts"
fi
HARDN_STATUS "Entropy daemon setup complete"

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
# AIDE INSTALLATION
# ==========================================
HARDN_STATUS "Setting up AIDE fast profile..."
if ! dpkg-query -W -f='${Status}' aide 2>/dev/null | grep -q "install ok installed"; then
    if ! apt_install "aide" "Installing AIDE" 120 aide; then
        log_warning "AIDE installation failed, skipping baseline setup"
    fi
fi

if command -v aide >/dev/null 2>&1; then
    mkdir -p /etc/aide /etc/aide/aide.conf.d /var/lib/aide /var/log/hardn

    AIDE_FAST_CONFIG="/etc/aide/aide.conf.hardn-fast"
    AIDE_FAST_LOG="/var/log/hardn/aide-fast-init.log"
    AIDE_FAST_TIMEOUT="${AIDE_FAST_TIMEOUT:-300}"

    cat > /etc/aide/aide.conf.d/99-hardn-fast.conf <<'EOF'
# HARDN fast profile placeholder
# The active quick profile lives in /etc/aide/aide.conf.hardn-fast
# and is invoked directly by the hardening automation.
EOF

    cat > "$AIDE_FAST_CONFIG" <<'EOF'
# HARDN quick AIDE profile (fast baseline)
database_in=file:/var/lib/aide/aide.db.hardn-fast.gz
database_out=file:/var/lib/aide/aide.db.hardn-fast.new.gz
database_new=file:/var/lib/aide/aide.db.hardn-fast.new.gz
gzip_dbout=yes
log_level=warning
report_level=summary
report_quiet=yes
num_workers=60%
report_url=file:/var/log/hardn/aide-fast-report.txt

!/dev
!/proc
!/sys
!/run
!/tmp
!/var/cache
!/var/tmp
!/var/log/journal
!/var/log/apt
!/var/log/hardn
!/var/log/dpkg.log
!/home/*/.cache
!/var/tmp/*
!/var/lib/systemd/coredump

/etc            p+i+n+u+g+sha256
/usr            p+i+n+u+g+sha256
/var            p+i+n+u+g+sha256
/home           p+i+n+u+g+sha256
EOF

    AIDE_DB="/var/lib/aide/aide.db.hardn-fast.gz"
    AIDE_DB_NEW="/var/lib/aide/aide.db.hardn-fast.new.gz"

    HARDN_STATUS "Building compact AIDE database (timeout ${AIDE_FAST_TIMEOUT}s)..."
    rm -f "$AIDE_DB_NEW"

    aide_cmd=(nice -n 10 ionice -c3 aide --config "$AIDE_FAST_CONFIG" --init)

    if timeout "$AIDE_FAST_TIMEOUT" "${aide_cmd[@]}" >"$AIDE_FAST_LOG" 2>&1; then
        aide_exit=0
    else
        aide_exit=$?
        if [ "$aide_exit" -eq 124 ] || [ "$aide_exit" -eq 137 ]; then
            log_warning "AIDE baseline timed out after ${AIDE_FAST_TIMEOUT}s; retrying once without timeout"
            if "${aide_cmd[@]}" >>"$AIDE_FAST_LOG" 2>&1; then
                aide_exit=0
            else
                aide_exit=$?
            fi
        fi
    fi

    if [ "$aide_exit" -eq 0 ]; then
        if [ -f "$AIDE_DB_NEW" ]; then
            if mv -f "$AIDE_DB_NEW" "$AIDE_DB" 2>/dev/null; then
                chmod 600 "$AIDE_DB" 2>/dev/null || true
                HARDN_STATUS "Quick AIDE baseline ready at $AIDE_DB"
            else
                log_warning "AIDE initialization succeeded but finalizing $AIDE_DB failed"
            fi
        else
            log_warning "AIDE initialization completed but $AIDE_DB_NEW not found"
        fi
    else
        log_warning "AIDE fast baseline generation failed (exit $aide_exit), see $AIDE_FAST_LOG"
    fi
else
    log_warning "AIDE not available; skipping configuration"
fi

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
# AUDIT (Enhanced with auditd MITRE ATT&CK rules)
# ==========================================
HARDN_STATUS "Installing auditd..."
if apt_install "auditd" "Installing auditd components" 120 auditd audispd-plugins; then
    HARDN_STATUS "auditd installed successfully"
    systemctl enable auditd 2>/dev/null || true
    systemctl start auditd 2>/dev/null || true
else
    log_warning "auditd installation failed, continuing..."
fi

HARDN_STATUS "Configuring auditd disk space safeguards..."
AUDIT_CONF="/etc/audit/auditd.conf"
if [ -f "$AUDIT_CONF" ]; then
    cp "$AUDIT_CONF" "$AUDIT_CONF.bak.$(date +%Y%m%d%H%M%S)" 2>/dev/null || true
    declare -A auditd_settings=(
        ["space_left"]="2048"
        ["space_left_action"]="email"
        ["admin_space_left"]="1024"
        ["admin_space_left_action"]="halt"
        ["action_mail_acct"]="root"
        ["max_log_file_action"]="rotate"
    )
    for key in "${!auditd_settings[@]}"; do
        value="${auditd_settings[$key]}"
        if grep -Eq "^[[:space:]]*$key[[:space:]]*=" "$AUDIT_CONF"; then
            sed -ri "s|^[[:space:]]*$key[[:space:]]*=.*$|$key = $value|I" "$AUDIT_CONF"
        else
            printf '%s = %s\n' "$key" "$value" >> "$AUDIT_CONF"
        fi
    done
    systemctl reload auditd 2>/dev/null || systemctl restart auditd 2>/dev/null || true
else
    log_warning "auditd.conf not found; space thresholds not set"
fi

HARDN_STATUS "Configuring MITRE ATT&CK audit rules..."

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
# FAIL2BAN HARDENING
# ==========================================
HARDN_STATUS "Configuring Fail2Ban..."

HARDN_FAIL2BAN_BANTIME="${HARDN_FAIL2BAN_BANTIME:-600}"
HARDN_FAIL2BAN_FINDTIME="${HARDN_FAIL2BAN_FINDTIME:-600}"
HARDN_FAIL2BAN_MAXRETRY="${HARDN_FAIL2BAN_MAXRETRY:-5}"

if apt_install "fail2ban" "Installing Fail2Ban" 180 fail2ban; then
    mkdir -p /etc/fail2ban/jail.d
    sed -i '/^\s*allowipv6\s*=\s*/d' /etc/fail2ban/jail.local 2>/dev/null || true
    sed -i '/^\s*\[sshd-ddos\]/I,/^\s*$/d' /etc/fail2ban/jail.local 2>/dev/null || true
    cat > /etc/fail2ban/jail.d/99-hardn.conf <<EOF
[DEFAULT]
bantime = ${HARDN_FAIL2BAN_BANTIME}
findtime = ${HARDN_FAIL2BAN_FINDTIME}
maxretry = ${HARDN_FAIL2BAN_MAXRETRY}
backend = systemd

[sshd]
enabled = true
EOF

    systemctl enable fail2ban 2>/dev/null || true
    if fail2ban-client -t >/var/log/hardn/fail2ban-config-check.log 2>&1; then
        systemctl restart fail2ban 2>/dev/null || true
    else
        log_warning "Fail2Ban configuration test failed; see /var/log/hardn/fail2ban-config-check.log"
    fi
    HARDN_STATUS "Fail2Ban configured with hardened defaults"
else
    log_warning "Fail2Ban installation failed; skipping configuration"
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
HARDN_STATUS "Configuring AppArmor profiles...enforcing security profiles while disabling problematic native apps"
sleep 2
if command -v aa-enforce >/dev/null 2>&1; then
    # Install apparmor-profiles if not present
    apt_install "apparmor" "Installing AppArmor profiles" apparmor-profiles apparmor-utils || true

    # Disable problematic native applications that cause segfaults
    HARDN_STATUS "Disabling AppArmor profiles for native applications that cause issues"
    aa-disable nautilus 2>/dev/null || log_warning "Failed to disable nautilus AppArmor profile"
    aa-disable evince 2>/dev/null || log_warning "Failed to disable evince AppArmor profile"
    aa-disable firefox 2>/dev/null || log_warning "Failed to disable firefox AppArmor profile"

    # Enforce remaining profiles for security
    aa-enforce /etc/apparmor.d/* 2>/dev/null || log_warning "Some AppArmor profiles failed to enforce"
fi

if command -v aa-status >/dev/null 2>&1; then
    aa-status > /var/log/hardn/aa-status.txt 2>&1 || log_warning "Failed to capture AppArmor status"
    HARDN_STATUS "AppArmor status captured at /var/log/hardn/aa-status.txt"
fi

# ==========================================
# COMPILER RESTRICTIONS
# ==========================================
HARDN_STATUS "Restricting compiler access..."

HARDN_COMPILER_GROUP="${HARDN_COMPILER_GROUP:-hardncompilers}"
HARDN_COMPILER_POLICY_FILE="${HARDN_COMPILER_POLICY_FILE:-/etc/hardn/compiler-policy.conf}"
HARDN_COMPILER_ALLOWED_USERS="${HARDN_COMPILER_ALLOWED_USERS:-}"

if [ -z "$HARDN_COMPILER_ALLOWED_USERS" ] && [ -n "${SUDO_USER:-}" ]; then
    HARDN_COMPILER_ALLOWED_USERS="$SUDO_USER"
fi

if [ -z "${HARDN_COMPILER_POLICY:-}" ] && [ -f "$HARDN_COMPILER_POLICY_FILE" ]; then
    HARDN_COMPILER_POLICY="$(awk 'NF && $0 !~ /^#/ {print tolower($0); exit}' "$HARDN_COMPILER_POLICY_FILE" 2>/dev/null || echo "")"
fi

HARDN_COMPILER_POLICY="${HARDN_COMPILER_POLICY:-restrict}"

compiler_candidates=(
    "/usr/bin/gcc"
    "/usr/bin/g++"
    "/usr/bin/cc"
    "/usr/bin/as"
    "/usr/bin/clang"
    "/usr/bin/clang++"
)

case "$HARDN_COMPILER_POLICY" in
    allow|permissive)
        HARDN_STATUS "Compiler restriction policy set to '$HARDN_COMPILER_POLICY'; ensuring toolchain executables are world-accessible."
        for compiler in "${compiler_candidates[@]}"; do
            if [ -e "$compiler" ] || [ -L "$compiler" ]; then
                target_path="$(readlink -f "$compiler" 2>/dev/null || echo "$compiler")"
                if [ -e "$target_path" ]; then
                    chown root:root "$target_path" 2>/dev/null || true
                    chmod 0755 "$target_path" 2>/dev/null || true
                fi
            fi
        done
        ;;
    disable|off|none)
        HARDN_STATUS "Compiler restriction policy disabled; no permission changes applied."
        ;;
    *)
        HARDN_STATUS "Compiler restriction policy set to '$HARDN_COMPILER_POLICY'; limiting compiler execution to group '$HARDN_COMPILER_GROUP'."

        if ! getent group "$HARDN_COMPILER_GROUP" >/dev/null 2>&1; then
            log_update "Creating compiler access group '$HARDN_COMPILER_GROUP'"
            groupadd "$HARDN_COMPILER_GROUP" 2>/dev/null || true
        fi

        if [ -n "$HARDN_COMPILER_ALLOWED_USERS" ]; then
            for user in $HARDN_COMPILER_ALLOWED_USERS; do
                if id "$user" >/dev/null 2>&1; then
                    usermod -a -G "$HARDN_COMPILER_GROUP" "$user" 2>/dev/null || log_warning "Failed adding $user to $HARDN_COMPILER_GROUP"
                else
                    log_warning "Requested compiler access for unknown user '$user'"
                fi
            done
        fi

        for compiler in "${compiler_candidates[@]}"; do
            if [ -e "$compiler" ] || [ -L "$compiler" ]; then
                target_path="$(readlink -f "$compiler" 2>/dev/null || echo "$compiler")"
                if [ -e "$target_path" ]; then
                    chown root:"$HARDN_COMPILER_GROUP" "$target_path" 2>/dev/null || true
                    chmod 0750 "$target_path" 2>/dev/null || true
                fi
            fi
        done
        ;;
esac

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
# clamav
# ==========================================
HARDN_STATUS "Installing ClamAV..."
if ! apt_install "clamav" "Installing ClamAV" 120 clamav clamav-daemon; then
    log_warning "ClamAV installation failed, continuing..."
fi
systemctl enable clamav-daemon 2>/dev/null || true
systemctl start clamav-daemon 2>/dev/null || true       
# Update ClamAV database
mkdir -p /var/log/hardn 2>/dev/null || true
FRESHCLAM_LOG="/var/log/hardn/freshclam-update.log"
HARDN_STATUS "Updating ClamAV signatures..."
update_succeeded=0

if systemctl list-unit-files | grep -q '^clamav-freshclam.service'; then
    systemctl enable clamav-freshclam 2>/dev/null || true
    systemctl stop clamav-freshclam 2>/dev/null || true
fi

if command -v freshclam >/dev/null 2>&1; then
    if timeout 300 freshclam --stdout --no-warnings >"$FRESHCLAM_LOG" 2>&1; then
        update_succeeded=1
        HARDN_STATUS "ClamAV signature update complete (see $FRESHCLAM_LOG)"
    fi
fi

if [ $update_succeeded -eq 0 ]; then
    if systemctl list-unit-files | grep -q '^clamav-freshclam.service'; then
        if systemctl restart clamav-freshclam 2>/dev/null; then
            update_succeeded=1
            HARDN_STATUS "clamav-freshclam service restarted to refresh signatures"
        fi
    fi
fi

if systemctl list-unit-files | grep -q '^clamav-freshclam.service'; then
    systemctl start clamav-freshclam 2>/dev/null || true
fi

if [ $update_succeeded -eq 0 ]; then
    if compgen -G '/var/lib/clamav/*.[cC][lL][dD]' >/dev/null 2>&1 || compgen -G '/var/lib/clamav/*.[cC][vV][dD]' >/dev/null 2>&1; then
        HARDN_STATUS "Existing ClamAV signatures detected; updates will occur when connectivity is available (see $FRESHCLAM_LOG)"
    else
        log_warning "ClamAV signatures missing; review $FRESHCLAM_LOG for remediation"
    fi
fi

# =========================================
# rkhunter
# ==========================================
HARDN_STATUS "Installing rkhunter..."
if apt_install "rkhunter" "Installing rkhunter" 120 rkhunter; then
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
if command -v update-initramfs >/dev/null 2>&1; then
    update-initramfs -u 2>/dev/null || log_warning "update-initramfs failed after FireWire blacklist"
fi

# ==========================================
# sysstat
# ==========================================
HARDN_STATUS "Installing sysstat..."
if apt_install "sysstat" "Installing sysstat" 120 sysstat; then
    HARDN_STATUS "sysstat installed successfully"
    # Configure sysstat
    sed -i 's|ENABLED="false"|ENABLED="true"|g' /etc/default/sysstat 2>/dev/null || true
    systemctl enable sysstat 2>/dev/null || true
    systemctl start sysstat 2>/dev/null || true
else
    log_warning "sysstat installation failed, continuing..."
fi

# ==========================================
# ACCT (PROCESS ACCOUNTING)
# ==========================================
HARDN_STATUS "Installing process accounting (acct)..."
acct_package=""
if apt_install "acct" "Installing process accounting tools" 120 acct; then
    acct_package="acct"
elif apt_install "acct_psacct" "Installing process accounting tools (psacct fallback)" 120 psacct; then
    acct_package="psacct"
fi

if [ -n "$acct_package" ]; then
    HARDN_STATUS "Process accounting package ($acct_package) installed"
    accounting_activated=0
    for svc in acct psacct; do
        if systemctl list-unit-files | grep -q "^$svc.service"; then
            systemctl enable "$svc" 2>/dev/null || true
            systemctl start "$svc" 2>/dev/null || true
            HARDN_STATUS "Process accounting service $svc enabled"
            accounting_activated=1
            break
        fi
    done

    if command -v accton >/dev/null 2>&1; then
        if accton on 2>/dev/null; then
            HARDN_STATUS "Process accounting now actively capturing data"
            accounting_activated=1
        fi
    fi

    if [ $accounting_activated -eq 0 ]; then
        log_warning "Process accounting package installed but service not activated; investigate manually"
    fi
else
    log_warning "Process accounting package installation failed, continuing..."
fi

# unattended-upgrades
# ==========================================
HARDN_STATUS "Installing unattended-upgrades..."
if apt_install "unattended_upgrades" "Installing unattended-upgrades" 120 unattended-upgrades; then
    HARDN_STATUS "unattended-upgrades installed successfully"
    # Configure unattended-upgrades
    dpkg-reconfigure -f noninteractive unattended-upgrades 2>/dev/null || log_warning "unattended-upgrades reconfiguration failed"
    cat > /etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
EOF
    if [ -f /etc/apt/apt.conf.d/50unattended-upgrades ]; then
    sed -i 's|^[[:space:]]*//[[:space:]]*"${distro_id}:${distro_codename}-security";|        "${distro_id}:${distro_codename}-security";|' /etc/apt/apt.conf.d/50unattended-upgrades
        if ! grep -q 'Unattended-Upgrade::Origins-Pattern' /etc/apt/apt.conf.d/50unattended-upgrades 2>/dev/null; then
            cat >> /etc/apt/apt.conf.d/50unattended-upgrades <<'EOF'
Unattended-Upgrade::Origins-Pattern {
        "${distro_id}:${distro_codename}-security";
        "${distro_id}:${distro_codename}-updates";
};
EOF
        fi
    fi
else
    log_warning "unattended-upgrades installation failed, continuing..."
fi

# ==========================================
# APT HARDENING
# ==========================================
HARDN_STATUS "Applying APT hardening configuration..."
cat > /etc/apt/apt.conf.d/99hardn <<'EOF'
APT::Install-Suggests "false";
APT::Install-Recommends "false";
APT::Get::AllowUnauthenticated "false";
APT::Get::Assume-Yes "false";
Acquire::AllowDowngrade "false";
Acquire::http::AllowRedirect "false";
Acquire::Retries "3";
EOF

HARDN_STATUS "Installing debsums and verifying package checksums..."
if apt_install "debsums" "Installing debsums" 180 debsums; then
    DEBSUMS_LOG="/var/log/hardn/debsums-baseline.log"
    if debsums --all --silent >"$DEBSUMS_LOG" 2>&1; then
        log_update "debsums verification complete; no checksum issues detected"
    else
        {
            echo ""
            echo "# Additional context"
            debsums --list-missing 2>&1
            debsums --changed 2>&1
        } >>"$DEBSUMS_LOG" 2>&1 || true
        log_update "debsums reported checksum issues; see $DEBSUMS_LOG"
    fi
else
    log_warning "debsums installation failed"
fi

# =========================================
# umask
# ==========================================
HARDN_STATUS "Setting secure umask in system files..."
if ! grep -q "umask 022" /etc/bash.bashrc 2>/dev/null; then
    echo "umask 022" >> /etc/bash.bashrc
fi

# ==========================================
# LYNIS VALIDATION
# ==========================================
HARDN_STATUS "Running Lynis baseline scan..."
if apt_install "lynis" "Installing Lynis" 180 lynis; then
    LYNIS_LOG="/var/log/hardn/lynis-baseline.log"
    LYNIS_REPORT="/var/log/hardn/lynis-report.dat"
    if ! timeout 900 lynis audit system --quick --no-colors --logfile "$LYNIS_LOG" --report-file "$LYNIS_REPORT" >/dev/null 2>&1; then
        log_warning "Lynis baseline scan encountered issues; review $LYNIS_LOG"
    else
        HARDN_STATUS "Lynis baseline complete. Report: $LYNIS_REPORT"
    fi
else
    log_warning "Lynis installation failed; skipping baseline scan"
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
echo "  ✓ Authentication hardening (password history & inactivity)"
echo "  ✓ Service account shell restrictions"
echo "  ✓ Comprehensive SSH configuration"
echo "  ✓ Secure file permissions and sudo logging"
echo "  ✓ Kernel security parameters & IPv6 policy documentation"
echo "  ✓ Entropy daemon and time synchronization"
echo "  ✓ Persistent journald with remote syslog forwarding"
echo "  ✓ AIDE fast baseline and debsums checksums"
echo "  ✓ MITRE ATT&CK audit rules"
echo "  ✓ Strict firewall configuration"
echo "  ✓ Log rotation configured"
echo "  ✓ Core dumps disabled"
echo "  ✓ AppArmor profiles configured (problematic apps disabled, others enforced)"
echo "  ✓ Compiler access restricted"
echo "  ✓ Network parameters tuned"
echo "  ✓ Lynis baseline scan completed"
echo ""
echo -e "${YELLOW}Note:${NC} System reboot recommended for all changes to take effect."
echo -e "${YELLOW}Note:${NC} Run 'lynis audit system' to verify improvements."
echo ""

HARDN_STATUS "Enhanced hardening module completed successfully!"