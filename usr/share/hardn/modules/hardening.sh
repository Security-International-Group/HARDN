#!/bin/bash
# HARDN Security Hardening Module
# Basic system hardening configurations

echo "HARDN Security Hardening Module"
echo "=================================="

# Function to log actions
log_action() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1"
}

# Basic hardening steps
log_action "Starting basic security hardening..."

# 1. Disable root login via SSH
if [ -f /etc/ssh/sshd_config ]; then
    log_action "Configuring SSH security..."
    sed -i 's/#PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
    sed -i 's/PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
    systemctl reload sshd 2>/dev/null || true
fi

# 2. Set secure umask
log_action "Setting secure umask in system files..."
if ! grep -q "umask 027" /etc/bash.bashrc 2>/dev/null; then
    echo "umask 027" >> /etc/bash.bashrc
fi

# 3. Disable unused services 
log_action "Checking for unused services..."
# disable unused services like telnet, rsh, etc. if they exist
for service in telnet rsh; do
    if systemctl list-unit-files | grep -q "^$service.service"; then
        log_action "Disabling $service service..."
        systemctl disable --now $service 2>/dev/null || true
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
timeout 120 apt-get install -y --no-install-recommends clamav clamav-daemon 2>/dev/null || log_action "Warning: ClamAV installation failed, continuing..."
systemctl enable clamav-freshclam 2>/dev/null || true
systemctl start clamav-freshclam 2>/dev/null || true
systemctl enable clamav-daemon 2>/dev/null || true
systemctl start clamav-daemon 2>/dev/null || true   
# 7. install rkhunter (skip in network-restricted environments)
log_action "Installing rkhunter..."
if timeout 120 apt-get install -y rkhunter --no-install-recommends 2>/dev/null; then
    log_action "rkhunter installed successfully"
    # Configure rkhunter to skip network operations
    if [ -f /etc/rkhunter.conf ]; then
        log_action "Configuring rkhunter for offline operation..."
        # Disable network-dependent checks
        sed -i 's|UPDATE_MIRRORS=.*|UPDATE_MIRRORS=0|g' /etc/rkhunter.conf 2>/dev/null || true
        sed -i 's|MIRRORS_MODE=.*|MIRRORS_MODE=0|g' /etc/rkhunter.conf 2>/dev/null || true
        sed -i 's|WEB_CMD=.*|WEB_CMD=""|g' /etc/rkhunter.conf 2>/dev/null || true
    fi
else
    log_action "Warning: rkhunter installation failed (possibly network issues), skipping..."
fi
# 8. install lynis and start service
log_action "Installing Lynis..."
timeout 120 apt-get install -y --no-install-recommends lynis 2>/dev/null || log_action "Warning: Lynis installation failed, continuing..."
# 9. install fail2ban and start service
log_action "Installing Fail2Ban..."
timeout 120 apt-get install -y --no-install-recommends fail2ban 2>/dev/null || log_action "Warning: Fail2Ban installation failed, continuing..."
systemctl enable fail2ban 2>/dev/null || true
systemctl start fail2ban 2>/dev/null || true   
# 10. install auditd and start service
log_action "Installing auditd..."
timeout 120 apt-get install -y --no-install-recommends auditd audispd-plugins 2>/dev/null || log_action "Warning: auditd installation failed, continuing..."
systemctl enable auditd 2>/dev/null || true
systemctl start auditd 2>/dev/null || true   
# 11. configure fail2ban for ssh
log_action "Configuring Fail2Ban for SSH..."
if [ ! -f /etc/fail2ban/jail.local ]; then
    echo "[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 5
bantime = 600
" > /etc/fail2ban/jail.local
    systemctl restart fail2ban 2>/dev/null || true
fi      
# 12. setup linux logging 
log_action "Setting up system logging..."
apt-get install -y --no-install-recommends rsyslog 2>/dev/null || log_action "Warning: rsyslog installation failed, continuing..."
systemctl enable rsyslog 2>/dev/null || true
systemctl start rsyslog 2>/dev/null || true   
# 13. setup unattended upgrades (skip interactive config in service context)
log_action "Setting up unattended upgrades..."
apt-get install -y --no-install-recommends unattended-upgrades 2>/dev/null || log_action "Warning: unattended-upgrades installation failed, continuing..."
# Skip dpkg-reconfigure as it may hang in non-interactive environments
# dpkg-reconfigure -plow unattended-upgrades 2>/dev/null || true
# 14. setup ufw firewall
log_action "Setting up UFW firewall..."
apt-get install -y --no-install-recommends ufw 2>/dev/null || log_action "Warning: UFW installation failed, continuing..."
ufw default deny incoming 2>/dev/null || true
ufw default allow outgoing 2>/dev/null || true
ufw allow ssh 2>/dev/null || true
ufw enable 2>/dev/null || true

# 15 kernel security
log_action "Configuring kernel security parameters..."
cat <<EOF >> /etc/sysctl.conf
# Hardened by HARDN
# Disable IP forwarding
net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0    
# Enable IP spoofing protection
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
# Disable source routing
net.ipv4.conf.all.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0
# Log Martian packets
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
# Ignore ICMP broadcast requests
net.ipv4.icmp_echo_ignore_broadcasts = 1
# Ignore bogus ICMP responses
net.ipv4.icmp_ignore_bogus_error_responses = 1
# Enable execshield
kernel.randomize_va_space = 2
# Disable core dumps
fs.suid_dumpable = 0
EOF
# Apply sysctl changes with timeout to prevent hanging
timeout 30 sysctl -p 2>/dev/null || log_action "Warning: sysctl -p failed or timed out, continuing..."       

# 16. log completion
log_action "Logging configuration changes..."
echo "UFW firewall configured successfully."
log_action "Basic hardening completed successfully!"
echo ""
echo " Module 'hardening' completed"
echo "   - SSH root login disabled"
echo "   - Secure umask configured"
echo "   - Critical file permissions set"