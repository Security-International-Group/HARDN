#!/bin/bash
# Fix script for legion-daemon.service issues
# This script fixes path and directory issues with the legion-daemon service

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}HARDN Legion Service Fix Script${NC}"
echo "================================"

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}This script must be run as root${NC}"
   exit 1
fi

echo "Checking for issues..."

# 1. Check for incorrect symlinks
if [ -L "/usr/local/bin/hardn" ]; then
    echo -e "${YELLOW}Found symlink at /usr/local/bin/hardn - removing...${NC}"
    rm -f /usr/local/bin/hardn
fi

# 2. Ensure correct binary exists
if [ ! -f "/usr/bin/hardn" ]; then
    echo -e "${RED}ERROR: /usr/bin/hardn not found!${NC}"
    echo "Please reinstall HARDN package"
    exit 1
else
    echo -e "${GREEN}✓ Found HARDN binary at /usr/bin/hardn${NC}"
fi

# 3. Create necessary directories
echo "Creating necessary directories..."
mkdir -p /var/lib/hardn/legion
mkdir -p /var/log/hardn
chmod 755 /var/lib/hardn
chmod 755 /var/lib/hardn/legion
chmod 755 /var/log/hardn
echo -e "${GREEN}✓ Directories created${NC}"

# 4. Update the service file if it exists
SERVICE_FILE="/lib/systemd/system/legion-daemon.service"
if [ -f "$SERVICE_FILE" ]; then
    echo "Updating legion-daemon.service..."
    
    # Create updated service file
    cat > "$SERVICE_FILE" << 'EOF'
[Unit]
Description=HARDN LEGION Security Monitoring Daemon
After=network.target hardn-monitor.service
Wants=network.target hardn-monitor.service

[Service]
Type=simple
User=root
Group=root
# Create necessary directories before starting
ExecStartPre=/bin/bash -c 'mkdir -p /var/lib/hardn/legion /var/log/hardn && chmod 755 /var/lib/hardn /var/lib/hardn/legion'
# Use the correct binary path and create baseline if needed
ExecStart=/bin/bash -c 'if [ ! -d /var/lib/hardn/legion ] || [ -z "$(ls -A /var/lib/hardn/legion/baseline_*.json 2>/dev/null)" ]; then echo "Creating LEGION baseline..."; /usr/bin/hardn legion --create-baseline --json; fi; exec /usr/bin/hardn legion --daemon --verbose'
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=legion-daemon
# Set environment to use correct binary
Environment="PATH=/usr/bin:/bin:/usr/sbin:/sbin"

# Security settings - adjusted to avoid namespace issues
NoNewPrivileges=yes
ProtectHome=yes
ProtectSystem=strict
ReadWritePaths=/var/lib/hardn /var/log/hardn
PrivateTmp=yes

# Resource limits
MemoryMax=256M
CPUQuota=30%

[Install]
WantedBy=multi-user.target
EOF
    
    echo -e "${GREEN}✓ Service file updated${NC}"
fi

# 5. Reload systemd
echo "Reloading systemd daemon..."
systemctl daemon-reload
echo -e "${GREEN}✓ Systemd reloaded${NC}"

# 6. Reset failed state if needed
if systemctl is-failed legion-daemon.service >/dev/null 2>&1; then
    echo "Resetting failed state..."
    systemctl reset-failed legion-daemon.service
    echo -e "${GREEN}✓ Failed state cleared${NC}"
fi

# 7. Try to restart the service
echo ""
echo "Attempting to restart legion-daemon.service..."
if systemctl restart legion-daemon.service; then
    echo -e "${GREEN}✓ Service restarted successfully!${NC}"
    echo ""
    echo "Service status:"
    systemctl status legion-daemon.service --no-pager | head -15
else
    echo -e "${YELLOW}Service restart failed. Checking logs...${NC}"
    echo ""
    echo "Recent error messages:"
    journalctl -u legion-daemon.service -n 10 --no-pager
fi

echo ""
echo -e "${GREEN}Fix script completed!${NC}"
echo ""
echo "You can check the service status with:"
echo "  systemctl status legion-daemon.service"
echo ""
echo "View logs with:"
echo "  journalctl -u legion-daemon.service -f"