#!/bin/bash
# security-tools-manager.sh - Interactive Security Tools Manager for HARDN
# This script provides an easy way to activate, deactivate, and check security tools

set -e

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}This script must be run as root${NC}" 
   exit 1
fi

# Function to print header
print_header() {
    clear
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║        HARDN SECURITY TOOLS ACTIVATION MANAGER              ║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

# Function to check if a package is installed
check_package_installed() {
    local package=$1
    if dpkg -l | grep -q "^ii.*$package"; then
        return 0
    else
        return 1
    fi
}

# Function to check tool status
check_tool_status() {
    local tool=$1
    case $tool in
        "AIDE")
            if systemctl is-active dailyaidecheck.timer >/dev/null 2>&1; then
                echo "ACTIVE"
            elif systemctl is-enabled dailyaidecheck.timer >/dev/null 2>&1; then
                echo "ENABLED"
            elif check_package_installed aide; then
                echo "INSTALLED"
            else
                echo "NOT_INSTALLED"
            fi
            ;;
        "AppArmor")
            if systemctl is-active apparmor >/dev/null 2>&1; then
                echo "ACTIVE"
            elif systemctl is-enabled apparmor >/dev/null 2>&1; then
                echo "ENABLED"
            elif check_package_installed apparmor; then
                echo "INSTALLED"
            else
                echo "NOT_INSTALLED"
            fi
            ;;
        "Fail2Ban")
            if systemctl is-active fail2ban >/dev/null 2>&1; then
                echo "ACTIVE"
            elif systemctl is-enabled fail2ban >/dev/null 2>&1; then
                echo "ENABLED"
            elif check_package_installed fail2ban; then
                echo "INSTALLED"
            else
                echo "NOT_INSTALLED"
            fi
            ;;
        "UFW")
            if ufw status 2>/dev/null | grep -q "Status: active"; then
                echo "ACTIVE"
            elif check_package_installed ufw; then
                echo "INSTALLED"
            else
                echo "NOT_INSTALLED"
            fi
            ;;
        "Auditd")
            if systemctl is-active auditd >/dev/null 2>&1; then
                echo "ACTIVE"
            elif systemctl is-enabled auditd >/dev/null 2>&1; then
                echo "ENABLED"
            elif check_package_installed auditd; then
                echo "INSTALLED"
            else
                echo "NOT_INSTALLED"
            fi
            ;;
        "RKHunter")
            if check_package_installed rkhunter; then
                if [ -f /var/lib/rkhunter/db/rkhunter.dat ]; then
                    echo "ACTIVE"
                else
                    echo "INSTALLED"
                fi
            else
                echo "NOT_INSTALLED"
            fi
            ;;
        "ClamAV")
            if systemctl is-active clamav-daemon >/dev/null 2>&1; then
                echo "ACTIVE"
            elif systemctl is-enabled clamav-daemon >/dev/null 2>&1; then
                echo "ENABLED"
            elif check_package_installed clamav-daemon; then
                echo "INSTALLED"
            else
                echo "NOT_INSTALLED"
            fi
            ;;
        "Suricata")
            if systemctl is-active suricata >/dev/null 2>&1; then
                echo "ACTIVE"
            elif systemctl is-enabled suricata >/dev/null 2>&1; then
                echo "ENABLED"
            elif check_package_installed suricata; then
                echo "INSTALLED"
            else
                echo "NOT_INSTALLED"
            fi
            ;;
        "OSSEC")
            if pgrep -x "ossec-analysisd" >/dev/null 2>&1; then
                echo "ACTIVE"
            elif [ -d /var/ossec ]; then
                echo "INSTALLED"
            else
                echo "NOT_INSTALLED"
            fi
            ;;
        "Lynis")
            if systemctl is-active lynis.timer >/dev/null 2>&1; then
                echo "ACTIVE"
            elif systemctl is-enabled lynis.timer >/dev/null 2>&1; then
                echo "ENABLED"
            elif check_package_installed lynis; then
                echo "INSTALLED"
            else
                echo "NOT_INSTALLED"
            fi
            ;;
    esac
}

# Function to activate a tool
activate_tool() {
    local tool=$1
    echo -e "${YELLOW}Activating $tool...${NC}"
    
    case $tool in
        "AIDE")
            if ! check_package_installed aide; then
                echo -e "${YELLOW}Installing AIDE...${NC}"
                apt-get update && apt-get install -y aide aide-common
            fi
            
            # Initialize AIDE database if not exists
            if [ ! -f /var/lib/aide/aide.db ]; then
                echo -e "${YELLOW}Initializing AIDE database (this may take a while)...${NC}"
                aideinit
                if [ -f /var/lib/aide/aide.db.new ]; then
                    mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
                fi
            fi
            
            # Enable the timer
            systemctl enable dailyaidecheck.timer 2>/dev/null || true
            systemctl start dailyaidecheck.timer 2>/dev/null || true
            echo -e "${GREEN}✓ AIDE activated successfully${NC}"
            ;;
            
        "AppArmor")
            if ! check_package_installed apparmor; then
                echo -e "${YELLOW}Installing AppArmor...${NC}"
                apt-get update && apt-get install -y apparmor apparmor-utils apparmor-profiles
            fi
            systemctl enable apparmor
            systemctl start apparmor
            echo -e "${GREEN}✓ AppArmor activated successfully${NC}"
            ;;
            
        "Fail2Ban")
            if ! check_package_installed fail2ban; then
                echo -e "${YELLOW}Installing Fail2Ban...${NC}"
                apt-get update && apt-get install -y fail2ban
            fi
            systemctl enable fail2ban
            systemctl start fail2ban
            echo -e "${GREEN}✓ Fail2Ban activated successfully${NC}"
            ;;
            
        "UFW")
            if ! check_package_installed ufw; then
                echo -e "${YELLOW}Installing UFW...${NC}"
                apt-get update && apt-get install -y ufw
            fi
            # Enable UFW with default settings
            echo -e "${YELLOW}Enabling UFW with default settings...${NC}"
            ufw --force enable
            echo -e "${GREEN}✓ UFW activated successfully${NC}"
            ;;
            
        "Auditd")
            if ! check_package_installed auditd; then
                echo -e "${YELLOW}Installing Auditd...${NC}"
                apt-get update && apt-get install -y auditd audispd-plugins
            fi
            systemctl enable auditd
            systemctl start auditd
            echo -e "${GREEN}✓ Auditd activated successfully${NC}"
            ;;
            
        "RKHunter")
            if ! check_package_installed rkhunter; then
                echo -e "${YELLOW}Installing RKHunter...${NC}"
                apt-get update && apt-get install -y rkhunter
            fi
            echo -e "${YELLOW}Updating RKHunter database...${NC}"
            rkhunter --propupd
            rkhunter --update || true
            echo -e "${GREEN}✓ RKHunter activated successfully${NC}"
            ;;
            
        "ClamAV")
            if ! check_package_installed clamav-daemon; then
                echo -e "${YELLOW}Installing ClamAV...${NC}"
                apt-get update && apt-get install -y clamav clamav-daemon clamav-freshclam
            fi
            
            # Stop freshclam service temporarily to update database
            systemctl stop clamav-freshclam 2>/dev/null || true
            
            echo -e "${YELLOW}Updating ClamAV virus definitions...${NC}"
            freshclam || true
            
            systemctl enable clamav-freshclam
            systemctl start clamav-freshclam
            systemctl enable clamav-daemon
            systemctl start clamav-daemon
            echo -e "${GREEN}✓ ClamAV activated successfully${NC}"
            ;;
            
        "Suricata")
            if ! check_package_installed suricata; then
                echo -e "${YELLOW}Installing Suricata...${NC}"
                apt-get update && apt-get install -y suricata suricata-update
            fi
            
            echo -e "${YELLOW}Updating Suricata rules...${NC}"
            suricata-update || true
            
            systemctl enable suricata
            systemctl start suricata
            echo -e "${GREEN}✓ Suricata activated successfully${NC}"
            ;;
            
        "OSSEC")
            if [ ! -d /var/ossec ]; then
                echo -e "${RED}OSSEC is not installed. Please install OSSEC manually.${NC}"
                echo "Visit: https://www.ossec.net/downloads/"
                return 1
            fi
            /var/ossec/bin/ossec-control start
            echo -e "${GREEN}✓ OSSEC activated successfully${NC}"
            ;;
            
        "Lynis")
            if ! check_package_installed lynis; then
                echo -e "${YELLOW}Installing Lynis...${NC}"
                apt-get update && apt-get install -y lynis
            fi
            
            # Create a systemd timer if it doesn't exist
            if [ ! -f /etc/systemd/system/lynis.timer ]; then
                cat > /etc/systemd/system/lynis.timer <<EOF
[Unit]
Description=Daily Lynis security audit
[Timer]
OnCalendar=daily
Persistent=true
[Install]
WantedBy=timers.target
EOF
                
                cat > /etc/systemd/system/lynis.service <<EOF
[Unit]
Description=Lynis security audit
[Service]
Type=oneshot
ExecStart=/usr/bin/lynis audit system --cronjob
[Install]
WantedBy=multi-user.target
EOF
                systemctl daemon-reload
            fi
            
            systemctl enable lynis.timer
            systemctl start lynis.timer
            echo -e "${GREEN}✓ Lynis activated successfully${NC}"
            ;;
    esac
}

# Function to display tool status
display_status() {
    echo -e "${CYAN}Current Security Tools Status:${NC}"
    echo ""
    
    declare -a tools=("AIDE" "AppArmor" "Fail2Ban" "UFW" "Auditd" "RKHunter" "ClamAV" "Suricata" "OSSEC" "Lynis")
    
    for tool in "${tools[@]}"; do
        status=$(check_tool_status "$tool")
        case $status in
            "ACTIVE")
                echo -e "  ${GREEN}✓${NC} $tool ${GREEN}[ACTIVE]${NC}"
                ;;
            "ENABLED")
                echo -e "  ${YELLOW}●${NC} $tool ${YELLOW}[ENABLED]${NC}"
                ;;
            "INSTALLED")
                echo -e "  ${BLUE}○${NC} $tool ${BLUE}[INSTALLED]${NC}"
                ;;
            "NOT_INSTALLED")
                echo -e "  ${RED}✗${NC} $tool ${RED}[NOT INSTALLED]${NC}"
                ;;
        esac
    done
    echo ""
}

# Function to activate all tools
activate_all() {
    echo -e "${CYAN}Activating all security tools...${NC}"
    echo ""
    
    declare -a tools=("AppArmor" "Fail2Ban" "UFW" "Auditd" "RKHunter" "ClamAV" "Suricata" "Lynis" "AIDE")
    
    for tool in "${tools[@]}"; do
        echo "----------------------------------------"
        activate_tool "$tool"
        sleep 1
    done
    
    echo ""
    echo -e "${GREEN}All available security tools have been activated!${NC}"
}

# Main menu
main_menu() {
    while true; do
        print_header
        display_status
        
        echo "Options:"
        echo "  1) Activate AIDE"
        echo "  2) Activate AppArmor"
        echo "  3) Activate Fail2Ban"
        echo "  4) Activate UFW"
        echo "  5) Activate Auditd"
        echo "  6) Activate RKHunter"
        echo "  7) Activate ClamAV"
        echo "  8) Activate Suricata"
        echo "  9) Activate OSSEC"
        echo " 10) Activate Lynis"
        echo ""
        echo "  A) Activate ALL tools"
        echo "  R) Refresh status"
        echo "  Q) Quit"
        echo ""
        
        read -p "Enter your choice: " choice
        
        case $choice in
            1) activate_tool "AIDE"; read -p "Press Enter to continue..." ;;
            2) activate_tool "AppArmor"; read -p "Press Enter to continue..." ;;
            3) activate_tool "Fail2Ban"; read -p "Press Enter to continue..." ;;
            4) activate_tool "UFW"; read -p "Press Enter to continue..." ;;
            5) activate_tool "Auditd"; read -p "Press Enter to continue..." ;;
            6) activate_tool "RKHunter"; read -p "Press Enter to continue..." ;;
            7) activate_tool "ClamAV"; read -p "Press Enter to continue..." ;;
            8) activate_tool "Suricata"; read -p "Press Enter to continue..." ;;
            9) activate_tool "OSSEC"; read -p "Press Enter to continue..." ;;
            10) activate_tool "Lynis"; read -p "Press Enter to continue..." ;;
            [Aa]) activate_all; read -p "Press Enter to continue..." ;;
            [Rr]) continue ;;
            [Qq]) 
                echo -e "${CYAN}Goodbye!${NC}"
                exit 0 
                ;;
            *) 
                echo -e "${RED}Invalid choice. Press Enter to continue...${NC}"
                read
                ;;
        esac
    done
}

# Check for command line arguments
if [ $# -eq 0 ]; then
    main_menu
else
    case $1 in
        --status)
            display_status
            ;;
        --activate-all)
            activate_all
            ;;
        --help)
            echo "HARDN Security Tools Manager"
            echo ""
            echo "Usage: $0 [option]"
            echo ""
            echo "Options:"
            echo "  --status        Display current status of all security tools"
            echo "  --activate-all  Activate all security tools non-interactively"
            echo "  --help         Display this help message"
            echo ""
            echo "Run without arguments for interactive menu"
            ;;
        *)
            echo "Unknown option: $1"
            echo "Run '$0 --help' for usage information"
            exit 1
            ;;
    esac
fi