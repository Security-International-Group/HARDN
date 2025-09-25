#!/bin/bash

# HARDN Interactive Service Manager
# This script provides an interactive menu for managing HARDN services and modules

set -euo pipefail

# Color codes for better UI
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
PURPLE='\033[0;35m'
NC='\033[0m' # No Color
BOLD='\033[1m'

# Configuration
HARDN_BIN="/usr/local/bin/hardn"
LOG_DIR="/var/log/hardn"

print_colored() {
    local color=$1
    shift
    echo -e "${color}$@${NC}"
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_colored $RED "❌ This script must be run as root!"
        echo "Please run with: sudo $0"
        exit 1
    fi
}

display_header() {
    clear
    echo -e "${CYAN}╔═══════════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${NC}                     ${BOLD}HARDN Service Manager${NC}                                  ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}         Linux Security Hardening & Extended Detection Toolkit              ${CYAN}║${NC}"
    echo -e "${CYAN}╚═══════════════════════════════════════════════════════════════════════════╝${NC}"
    echo
}

check_service_status() {
    local service_name=$1
    if systemctl is-active --quiet "$service_name" 2>/dev/null; then
        echo "active"
    elif systemctl is-enabled --quiet "$service_name" 2>/dev/null; then
        echo "enabled"
    else
        echo "inactive"
    fi
}

display_service_status() {
    echo -e "\n${BOLD}Current Service Status:${NC}"
    echo -e "─────────────────────────────────────────────────"
    
    local services=("hardn.service" "hardn-api.service" "legion-daemon.service")
    
    for service in "${services[@]}"; do
        local status=$(check_service_status "$service")
        local display_name=$(echo "$service" | sed 's/.service//')
        
        case $status in
            "active")
                print_colored $GREEN "  ● $display_name: Running ✓"
                ;;
            "enabled")
                print_colored $YELLOW "  ● $display_name: Enabled (not running)"
                ;;
            *)
                print_colored $RED "  ● $display_name: Inactive ✗"
                ;;
        esac
    done
    echo
}

manage_service() {
    local service_name=$1
    local action=$2
    
    echo -n "  ${action^}ing $service_name... "
    
    if systemctl $action "$service_name" 2>/dev/null; then
        print_colored $GREEN "✓ Success"
        if [[ "$action" == "start" || "$action" == "restart" ]]; then
            sleep 2  # Give service time to start
        fi
    else
        print_colored $RED "✗ Failed"
        echo "  Check logs with: journalctl -u $service_name -n 50"
    fi
}

run_legion_menu() {
    while true; do
        display_header
        echo -e "${BOLD}LEGION Security Monitoring Options:${NC}"
        echo -e "─────────────────────────────────────────────────"
        echo
        echo "1) Run LEGION Once (Security Assessment)"
        echo "2) Start LEGION Daemon (Continuous Monitoring)"
        echo "3) Stop LEGION Daemon"
        echo "4) View LEGION Logs"
        echo "5) Check LEGION Status"
        echo "6) Run LEGION with Custom Options"
        echo
        echo "0) Back to Main Menu"
        echo
        read -p "Select option [0-6]: " legion_choice
        
        case $legion_choice in
            1)
                echo -e "\n${BOLD}Running LEGION security assessment...${NC}"
                $HARDN_BIN legion
                read -p $'\nPress Enter to continue...'
                ;;
            2)
                echo -e "\n${BOLD}Starting LEGION daemon...${NC}"
                manage_service "legion-daemon.service" "start"
                read -p $'\nPress Enter to continue...'
                ;;
            3)
                echo -e "\n${BOLD}Stopping LEGION daemon...${NC}"
                manage_service "legion-daemon.service" "stop"
                read -p $'\nPress Enter to continue...'
                ;;
            4)
                echo -e "\n${BOLD}Recent LEGION logs:${NC}"
                journalctl -u legion-daemon.service -n 50 --no-pager
                read -p $'\nPress Enter to continue...'
                ;;
            5)
                echo -e "\n${BOLD}LEGION daemon status:${NC}"
                systemctl status legion-daemon.service --no-pager
                read -p $'\nPress Enter to continue...'
                ;;
            6)
                echo -e "\n${BOLD}Enter LEGION options:${NC}"
                echo "Example: --verbose --risk-threshold 3"
                read -p "Options: " legion_options
                echo -e "\n${BOLD}Running LEGION with options...${NC}"
                $HARDN_BIN legion $legion_options
                read -p $'\nPress Enter to continue...'
                ;;
            0)
                return
                ;;
            *)
                print_colored $RED "Invalid option!"
                sleep 1
                ;;
        esac
    done
}

run_modules_menu() {
    while true; do
        display_header
        echo -e "${BOLD}Available HARDN Modules:${NC}"
        echo -e "─────────────────────────────────────────────────"
        echo
        
        # Get available modules
        local modules=$($HARDN_BIN --list-modules 2>/dev/null | grep -E "^    - " | sed 's/    - //' || true)
        
        if [[ -z "$modules" ]]; then
            print_colored $RED "No modules found!"
            echo "Make sure HARDN is properly installed."
            read -p $'\nPress Enter to continue...'
            return
        fi
        
        # Display modules with numbers
        local i=1
        declare -a module_array
        while IFS= read -r module; do
            echo "$i) $module"
            module_array[$i]=$module
            ((i++))
        done <<< "$modules"
        
        echo
        echo "a) Run ALL modules"
        echo "0) Back to Main Menu"
        echo
        read -p "Select module [0-$((i-1))]: " module_choice
        
        case $module_choice in
            a|A)
                echo -e "\n${BOLD}Running all modules...${NC}"
                $HARDN_BIN --run-all-modules
                read -p $'\nPress Enter to continue...'
                ;;
            0)
                return
                ;;
            [1-9]*)
                if [[ $module_choice -lt $i && $module_choice -gt 0 ]]; then
                    local selected_module="${module_array[$module_choice]}"
                    echo -e "\n${BOLD}Running module: $selected_module${NC}"
                    $HARDN_BIN run-module "$selected_module"
                    read -p $'\nPress Enter to continue...'
                else
                    print_colored $RED "Invalid option!"
                    sleep 1
                fi
                ;;
            *)
                print_colored $RED "Invalid option!"
                sleep 1
                ;;
        esac
    done
}

run_tools_menu() {
    while true; do
        display_header
        echo -e "${BOLD}Available HARDN Tools:${NC}"
        echo -e "─────────────────────────────────────────────────"
        echo
        
        # Show tools by category
        echo -e "${PURPLE}Security Scanners:${NC}"
        echo "  1) lynis         - Security auditing tool"
        echo "  2) rkhunter      - Rootkit scanner"
        echo "  3) aide          - File integrity monitoring"
        echo "  4) chkrootkit    - Rootkit detector"
        echo
        echo -e "${PURPLE}Network Security:${NC}"
        echo "  5) ufw           - Firewall configuration"
        echo "  6) fail2ban      - Intrusion prevention"
        echo "  7) suricata      - Network IDS/IPS"
        echo
        echo -e "${PURPLE}Access Control:${NC}"
        echo "  8) apparmor      - Mandatory access control"
        echo
        echo -e "${PURPLE}System Monitoring:${NC}"
        echo "  9) auditd        - System audit daemon"
        echo
        echo "a) Run ALL tools"
        echo "0) Back to Main Menu"
        echo
        read -p "Select tool [0-9,a]: " tool_choice
        
        local tool_name=""
        case $tool_choice in
            1) tool_name="lynis" ;;
            2) tool_name="rkhunter" ;;
            3) tool_name="aide" ;;
            4) tool_name="chkrootkit" ;;
            5) tool_name="ufw" ;;
            6) tool_name="fail2ban" ;;
            7) tool_name="suricata" ;;
            8) tool_name="apparmor" ;;
            9) tool_name="auditd" ;;
            a|A)
                echo -e "\n${BOLD}Running all tools...${NC}"
                $HARDN_BIN --run-all-tools
                read -p $'\nPress Enter to continue...'
                ;;
            0)
                return
                ;;
            *)
                print_colored $RED "Invalid option!"
                sleep 1
                ;;
        esac
        
        if [[ -n "$tool_name" ]]; then
            echo -e "\n${BOLD}Running tool: $tool_name${NC}"
            $HARDN_BIN run-tool "$tool_name"
            read -p $'\nPress Enter to continue...'
        fi
    done
}

manage_services_menu() {
    while true; do
        display_header
        display_service_status
        
        echo -e "${BOLD}Service Management Options:${NC}"
        echo -e "─────────────────────────────────────────────────"
        echo
        echo "1) Start ALL HARDN Services"
        echo "2) Stop ALL HARDN Services"
        echo "3) Restart ALL HARDN Services"
        echo "4) Enable ALL Services (Start on boot)"
        echo "5) Disable ALL Services (Don't start on boot)"
        echo
        echo "6) Manage Individual Service"
        echo "7) View Service Logs"
        echo
        echo "0) Back to Main Menu"
        echo
        read -p "Select option [0-7]: " service_choice
        
        case $service_choice in
            1)
                echo -e "\n${BOLD}Starting all HARDN services...${NC}"
                for service in hardn.service hardn-api.service legion-daemon.service; do
                    manage_service "$service" "start"
                done
                read -p $'\nPress Enter to continue...'
                ;;
            2)
                echo -e "\n${BOLD}Stopping all HARDN services...${NC}"
                for service in legion-daemon.service hardn-api.service hardn.service; do
                    manage_service "$service" "stop"
                done
                read -p $'\nPress Enter to continue...'
                ;;
            3)
                echo -e "\n${BOLD}Restarting all HARDN services...${NC}"
                for service in hardn.service hardn-api.service legion-daemon.service; do
                    manage_service "$service" "restart"
                done
                read -p $'\nPress Enter to continue...'
                ;;
            4)
                echo -e "\n${BOLD}Enabling all HARDN services...${NC}"
                for service in hardn.service hardn-api.service legion-daemon.service; do
                    manage_service "$service" "enable"
                done
                read -p $'\nPress Enter to continue...'
                ;;
            5)
                echo -e "\n${BOLD}Disabling all HARDN services...${NC}"
                for service in legion-daemon.service hardn-api.service hardn.service; do
                    manage_service "$service" "disable"
                done
                read -p $'\nPress Enter to continue...'
                ;;
            6)
                echo -e "\n${BOLD}Select service:${NC}"
                echo "1) hardn.service"
                echo "2) hardn-api.service"
                echo "3) legion-daemon.service"
                read -p "Select [1-3]: " svc_num
                
                local selected_service=""
                case $svc_num in
                    1) selected_service="hardn.service" ;;
                    2) selected_service="hardn-api.service" ;;
                    3) selected_service="legion-daemon.service" ;;
                    *) 
                        print_colored $RED "Invalid selection!"
                        sleep 1
                        continue
                        ;;
                esac
                
                echo -e "\n${BOLD}Action for $selected_service:${NC}"
                echo "1) Start"
                echo "2) Stop"
                echo "3) Restart"
                echo "4) Enable"
                echo "5) Disable"
                echo "6) Status"
                read -p "Select [1-6]: " action_num
                
                case $action_num in
                    1) manage_service "$selected_service" "start" ;;
                    2) manage_service "$selected_service" "stop" ;;
                    3) manage_service "$selected_service" "restart" ;;
                    4) manage_service "$selected_service" "enable" ;;
                    5) manage_service "$selected_service" "disable" ;;
                    6) 
                        systemctl status "$selected_service" --no-pager
                        ;;
                    *)
                        print_colored $RED "Invalid action!"
                        ;;
                esac
                read -p $'\nPress Enter to continue...'
                ;;
            7)
                echo -e "\n${BOLD}Select service to view logs:${NC}"
                echo "1) hardn.service"
                echo "2) hardn-api.service"
                echo "3) legion-daemon.service"
                echo "4) All HARDN logs"
                read -p "Select [1-4]: " log_choice
                
                case $log_choice in
                    1) journalctl -u hardn.service -n 100 --no-pager ;;
                    2) journalctl -u hardn-api.service -n 100 --no-pager ;;
                    3) journalctl -u legion-daemon.service -n 100 --no-pager ;;
                    4) journalctl -u 'hardn*' -u 'legion*' -n 100 --no-pager ;;
                    *) print_colored $RED "Invalid selection!" ;;
                esac
                read -p $'\nPress Enter to continue...'
                ;;
            0)
                return
                ;;
            *)
                print_colored $RED "Invalid option!"
                sleep 1
                ;;
        esac
    done
}

main_menu() {
    while true; do
        display_header
        display_service_status
        
        echo -e "${BOLD}Main Menu:${NC}"
        echo -e "─────────────────────────────────────────────────"
        echo
        echo "1) Quick Start - Enable & Start All Services"
        echo "2) Manage HARDN Services"
        echo "3) Run HARDN Modules"
        echo "4) Run Security Tools"
        echo "5) LEGION Security Monitoring"
        echo "6) Generate Security Report"
        echo "7) View HARDN Status"
        echo "8) Sandbox Mode (Network Isolation)"
        echo
        echo "h) View HARDN Help"
        echo "q) Quit"
        echo
        read -p "Select option: " choice
        
        case $choice in
            1)
                echo -e "\n${BOLD}Quick Start - Enabling and starting all services...${NC}"
                for service in hardn.service hardn-api.service legion-daemon.service; do
                    manage_service "$service" "enable"
                    manage_service "$service" "start"
                done
                echo -e "\n${GREEN}✓ All services enabled and started!${NC}"
                read -p $'\nPress Enter to continue...'
                ;;
            2)
                manage_services_menu
                ;;
            3)
                run_modules_menu
                ;;
            4)
                run_tools_menu
                ;;
            5)
                run_legion_menu
                ;;
            6)
                echo -e "\n${BOLD}Generating security report...${NC}"
                $HARDN_BIN --security-report
                read -p $'\nPress Enter to continue...'
                ;;
            7)
                echo -e "\n${BOLD}HARDN Status:${NC}"
                $HARDN_BIN --status
                read -p $'\nPress Enter to continue...'
                ;;
            8)
                echo -e "\n${BOLD}Sandbox Mode Options:${NC}"
                echo "1) Enable Sandbox (Disconnect network)"
                echo "2) Disable Sandbox (Restore network)"
                echo "0) Cancel"
                read -p "Select [0-2]: " sandbox_choice
                
                case $sandbox_choice in
                    1)
                        echo -e "\n${YELLOW}⚠️  WARNING: This will disconnect all network access!${NC}"
                        read -p "Are you sure? [y/N]: " confirm
                        if [[ $confirm =~ ^[Yy]$ ]]; then
                            $HARDN_BIN --sandbox-on
                        fi
                        ;;
                    2)
                        $HARDN_BIN --sandbox-off
                        ;;
                esac
                read -p $'\nPress Enter to continue...'
                ;;
            h|H)
                $HARDN_BIN --help
                read -p $'\nPress Enter to continue...'
                ;;
            q|Q)
                echo -e "\n${GREEN}Thank you for using HARDN Service Manager!${NC}"
                exit 0
                ;;
            *)
                print_colored $RED "Invalid option!"
                sleep 1
                ;;
        esac
    done
}

check_root
main_menu