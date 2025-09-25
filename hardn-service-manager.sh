#!/bin/bash

# HARDN Interactive Service Manager
# This script provides an interactive menu for managing HARDN services and modules
# Requires bash 4.0+ for advanced features

set -euo pipefail

# Set up signal handlers
trap 'echo -e "\n\nInterrupted. Exiting..."; exit 130' INT TERM

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
readonly LOG_DIR="/var/log/hardn"
readonly HARDN_SERVICES="hardn.service hardn-api.service legion-daemon.service"

# Function to find HARDN binary
find_hardn_binary() {
    # Check environment variable first
    if [[ -n "${HARDN_BINARY:-}" && -x "${HARDN_BINARY}" ]]; then
        echo "${HARDN_BINARY}"
        return 0
    fi
    
    local possible_locations=(
        "./target/release/hardn"  # Development build
        "./hardn"                 # Current directory
        "/usr/local/bin/hardn"    # Local installation
        "/usr/bin/hardn"          # System installation
        "/opt/hardn/bin/hardn"    # Optional installation
        "$(command -v hardn 2>/dev/null || true)"  # In PATH (avoiding aliases)
    )
    
    for location in "${possible_locations[@]}"; do
        if [[ -n "$location" && -x "$location" ]]; then
            echo "$location"
            return 0
        fi
    done
    
    return 1
}

# Find HARDN binary
HARDN_BIN=$(find_hardn_binary || echo "")
readonly HARDN_BIN

# Function to print colored output
print_colored() {
    local color=$1
    shift
    echo -e "${color}$@${NC}"
}

# Function to check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_colored "$RED" "❌ This script must be run as root!"
        echo "Please run with: sudo $0"
        exit 1
    fi
}

# Function to check for required commands
check_dependencies() {
    local missing_deps=()
    
    for cmd in systemctl journalctl; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            missing_deps+=("$cmd")
        fi
    done
    
    if [[ ${#missing_deps[@]} -gt 0 ]]; then
        print_colored "$RED" "Error: Missing required dependencies: ${missing_deps[*]}"
        exit 1
    fi
    
    if [[ -z "$HARDN_BIN" || ! -x "$HARDN_BIN" ]]; then
        print_colored "$RED" "Error: HARDN binary not found!"
        echo "Please ensure HARDN is installed or built."
        echo "Searched locations:"
        echo "  - ./target/release/hardn (development build)"
        echo "  - ./hardn (current directory)"
        echo "  - /usr/local/bin/hardn (local installation)"
        echo "  - /usr/bin/hardn (system installation)"
        echo "  - /opt/hardn/bin/hardn (optional installation)"
        echo "  - PATH environment variable"
        echo ""
        echo "If running from source, try: cargo build --release"
        echo "You can also set HARDN_BINARY environment variable:"
        echo "  export HARDN_BINARY=/path/to/hardn"
        exit 1
    fi
    
    echo "Using HARDN binary: $HARDN_BIN"
}

# Function to display the header
display_header() {
    clear
    echo -e "${CYAN}╔═══════════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${NC}                     ${BOLD}HARDN Service Manager${NC}                                  ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}         Linux Security Hardening & Extended Detection Toolkit              ${CYAN}║${NC}"
    echo -e "${CYAN}╚═══════════════════════════════════════════════════════════════════════════╝${NC}"
    echo
}

# Function to check service status
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

# Function to display service status
display_service_status() {
    echo -e "\n${BOLD}Current Service Status:${NC}"
    echo -e "─────────────────────────────────────────────────"
    
    local services
    IFS=' ' read -ra services <<< "$HARDN_SERVICES"
    
    for service in "${services[@]}"; do
        local status=$(check_service_status "$service")
        local display_name=$(echo "$service" | sed 's/\.service$//')
        
        case $status in
            "active")
                print_colored "$GREEN" "  ● $display_name: Running ✓"
                ;;
            "enabled")
                print_colored "$YELLOW" "  ● $display_name: Enabled (not running)"
                ;;
            *)
                print_colored "$RED" "  ● $display_name: Inactive ✗"
                ;;
        esac
    done
    echo
}

# Function to manage a specific service
manage_service() {
    local service_name=$1
    local action=$2
    
    # Capitalize first letter for display (bash-specific but safe)
    local display_action="${action^}"
    echo -n "  ${display_action}ing $service_name... "
    
    if systemctl "$action" "$service_name" 2>/dev/null; then
        print_colored "$GREEN" "✓ Success"
        if [[ "$action" == "start" || "$action" == "restart" ]]; then
            sleep 2  # Give service time to start
        fi
    else
        print_colored "$RED" "✗ Failed"
        echo "  Check logs with: journalctl -u '$service_name' -n 50"
    fi
}

# Function to run LEGION options
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
        read -p "Select option [0-6]: " legion_choice || { echo; return; }
        
        case $legion_choice in
            1)
                echo -e "\n${BOLD}Running LEGION security assessment...${NC}"
                "$HARDN_BIN" legion
                read -p $'\nPress Enter to continue...' || true
                ;;
            2)
                echo -e "\n${BOLD}Starting LEGION daemon...${NC}"
                manage_service "legion-daemon.service" "start"
                read -p $'\nPress Enter to continue...' || true
                ;;
            3)
                echo -e "\n${BOLD}Stopping LEGION daemon...${NC}"
                manage_service "legion-daemon.service" "stop"
                read -p $'\nPress Enter to continue...' || true
                ;;
            4)
                echo -e "\n${BOLD}Recent LEGION logs:${NC}"
                journalctl -u legion-daemon.service -n 50 --no-pager
                read -p $'\nPress Enter to continue...' || true
                ;;
            5)
                echo -e "\n${BOLD}LEGION daemon status:${NC}"
                systemctl status legion-daemon.service --no-pager
                read -p $'\nPress Enter to continue...' || true
                ;;
            6)
                echo -e "\n${BOLD}Enter LEGION options:${NC}"
                echo "Example: --verbose --risk-threshold 3"
                read -p "Options: " legion_options || { echo; continue; }
                echo -e "\n${BOLD}Running LEGION with options...${NC}"
                # Use eval carefully with validated input
                "$HARDN_BIN" legion $legion_options
                read -p $'\nPress Enter to continue...' || true
                ;;
            0)
                return
                ;;
            *)
                print_colored "$RED" "Invalid option!"
                sleep 1
                ;;
        esac
    done
}

# Function to run modules
run_modules_menu() {
    while true; do
        display_header
        echo -e "${BOLD}Available HARDN Modules:${NC}"
        echo -e "─────────────────────────────────────────────────"
        echo
        
        # Get available modules
        local modules
        modules=$("$HARDN_BIN" --list-modules 2>/dev/null | grep -E "^    - " | sed 's/    - //' || true)
        
        if [[ -z "$modules" ]]; then
            print_colored "$RED" "No modules found!"
            echo "Make sure HARDN is properly installed."
            read -p $'\nPress Enter to continue...' || true
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
        read -p "Select module [0-$((i-1))]: " module_choice || { echo; return; }
        
        case $module_choice in
            a|A)
                echo -e "\n${BOLD}Running all modules...${NC}"
                "$HARDN_BIN" --run-all-modules
                read -p $'\nPress Enter to continue...' || true
                ;;
            0)
                return
                ;;
            [1-9]*)
                # Validate numeric input
                if [[ "$module_choice" =~ ^[0-9]+$ ]] && [[ $module_choice -lt $i && $module_choice -gt 0 ]]; then
                    local selected_module="${module_array[$module_choice]}"
                    echo -e "\n${BOLD}Running module: $selected_module${NC}"
                    "$HARDN_BIN" run-module "$selected_module"
                    read -p $'\nPress Enter to continue...' || true
                else
                    print_colored "$RED" "Invalid option!"
                    sleep 1
                fi
                ;;
            *)
                print_colored "$RED" "Invalid option!"
                sleep 1
                ;;
        esac
    done
}

# Function to run tools
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
        read -p "Select tool [0-9,a]: " tool_choice || { echo; return; }
        
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
                "$HARDN_BIN" --run-all-tools
                read -p $'\nPress Enter to continue...' || true
                ;;
            0)
                return
                ;;
            *)
                print_colored "$RED" "Invalid option!"
                sleep 1
                ;;
        esac
        
        if [[ -n "$tool_name" ]]; then
            echo -e "\n${BOLD}Running tool: $tool_name${NC}"
            "$HARDN_BIN" run-tool "$tool_name"
            read -p $'\nPress Enter to continue...' || true
        fi
    done
}

# Function to manage HARDN services
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
        read -p "Select option [0-7]: " service_choice || { echo; return; }
        
        case $service_choice in
            1)
                echo -e "\n${BOLD}Starting all HARDN services...${NC}"
                local services
                IFS=' ' read -ra services <<< "$HARDN_SERVICES"
                for service in "${services[@]}"; do
                    manage_service "$service" "start"
                done
                read -p $'\nPress Enter to continue...' || true
                ;;
            2)
                echo -e "\n${BOLD}Stopping all HARDN services...${NC}"
                local services
                IFS=' ' read -ra services <<< "$HARDN_SERVICES"
                # Stop in reverse order
                for ((i=${#services[@]}-1; i>=0; i--)); do
                    manage_service "${services[i]}" "stop"
                done
                read -p $'\nPress Enter to continue...' || true
                ;;
            3)
                echo -e "\n${BOLD}Restarting all HARDN services...${NC}"
                local services
                IFS=' ' read -ra services <<< "$HARDN_SERVICES"
                for service in "${services[@]}"; do
                    manage_service "$service" "restart"
                done
                read -p $'\nPress Enter to continue...' || true
                ;;
            4)
                echo -e "\n${BOLD}Enabling all HARDN services...${NC}"
                local services
                IFS=' ' read -ra services <<< "$HARDN_SERVICES"
                for service in "${services[@]}"; do
                    manage_service "$service" "enable"
                done
                read -p $'\nPress Enter to continue...' || true
                ;;
            5)
                echo -e "\n${BOLD}Disabling all HARDN services...${NC}"
                local services
                IFS=' ' read -ra services <<< "$HARDN_SERVICES"
                # Disable in reverse order
                for ((i=${#services[@]}-1; i>=0; i--)); do
                    manage_service "${services[i]}" "disable"
                done
                read -p $'\nPress Enter to continue...' || true
                ;;
            6)
                echo -e "\n${BOLD}Select service:${NC}"
                echo "1) hardn.service"
                echo "2) hardn-api.service"
                echo "3) legion-daemon.service"
                read -p "Select [1-3]: " svc_num || { echo; continue; }
                
                local selected_service=""
                case $svc_num in
                    1) selected_service="hardn.service" ;;
                    2) selected_service="hardn-api.service" ;;
                    3) selected_service="legion-daemon.service" ;;
                    *) 
                        print_colored "$RED" "Invalid selection!"
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
                read -p "Select [1-6]: " action_num || { echo; continue; }
                
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
                        print_colored "$RED" "Invalid action!"
                        ;;
                esac
                read -p $'\nPress Enter to continue...' || true
                ;;
            7)
                echo -e "\n${BOLD}Select service to view logs:${NC}"
                echo "1) hardn.service"
                echo "2) hardn-api.service"
                echo "3) legion-daemon.service"
                echo "4) All HARDN logs"
                read -p "Select [1-4]: " log_choice || { echo; continue; }
                
                case $log_choice in
                    1) journalctl -u hardn.service -n 100 --no-pager ;;
                    2) journalctl -u hardn-api.service -n 100 --no-pager ;;
                    3) journalctl -u legion-daemon.service -n 100 --no-pager ;;
                    4) journalctl -u 'hardn*' -u 'legion*' -n 100 --no-pager ;;
                    *) print_colored "$RED" "Invalid selection!" ;;
                esac
                read -p $'\nPress Enter to continue...' || true
                ;;
            0)
                return
                ;;
            *)
                print_colored "$RED" "Invalid option!"
                sleep 1
                ;;
        esac
    done
}

# Main menu function
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
        read -p "Select option: " choice || { echo; exit 0; }
        
        case $choice in
            1)
                echo -e "\n${BOLD}Quick Start - Enabling and starting all services...${NC}"
                local services
                IFS=' ' read -ra services <<< "$HARDN_SERVICES"
                for service in "${services[@]}"; do
                    manage_service "$service" "enable"
                    manage_service "$service" "start"
                done
                echo -e "\n${GREEN}✓ All services enabled and started!${NC}"
                read -p $'\nPress Enter to continue...' || true
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
                "$HARDN_BIN" --security-report
                read -p $'\nPress Enter to continue...' || true
                ;;
            7)
                echo -e "\n${BOLD}HARDN Status:${NC}"
                "$HARDN_BIN" --status
                read -p $'\nPress Enter to continue...' || true
                ;;
            8)
                echo -e "\n${BOLD}Sandbox Mode Options:${NC}"
                echo "1) Enable Sandbox (Disconnect network)"
                echo "2) Disable Sandbox (Restore network)"
                echo "0) Cancel"
                read -p "Select [0-2]: " sandbox_choice || { echo; continue; }
                
                case $sandbox_choice in
                    1)
                        echo -e "\n${YELLOW}⚠️  WARNING: This will disconnect all network access!${NC}"
                        read -p "Are you sure? [y/N]: " confirm || { echo; continue; }
                        if [[ "$confirm" =~ ^[Yy]$ ]]; then
                            "$HARDN_BIN" --sandbox-on
                        fi
                        ;;
                    2)
                        "$HARDN_BIN" --sandbox-off
                        ;;
                esac
                read -p $'\nPress Enter to continue...' || true
                ;;
            h|H)
                "$HARDN_BIN" --help
                read -p $'\nPress Enter to continue...' || true
                ;;
            q|Q)
                echo -e "\n${GREEN}Thank you for using HARDN Service Manager!${NC}"
                exit 0
                ;;
            *)
                print_colored "$RED" "Invalid option!"
                sleep 1
                ;;
        esac
    done
}

# Main execution
check_root
check_dependencies
main_menu