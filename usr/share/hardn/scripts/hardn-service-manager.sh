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
readonly HARDN_SERVICES="hardn.service hardn-api.service legion-daemon.service hardn-monitor.service"

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
        print_colored "$RED" "This script must be run as root!"
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
    echo -e "${CYAN}║${NC}                        ${BOLD}HARDN Service Manager${NC}                              ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}          Linux Security Hardening & Extended Detection Toolkit            ${CYAN}║${NC}"
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


manage_service() {
    local service_name=$1
    local action=$2
    
   
    local display_action="${action^}"
    echo -n "  ${display_action}ing $service_name... "
    
    if systemctl "$action" "$service_name" 2>/dev/null; then
        print_colored "$GREEN" "✓ Success"
        if [[ "$action" == "start" || "$action" == "restart" ]]; then
            sleep 2  
        fi
    else
        print_colored "$RED" "✗ Failed"
        echo "  Check logs with: journalctl -u '$service_name' -n 50"
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
        echo "6) Create System Baseline"
        echo "7) Run with Predictive Analysis"
        echo "8) Run with Automated Response"
        echo "9) Custom LEGION Options"
        echo
        echo "0) Back to Main Menu"
        echo
        read -p "Select option [0-9]: " legion_choice || { echo; return; }

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
                echo -e "\n${BOLD}Creating system baseline...${NC}"
                "$HARDN_BIN" legion --create-baseline
                read -p $'\nPress Enter to continue...' || true
                ;;
            7)
                echo -e "\n${BOLD}Running LEGION with ML analysis...${NC}"
                "$HARDN_BIN" legion --ml-enabled
                read -p $'\nPress Enter to continue...' || true
                ;;
            8)
                echo -e "\n${BOLD}Running LEGION with predictive analysis...${NC}"
                "$HARDN_BIN" legion --predictive
                read -p $'\nPress Enter to continue...' || true
                ;;
            9)
                echo -e "\n${BOLD}Running LEGION with automated response...${NC}"
                echo -e "${YELLOW}WARNING: Automated response may take security actions automatically!${NC}"
                read -p "Are you sure? [y/N]: " confirm || { echo; continue; }
                if [[ "$confirm" =~ ^[Yy]$ ]]; then
                    "$HARDN_BIN" legion --response-enabled
                fi
                read -p $'\nPress Enter to continue...' || true
                ;;
            10)
                echo -e "\n${BOLD}Enter LEGION options:${NC}"
                echo "Examples:"
                echo "  --verbose --ml-enabled"
                echo "  --daemon --json"
                echo "  --create-baseline --verbose"
                read -p "Options: " legion_options || { echo; continue; }
                echo -e "\n${BOLD}Running LEGION with options...${NC}"
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


run_modules_menu() {
    while true; do
        display_header
        echo -e "${BOLD}Available HARDN Modules:${NC}"
        echo -e "─────────────────────────────────────────────────"
        echo
       
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


run_tools_menu() {
    while true; do
        display_header
        echo -e "${BOLD}Available HARDN Tools:${NC}"
        echo -e "─────────────────────────────────────────────────"
        echo
        
        local tools_output
        tools_output=$("$HARDN_BIN" --list-tools 2>/dev/null || true)
        
        if [[ -z "$tools_output" ]]; then
            print_colored "$RED" "No tools found!"
            echo "Make sure HARDN is properly installed."
            read -p $'\nPress Enter to continue...' || true
            return
        fi
        
        local i=1
        declare -a tool_array
        local current_category=""
        
        while IFS= read -r line; do
            # Check for category headers
            if [[ "$line" =~ ^[A-Z].*:$ ]]; then
                current_category="${line%:}"
                echo -e "\n${PURPLE}$current_category:${NC}"
            # Check for tool lines (starting with bullet)
            elif [[ "$line" =~ ^[[:space:]]*•[[:space:]] ]]; then
                local tool_name=$(echo "$line" | sed 's/^[[:space:]]*•[[:space:]]*//')
                echo "$i) $tool_name"
                tool_array[$i]=$tool_name
                ((i++))
            fi
        done <<< "$tools_output"
        
        echo
        echo "a) Run ALL tools"
        echo "0) Back to Main Menu"
        echo
        read -p "Select tool [0-$((i-1)),a]: " tool_choice || { echo; return; }
        
        case $tool_choice in
            a|A)
                echo -e "\n${BOLD}Running all tools...${NC}"
                "$HARDN_BIN" --run-all-tools
                read -p $'\nPress Enter to continue...' || true
                ;;
            0)
                return
                ;;
            [1-9]*)
                # Validate numeric input
                if [[ "$tool_choice" =~ ^[0-9]+$ ]] && [[ $tool_choice -lt $i && $tool_choice -gt 0 ]]; then
                    local selected_tool="${tool_array[$tool_choice]}"
                    echo -e "\n${BOLD}Running tool: $selected_tool${NC}"
                    "$HARDN_BIN" run-tool "$selected_tool"
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
        echo "7) View Service Logs (Live & Historical)"
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
                echo -e "\n${BOLD}╔═══════════════════════════════════════════════════════════════════════════╗${NC}"
                echo -e "${BOLD}║                        HARDN Service Logs Viewer                        ║${NC}"
                echo -e "${BOLD}╚═══════════════════════════════════════════════════════════════════════════╝${NC}"
                echo -e "\n${CYAN}Choose log viewing mode:${NC}"
                echo "1) Live All Services (follow mode)"
                echo "2) Recent All Services (last 50 entries)"
                echo "3) Individual Service Logs"
                echo "4) Critical Errors Only"
                echo "5) Performance Metrics"
                echo "6) Custom journalctl command"
                echo -e "${YELLOW}Note: Use Ctrl+C to exit live/following modes${NC}"
                read -p $'\nSelect [1-6]: ' log_choice || { echo; continue; }
                
                case $log_choice in
                    1)
                        echo -e "\n${BOLD}${GREEN}LIVE MODE: Following all HARDN service logs...${NC}"
                        echo -e "${CYAN}Showing real-time logs from: hardn.service, hardn-api.service, legion-daemon.service, hardn-monitor.service${NC}"
                        echo -e "${YELLOW}Press Ctrl+C to stop following${NC}\n"
                        journalctl -u hardn.service -u hardn-api.service -u legion-daemon.service -u hardn-monitor.service -f --no-pager
                        ;;
                    2)
                        echo -e "\n${BOLD}Recent Logs from All HARDN Services${NC}"
                        echo -e "${CYAN}═══════════════════════════════════════════════════════════════════════════════${NC}"
                        journalctl -u hardn.service -u hardn-api.service -u legion-daemon.service -u hardn-monitor.service -n 50 --no-pager -o short-iso
                        ;;
                    3)
                        echo -e "\n${BOLD}Select individual service:${NC}"
                        echo "1) hardn.service (Security Monitoring & Response)"
                        echo "2) hardn-api.service (REST API Server)"
                        echo "3) legion-daemon.service (LEGION Monitoring Daemon)"
                        echo "4) hardn-monitor.service (Centralized Monitoring)"
                        read -p "Select [1-4]: " service_choice || { echo; continue; }
                        
                        case $service_choice in
                            1) 
                                echo -e "\n${BOLD}HARDN Security Monitoring Service Logs${NC}"
                                journalctl -u hardn.service -n 100 --no-pager -o short-iso
                                ;;
                            2)
                                echo -e "\n${BOLD}HARDN API Service Logs${NC}"
                                journalctl -u hardn-api.service -n 100 --no-pager -o short-iso
                                ;;
                            3)
                                echo -e "\n${BOLD}LEGION Monitoring Daemon Logs${NC}"
                                journalctl -u legion-daemon.service -n 100 --no-pager -o short-iso
                                ;;
                            4)
                                echo -e "\n${BOLD}HARDN Monitor Service Logs${NC}"
                                journalctl -u hardn-monitor.service -n 100 --no-pager -o short-iso
                                ;;
                            *) print_colored "$RED" "Invalid service selection!" ;;
                        esac
                        ;;
                    4)
                        echo -e "\n${BOLD}Critical Errors from All HARDN Services${NC}"
                        echo -e "${RED}Showing only ERROR, CRITICAL, and ALERT priority logs${NC}\n"
                        journalctl -u hardn.service -u hardn-api.service -u legion-daemon.service -u hardn-monitor.service -p err -n 50 --no-pager -o short-iso
                        ;;
                    5)
                        echo -e "\n${BOLD}HARDN Service Performance Metrics${NC}"
                        echo -e "${CYAN}Service Status Summary:${NC}"
                        for service in hardn.service hardn-api.service legion-daemon.service hardn-monitor.service; do
                            status=$(systemctl is-active "$service" 2>/dev/null || echo "unknown")
                            if [ "$status" = "active" ]; then
                                echo -e "  [ACTIVE] $service: ${GREEN}RUNNING${NC}"
                            else
                                echo -e "  [INACTIVE] $service: ${RED}$status${NC}"
                            fi
                        done
                        echo -e "\n${CYAN}Recent Performance Logs:${NC}"
                        journalctl -u hardn.service -u hardn-api.service -u legion-daemon.service -u hardn-monitor.service -g "CPU|Memory|load" -n 20 --no-pager -o short-iso
                        ;;
                    6)
                        echo -e "\n${BOLD}Custom journalctl command${NC}"
                        echo -e "${YELLOW}Example: -u hardn.service -n 50 -f${NC}"
                        read -p "Enter journalctl arguments: " custom_args
                        if [ -n "$custom_args" ]; then
                            echo -e "\n${CYAN}Executing: journalctl $custom_args${NC}\n"
                            journalctl $custom_args
                        else
                            print_colored "$YELLOW" "No arguments provided, skipping..."
                        fi
                        ;;
                    *) print_colored "$RED" "Invalid log viewing option!" ;;
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

# Function for dangerous operations (SELinux)
dangerous_operations_menu() {
    while true; do
        display_header
        echo -e "${BOLD}${RED}DANGEROUS OPERATIONS - USE WITH EXTREME CAUTION${NC}"
        echo -e "${RED}These operations can break your system and require manual intervention!${NC}"
        echo -e "─────────────────────────────────────────────────"
        echo
        echo "1) Enable SELinux (REQUIRES REBOOT - DISABLES AppArmor)"
        echo
        echo "0) Back to Main Menu"
        echo
        read -p "Select option [0-1]: " danger_choice || { echo; return; }
        
        case $danger_choice in
            1)
                echo -e "\n${BOLD}${RED}EXTREME WARNING${NC}"
                echo -e "${RED}Enabling SELinux will:"
                echo "  - Disable AppArmor completely"
                echo "  - Require a system reboot"
                echo "  - May break existing applications"
                echo "  - Requires manual SELinux policy configuration"
                echo -e "${NC}"
                read -p "Do you understand these risks and want to proceed? [yes/NO]: " confirm || { echo; continue; }
                if [[ "$confirm" == "yes" ]]; then
                    read -p "Type 'I UNDERSTAND' to confirm: " final_confirm || { echo; continue; }
                    if [[ "$final_confirm" == "I UNDERSTAND" ]]; then
                        echo -e "\n${BOLD}Enabling SELinux...${NC}"
                        "$HARDN_BIN" --enable-selinux
                        echo -e "\n${YELLOW}SELinux enabled. You MUST reboot your system now!${NC}"
                        echo -e "${YELLOW}After reboot, configure SELinux policies manually.${NC}"
                    else
                        echo "Operation cancelled."
                    fi
                else
                    echo "Operation cancelled."
                fi
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
        echo "9) Run Everything (Modules + Tools)"
        echo "10) Dangerous Operations"
        echo
        echo "a) About HARDN"
        echo "v) Show Version"
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
                # Note: The security report now has interactive options, 
                # so we don't need the extra "Press Enter" here
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
                        echo -e "\n${YELLOW}WARNING: This will disconnect all network access!${NC}"
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
            9)
                echo -e "\n${BOLD}Running all modules and tools...${NC}"
                "$HARDN_BIN" --run-everything
                read -p $'\nPress Enter to continue...' || true
                ;;
            10)
                dangerous_operations_menu
                ;;
            a|A)
                echo -e "\n${BOLD}About HARDN:${NC}"
                "$HARDN_BIN" --about
                read -p $'\nPress Enter to continue...' || true
                ;;
            v|V)
                echo -e "\n${BOLD}HARDN Version:${NC}"
                "$HARDN_BIN" --version
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