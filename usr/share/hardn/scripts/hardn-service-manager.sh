#!/bin/bash

# HARDN Interactive Service Manager
# This script provides an interactive menu for managing HARDN services and modules
# Requires bash 4.0+ for advanced features

set -euo pipefail

# Set up signal handlers
trap 'echo -e "\n\nInterrupted. Exiting..."; exit 130' INT TERM
# Ensure terminal is restored on any exit
trap 'stty sane; tput cnorm 2>/dev/null || true' EXIT

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
readonly DEFAULT_TOOL_PATHS="/usr/share/hardn/tools:/usr/lib/hardn/src/setup/tools"
declare -ar DEFAULT_TOOL_COMMANDS=(aide apparmor auditd clamv fail2ban lynis ossec suricata ufw grafana)
HARDN_BIN="${HARDN_BINARY:-}"

print_colored() {
    local color="$1"
    shift
    printf "%b%s%b\n" "$color" "$*" "$NC"
}

format_tool_display() {
    local name="${1,,}"
    case "$name" in
        aide)
            echo "AIDE (Integrity Monitoring)"
            ;;
        apparmor)
            echo "AppArmor (Mandatory Access Control)"
            ;;
        auditd)
            echo "Auditd (Linux Auditing)"
            ;;
        clamv|clamav)
            echo "ClamAV (Malware Scanner)"
            ;;
        fail2ban)
            echo "Fail2Ban (Brute-force Defense)"
            ;;
        lynis)
            echo "Lynis (Security Audit)"
            ;;
        ossec)
            echo "OSSEC (HIDS)"
            ;;
        legion)
            echo "LEGION (Threat Hunting)"
            ;;
        rkhunter)
            echo "RKHunter (Rootkit Scanner)"
            ;;
        suricata)
            echo "Suricata (IDS/IPS)"
            ;;
        ufw)
            echo "UFW Firewall"
            ;;
        grafana)
            echo "Grafana Endpoint Monitoring"
            ;;
        *)
            local human=${name//[_-]/ }
            human=${human,,}
            local formatted=""
            for word in $human; do
                formatted+="${word^} "
            done
            echo "${formatted% }"
            ;;
    esac
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_colored "$RED" "This service manager must be run as root."
        echo "Try again with sudo or from a root shell."
        exit 1
    fi
}

check_dependencies() {
    local -a required_cmds=(systemctl journalctl find sed awk)
    local -a missing_deps=()

    for cmd in "${required_cmds[@]}"; do
        command -v "$cmd" >/dev/null 2>&1 || missing_deps+=("$cmd")
    done

    if [[ ${#missing_deps[@]} -gt 0 ]]; then
        print_colored "$RED" "Error: Missing required dependencies: ${missing_deps[*]}"
        exit 1
    fi

    if [[ -n "${HARDN_BIN:-}" && -x "$HARDN_BIN" ]]; then
        :
    else
        if [[ -n "${HARDN_BINARY:-}" && -x "$HARDN_BINARY" ]]; then
            HARDN_BIN="$HARDN_BINARY"
        fi

        if [[ -z "${HARDN_BIN:-}" || ! -x "$HARDN_BIN" ]]; then
            local candidates=(
                "./target/release/hardn"
                "./hardn"
                "/usr/local/bin/hardn"
                "/usr/bin/hardn"
                "/opt/hardn/bin/hardn"
            )
            for candidate in "${candidates[@]}"; do
                if [[ -x "$candidate" ]]; then
                    HARDN_BIN="$candidate"
                    break
                fi
            done
        fi

        if [[ -z "${HARDN_BIN:-}" || ! -x "$HARDN_BIN" ]]; then
            HARDN_BIN=$(command -v hardn 2>/dev/null || true)
        fi
    fi

    if [[ -z "${HARDN_BIN:-}" || ! -x "$HARDN_BIN" ]]; then
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

    export HARDN_BIN
    echo "Using HARDN binary: $HARDN_BIN"
}

# Launch GUI as invoking desktop user (not root)
launch_gui() {
    echo -e "\n${BOLD}Launching HARDN Read-Only GUI...${NC}"
    if ! command -v hardn-gui >/dev/null 2>&1; then
        print_colored "$RED" "hardn-gui not found in PATH. Make sure the package is installed (sudo make hardn)."
        read -p $'\nPress Enter to continue...' || true
        return
    fi

    # Determine target desktop user
    local target_user="${SUDO_USER:-}"
    if [[ -z "$target_user" ]]; then
        target_user=$(logname 2>/dev/null || who | awk '{print $1}' | head -n1)
    fi
    if [[ -z "$target_user" ]]; then
        print_colored "$RED" "Unable to determine invoking desktop user. Run GUI manually as your user: hardn-gui"
        read -p $'\nPress Enter to continue...' || true
        return
    fi

    local log_dir="/var/log/hardn"
    local -a gui_feeds=(
        "$log_dir/hardn-monitor.log"
        "$log_dir/legion.log"
        "$log_dir/legion-audit.log"
    )

    if [[ -d "$log_dir" ]]; then
        if command -v setfacl >/dev/null 2>&1; then
            if setfacl -m "u:${target_user}:rX" "$log_dir" 2>/dev/null; then
                setfacl -m "d:u:${target_user}:rX" "$log_dir" 2>/dev/null || true
                for feed in "${gui_feeds[@]}"; do
                    [[ -e "$feed" ]] && setfacl -m "u:${target_user}:r--" "$feed" 2>/dev/null || true
                done
                print_colored "$GREEN" "✓ Granted read-only GUI access to HARDN monitoring feeds for $target_user."
            else
                print_colored "$YELLOW" "Unable to adjust ACLs for $target_user; falling back to world-readable HARDN logs."
                chmod o+rx "$log_dir" 2>/dev/null || true
                for feed in "${gui_feeds[@]}"; do
                    [[ -e "$feed" ]] && chmod o+r "$feed" 2>/dev/null || true
                done
            fi
        else
            print_colored "$YELLOW" "setfacl not available; granting world read-only access to HARDN logs."
            chmod o+rx "$log_dir" 2>/dev/null || true
            for feed in "${gui_feeds[@]}"; do
                [[ -e "$feed" ]] && chmod o+r "$feed" 2>/dev/null || true
            done
        fi
    else
        print_colored "$YELLOW" "HARDN log directory $log_dir not present yet; GUI will stream data once logs are created."
    fi

    local uid
    uid=$(id -u "$target_user")
    local xdg_runtime="/run/user/$uid"

    # Build environment for the user session
    local env_vars=(
        "DISPLAY=${DISPLAY:-}"
        "WAYLAND_DISPLAY=${WAYLAND_DISPLAY:-}"
        "XDG_RUNTIME_DIR=$xdg_runtime"
        "DBUS_SESSION_BUS_ADDRESS=unix:path=$xdg_runtime/bus"
    )

    if [[ -n "${DISPLAY:-}" || -n "${WAYLAND_DISPLAY:-}" ]]; then
        echo "Starting GUI for user '$target_user'..."
        runuser -u "$target_user" -- env "${env_vars[@]}" nohup hardn-gui >/dev/null 2>&1 &
        print_colored "$GREEN" "✓ GUI launch attempted for $target_user (check your desktop)."
    else
        print_colored "$YELLOW" "No graphical session detected (DISPLAY/WAYLAND_DISPLAY empty). GUI not started."
        echo "Tip: Run 'hardn-gui' from your desktop user terminal."
    fi

    read -p $'\nPress Enter to continue...' || true
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
                echo -e "\n${BOLD}Running LEGION with predictive analysis...${NC}"
                "$HARDN_BIN" legion --predictive --verbose
                read -p $'\nPress Enter to continue...' || true
                ;;
            8)
                echo -e "\n${BOLD}Running LEGION with automated response...${NC}"
                echo -e "${YELLOW}WARNING: Automated response may take security actions automatically!${NC}"
                read -p "Are you sure? [y/N]: " confirm || { echo; continue; }
                if [[ "$confirm" =~ ^[Yy]$ ]]; then
                    echo -e "\nPress Ctrl+C to stop the session and return to this menu."
                    local previous_int_trap previous_term_trap legion_interrupted session_status
                    previous_int_trap=$(trap -p INT || true)
                    previous_term_trap=$(trap -p TERM || true)
                    legion_interrupted=0
                    trap 'legion_interrupted=1' INT
                    set +e
                    (
                        trap - INT TERM
                        "$HARDN_BIN" legion --response-enabled --verbose
                    )
                    session_status=$?
                    set -e
                    if [[ -n "$previous_int_trap" ]]; then
                        eval "$previous_int_trap"
                    else
                        trap - INT
                    fi
                    if [[ -n "$previous_term_trap" ]]; then
                        eval "$previous_term_trap"
                    else
                        trap - TERM
                    fi
                    if [[ $session_status -eq 130 ]]; then
                        legion_interrupted=1
                    fi
                    if [[ $legion_interrupted -eq 1 ]]; then
                        echo -e "\nLEGION automated response session interrupted."
                    else
                        echo -e "\nLEGION automated response session ended."
                    fi
                fi
                read -p $'\nPress Enter to continue...' || true
                ;;
            9)
                echo -e "\n${BOLD}Enter custom LEGION options:${NC}"
                echo "Examples:"
                echo "  --verbose --predictive"
                echo "  --daemon --json"
                echo "  --create-baseline --verbose"
                echo "  --response-enabled --predictive --verbose"
                read -p "Options: " legion_options || { echo; continue; }
                echo -e "\n${BOLD}Running LEGION with custom options...${NC}"
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
        modules=$("$HARDN_BIN" --list-modules 2>/dev/null | sed -n 's/^[[:space:]]*[•-][[:space:]]\{1,\}\(.*\)$/\1/p' || true)

        if [[ -z "$modules" ]]; then
            # Fallback: inspect module directories directly
            local -a module_dirs=()
            IFS=':' read -ra module_dirs <<< "${HARDN_MODULE_PATH:-/usr/share/hardn/modules:/usr/lib/hardn/src/setup/modules}"
            local -A seen_modules=()
            for dir in "${module_dirs[@]}"; do
                [ -d "$dir" ] || continue
                while IFS= read -r -d '' module_file; do
                    local base
                    base=$(basename "$module_file")
                    base=${base%.sh}
                    seen_modules[$base]=1
                done < <(find "$dir" -maxdepth 1 -type f -name '*.sh' -print0 2>/dev/null)
            done
            if ((${#seen_modules[@]})); then
                modules=$(printf '%s\n' "${!seen_modules[@]}" | sort)
            fi
        fi

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
    local default_tool_dirs="$DEFAULT_TOOL_PATHS"

    while true; do
        display_header
        echo -e "${BOLD}Available HARDN Tools:${NC}"
        echo -e "─────────────────────────────────────────────────"
        echo

    local -a tool_display=()
    local -a tool_command=()
    declare -A seen_tools=()

        for tool in "${DEFAULT_TOOL_COMMANDS[@]}"; do
            tool_command+=("$tool")
            tool_display+=("$(format_tool_display "$tool")")
            seen_tools["$tool"]=1
        done

        local -a tool_dirs=()
        local IFS=':'
        read -ra tool_dirs <<< "${HARDN_TOOL_PATH:-$default_tool_dirs}"

        for dir in "${tool_dirs[@]}"; do
            [[ -d "$dir" ]] || continue
            while IFS= read -r -d '' tool_script; do
                local base
                base=$(basename "$tool_script")
                base=${base%.sh}
                local command="${base,,}"
                [[ -n "$command" ]] || continue
                if [[ -z "${seen_tools[$command]:-}" ]]; then
                    tool_command+=("$command")
                    tool_display+=("$(format_tool_display "$command")")
                    seen_tools["$command"]=1
                fi
            done < <(find "$dir" -maxdepth 1 -type f -name '*.sh' -print0 2>/dev/null)
        done

        local tool_count=${#tool_display[@]}

        if (( tool_count == 0 )); then
            print_colored "$RED" "No tools found!"
            echo "Make sure HARDN is properly installed or update tool definitions."
            read -p $'\nPress Enter to continue...' || true
            return
        fi

        for ((idx=0; idx<tool_count; idx++)); do
            printf "%d) %s\n" "$((idx + 1))" "${tool_display[$idx]}"
        done

        echo
        print_colored "$YELLOW" "Administrator note: update ${HARDN_TOOL_PATH:-$default_tool_dirs} with custom tool scripts and align this menu with your deployment."
        echo
        echo "a) Run ALL tools"
        echo "0) Back to Main Menu"
        echo
        read -p "Select tool [0-${tool_count},a]: " tool_choice || { echo; return; }

        case $tool_choice in
            a|A)
                echo -e "\n${BOLD}Running all tools...${NC}"
                "$HARDN_BIN" --run-all-tools
                read -p $'\nPress Enter to continue...' || true
                ;;
            0)
                return
                ;;
            '')
                continue
                ;;
            *)
                if [[ "$tool_choice" =~ ^[0-9]+$ ]]; then
                    local index=$((tool_choice - 1))
                    if (( index >= 0 && index < tool_count )); then
                        local selected_display="${tool_display[$index]}"
                        local selected_command="${tool_command[$index]}"
                        echo -e "\n${BOLD}Running tool: $selected_display${NC}"

                        local script_found=false
                        for dir in "${tool_dirs[@]}"; do
                            if [[ -f "$dir/${selected_command}.sh" ]]; then
                                script_found=true
                                break
                            fi
                        done
                        if [[ "$script_found" == false ]]; then
                            print_colored "$YELLOW" "No dedicated script located for '${selected_command}'. Update your tooling to match custom deployments."
                        fi

                        if "$HARDN_BIN" run-tool "$selected_command"; then
                            :
                        else
                            print_colored "$RED" "Tool execution reported errors. Review hardn.service logs for details."
                        fi
                        read -p $'\nPress Enter to continue...' || true
                    else
                        print_colored "$RED" "Invalid option!"
                        sleep 1
                    fi
                else
                    print_colored "$RED" "Invalid option!"
                    sleep 1
                fi
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
                echo -e "${BOLD}║                        HARDN Services Logs Viewer                         ║${NC}"
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
                        journalctl -u hardn.service -u hardn-api.service -u legion-daemon.service -u hardn-monitor.service -u err -n 50 --no-pager -o short-iso
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
                        journalctl -u hardn.service -u hardn-api.service -u legion-daemon.service -u hardn-monitor.service -u "CPU|Memory|load" -n 20 --no-pager -o short-iso
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
        echo -e "${BOLD}${RED}ADVANCED OPERATIONS - USE WITH CAUTION${NC}"
        echo -e "${RED}These operations are for advanced security needs and could damage your system if not performed correctly!${NC}"
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
                echo "  - Disable AppArmor"
                echo "  - Require a system reboot"
                echo "  - May disconnect existing applications"
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
        echo "10) Advanced Operations"
        echo "11) Launch HARDN SIEM"
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
            11)
                launch_gui
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