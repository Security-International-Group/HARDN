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
readonly DEFAULT_TOOL_PATHS="/usr/share/hardn/tools:/usr/lib/hardn/src/setup/tools"
declare -ar DEFAULT_TOOL_COMMANDS=(aide apparmor auditd clamv fail2ban firejail grafana ossec suricata ufw)
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
        ossec)
            echo "OSSEC (HIDS)"
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
        firejail)
            echo "Firejail (Application Sandboxing)"
            ;;
        selinux)
            echo "SELinux (Mandatory Access Control)"
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

display_header() {
    clear
    echo -e "${CYAN}╔═══════════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${NC}                        ${BOLD}HARDN Service Manager${NC}                              ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}          Linux Security Hardening & Extended Detection Toolkit            ${CYAN}║${NC}"
    echo -e "${CYAN}╚═══════════════════════════════════════════════════════════════════════════╝${NC}"
    echo
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
                            print_colored "$RED" "Tool execution reported errors. Review the HARDN logs for details."
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

dangerous_operations_menu() {
    while true; do
        display_header
        echo -e "${BOLD}${RED}ADVANCED OPERATIONS - USE WITH CAUTION${NC}"
        echo -e "${RED}These operations are for advanced security needs and could damage your system if not performed correctly!${NC}"
        echo -e "─────────────────────────────────────────────────"
        echo
        echo "1) Enable SELinux (REQUIRES REBOOT - DISABLES AppArmor)"
        echo "2) Uninstall HARDN (remove services, drop-in configs, runtime data)"
        echo
        echo "0) Back to Main Menu"
        echo
        read -p "Select option [0-2]: " danger_choice || { echo; return; }

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
            2)
                echo -e "\n${BOLD}${RED}HARDN UNINSTALL${NC}"
                echo -e "${RED}This will:"
                echo "  - Stop and disable all HARDN services"
                echo "  - Remove HARDN drop-in config files (99-hardn-*.conf etc.)"
                echo "  - Remove /var/log/hardn and /var/lib/hardn"
                echo "  - Purge the hardn package"
                echo "  - Remove the hardn system user/group"
                echo ""
                echo "It will NOT (unless you opt in via flags):"
                echo "  - Re-enable SSH if HARDN disabled it"
                echo "  - Reset the firewall (dangerous over remote SSH)"
                echo "  - Purge installed security packages (aide, clamav, fail2ban, ...)"
                echo -e "${NC}"
                read -p "Type 'YES UNINSTALL' to confirm: " final_confirm || { echo; continue; }
                if [[ "$final_confirm" == "YES UNINSTALL" ]]; then
                    extra_flags=""
                    read -p "Also re-enable SSH (--restore-ssh)? [y/N]: " ans
                    [[ "$ans" =~ ^[yY] ]] && extra_flags="$extra_flags --restore-ssh"
                    read -p "Also purge security packages (--purge-packages)? [y/N]: " ans
                    [[ "$ans" =~ ^[yY] ]] && extra_flags="$extra_flags --purge-packages"
                    read -p "Also reset the firewall (--reset-firewall, DANGEROUS)? [y/N]: " ans
                    [[ "$ans" =~ ^[yY] ]] && extra_flags="$extra_flags --reset-firewall"
                    echo -e "\n${BOLD}Running uninstall...${NC}"
                    # shellcheck disable=SC2086
                    "$HARDN_BIN" --uninstall --yes $extra_flags
                else
                    echo "Uninstall cancelled."
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


main_menu() {
    while true; do
        display_header
        
        echo -e "${BOLD}Main Menu:${NC}"
        echo -e "─────────────────────────────────────────────────"
        echo
        echo "1) Run HARDN Modules"
        echo "2) Run Security Tools"
        echo "3) Generate Security Report"
        echo "4) View HARDN Status"
        echo "5) Sandbox Mode (Network Isolation)"
        echo "6) Run Everything (Modules + Tools)"
        echo "7) Advanced Operations"
        echo
        echo "a) About HARDN"
        echo "v) Show Version"
        echo "h) View HARDN Help"
        echo "q) Quit"
        echo
        read -p "Select option: " choice || { echo; exit 0; }
        
        case $choice in
            1)
                run_modules_menu
                ;;
            2)
                run_tools_menu
                ;;
            3)
                echo -e "\n${BOLD}Generating security report...${NC}"
                "$HARDN_BIN" --security-report
                # Note: The security report now has interactive options, 
                # so we don't need the extra "Press Enter" here
                ;;
            4)
                echo -e "\n${BOLD}HARDN Status:${NC}"
                "$HARDN_BIN" --status
                read -p $'\nPress Enter to continue...' || true
                ;;
            5)
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
            6)
                echo -e "\n${BOLD}Running all modules and tools...${NC}"
                "$HARDN_BIN" --run-everything
                read -p $'\nPress Enter to continue...' || true
                ;;
            7)
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

# Main 
check_root
check_dependencies
main_menu
