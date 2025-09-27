# Code Execution Flow for `sudo hardn-service-manager`

Here's the complete execution flow showing where in the code and the order of execution when you run `sudo hardn-service-manager`:

## 1. **Command Entry Point** 📍

**Installation Location**: `/usr/bin/hardn-service-manager`

**Source Path**: `usr/share/hardn/scripts/hardn-service-manager.sh`

**Installation Process**:
```bash
install -m 755 usr/share/hardn/scripts/hardn-service-manager.sh debian/hardn/usr/bin/hardn-service-manager
```

## 2. **Script Initialization** 🚀

When you run `sudo hardn-service-manager`, execution begins at:

```bash
# Main execution
check_root
check_dependencies
main_menu
```

### **Step 2.1**: Root Check
```bash
# Function to check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_colored "$RED" "This script must be run as root!"
        echo "Please run with: sudo $0"
        exit 1
    fi
}
```

### **Step 2.2**: Find HARDN Binary
```bash
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
```

### **Step 2.3**: Dependency Check
```bash
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
        # ... error details ...
        exit 1
    fi
    
    echo "Using HARDN binary: $HARDN_BIN"
}
```

## 3. **Main Menu Loop** 🎯

### **Step 3.1**: Display Header and Service Status
```bash
# Main menu function
main_menu() {
    while true; do
        display_header
        display_service_status
        
        echo -e "${BOLD}Main Menu:${NC}"
        echo -e "─────────────────────────────────────────────────"
        # ... menu options ...
```

### **Step 3.2**: Header Display
```bash
# Function to display the header
display_header() {
    clear
    echo -e "${CYAN}╔═══════════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${NC}                     ${BOLD}HARDN Service Manager${NC}                           ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}         Linux Security Hardening & Extended Detection Toolkit                ${CYAN}║${NC}"
    echo -e "${CYAN}╚═══════════════════════════════════════════════════════════════════════════╝${NC}"
    echo
}
```

### **Step 3.3**: Service Status Check
```bash
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
```

## 4. **HARDN Binary Integration** ⚙️

The service manager calls the main HARDN binary (`/usr/bin/hardn`) which starts at:

```rust
/// Main entry point for HARDN
fn main() {
    let args: Vec<String> = env::args().collect();
    let module_dirs = env_or_defaults("HARDN_MODULE_PATH", DEFAULT_MODULE_DIRS);
    let tool_dirs = env_or_defaults("HARDN_TOOL_PATH", DEFAULT_TOOL_DIRS);

    // Only show banner for commands that benefit from it and when stdout is a TTY
    let show_banner = match args.len() {
        1 => false, // No args - show help menu instead
        2 => matches!(args[1].as_str(), "-h" | "--help" | "help" | "-a" | "--about" | "about"),
        _ => false,
    } && atty::is(atty::Stream::Stdout);

    if show_banner {
        print_banner();
    }

    let exit_code = if args.len() >= 2 && (args[1] == "legion" || args[1] == "--legion") {
        run_legion(&args)
    } else {
        match args.len() {
            1 => {
                print_help();
                EXIT_SUCCESS
            }
            2 => {
                match args[1].as_str() {
                    "-v" | "--version" | "version" => {
                        println!("{} version {}", APP_NAME, VERSION);
                        EXIT_SUCCESS
                    }
                    // ... all other command options ...
                }
            }
```

### **Example Call Flows from Service Manager**:

1. **LEGION Execution**:
   ```bash
   "$HARDN_BIN" legion
   ```
   ↓ Calls:
   ```rust
   /// Run the LEGION monitoring tool
   fn run_legion(args: &[String]) -> i32 {
       // Pass the remaining arguments to the legion module
       // Skip "hardn" and "legion" from the args
       let legion_args = if args.len() > 2 {
           args[2..].to_vec()
       } else {
           vec![]
       };

       // Set up environment for legion
       std::env::set_var("RUST_BACKTRACE", "1");

       // Create a tokio runtime for async legion execution
       let rt = tokio::runtime::Runtime::new().unwrap();

       // Call the legion module
       rt.block_on(async {
           match crate::legion::legion::run_with_args(&legion_args).await {
               Ok(()) => EXIT_SUCCESS,
               Err(e) => {
                   log_message(LogLevel::Error, &format!("LEGION failed: {}", e));
                   EXIT_FAILURE
               }
           }
       })
   }
   ```

2. **Security Report Generation**:
   ```bash
   "$HARDN_BIN" --security-report
   ```
   ↓ Calls:
   ```rust
   /// Generate and display comprehensive security report
   fn generate_security_report() {
       println!("\n╔═══════════════════════════════════════════════════════════════════════════════╗");
       println!("║                     HARDN COMPREHENSIVE SECURITY REPORT                     ║");
       println!("╚═════════════════════════════════════════════════════════════════════════════════╝\n");
       // ... comprehensive reporting logic ...
   }
   ```

## 5. **Complete Execution Flow Diagram** 📊

```
sudo hardn-service-manager
│
├─ ENTRY POINT: /usr/bin/hardn-service-manager
│  │
│  └─ SOURCE: usr/share/hardn/scripts/hardn-service-manager.sh
│
├─ SCRIPT INITIALIZATION
│  │
│  ├─ 1. Signal Handlers Setup (line 10)
│  │   └─ trap 'echo -e "\n\nInterrupted. Exiting..."; exit 130' INT TERM
│  │
│  ├─ 2. Color & Configuration Setup (lines 12-24)
│  │   ├─ Color codes definition
│  │   └─ HARDN_SERVICES="hardn.service hardn-api.service legion-daemon.service hardn-monitor.service"
│  │
│  ├─ 3. Find HARDN Binary (lines 26-55)
│  │   ├─ Search paths: ./target/release/hardn, /usr/bin/hardn, etc.
│  │   └─ Set HARDN_BIN variable
│  │
│  ├─ 4. Root Check (lines 65-71)
│  │   └─ check_root() - Verify EUID == 0
│  │
│  └─ 5. Dependencies Check (lines 73-106)
│      ├─ Verify systemctl & journalctl available
│      └─ Verify HARDN binary exists and is executable
│
├─ MAIN EXECUTION LOOP
│  │
│  └─ main_menu() - Infinite loop (lines 665-778)
│     │
│     ├─ Display Functions
│     │  ├─ display_header() - ASCII banner (lines 108-116)
│     │  └─ display_service_status() - Check systemctl status (lines 130-155)
│     │
│     └─ Menu Options (lines 671-687)
│        ├─ 1) Quick Start - Enable & Start All Services
│        ├─ 2) Manage HARDN Services → manage_services_menu()
│        ├─ 3) Run HARDN Modules → run_modules_menu()
│        ├─ 4) Run Security Tools → run_tools_menu()
│        ├─ 5) LEGION Security Monitoring → run_legion_menu()
│        ├─ 6) Generate Security Report
│        ├─ 7) View HARDN Status
│        ├─ 8) Sandbox Mode (Network Isolation)
│        ├─ 9) Run Everything (Modules + Tools)
│        └─ 10) Dangerous Operations
│
├─ HARDN BINARY INTEGRATION
│  │
│  └─ Calls to "$HARDN_BIN" → /usr/bin/hardn
│     │
│     ├─ ENTRY: src/main.rs::main() (line 1770)
│     │  ├─ Parse args: Vec<String>
│     │  ├─ Set up module/tool directories
│     │  └─ Route to appropriate function
│     │
│     ├─ Common Calls from Service Manager:
│     │  ├─ "$HARDN_BIN" legion → run_legion() (line 1740)
│     │  │   └─ crate::legion::legion::run_with_args()
│     │  ├─ "$HARDN_BIN" --security-report → generate_security_report() (line 95)
│     │  ├─ "$HARDN_BIN" --list-modules → print_modules() (line 31)
│     │  ├─ "$HARDN_BIN" --list-tools → print_tools() (line 60)
│     │  ├─ "$HARDN_BIN" run-module <name> → handle_run_module()
│     │  └─ "$HARDN_BIN" --run-all-modules → run_all_modules()
│     │
│     └─ EXIT: process::exit(exit_code) (line 1880)
│
└─ USER INTERACTION FLOW
   │
   ├─ Interactive Menu System
   │  ├─ Bash 'read' commands for user input
   │  ├─ Case statements for option routing
   │  └─ Colored output using escape sequences
   │
   ├─ Service Management
   │  ├─ systemctl commands via manage_service()
   │  └─ journalctl for log viewing
   │
   └─ Error Handling
      ├─ Signal traps (Ctrl+C handling)
      ├─ Input validation
      └─ Command execution status checking
```

## **Key Files and Their Roles**:

1. **`usr/share/hardn/scripts/hardn-service-manager.sh`** - Main interactive bash script
2. **`src/main.rs`** - HARDN binary entry point and command router  
3. **`src/legion/legion.rs`** - LEGION security monitoring module
4. **`debian/rules`** - Installation configuration
5. **`debian/postinst`** - Post-installation setup script

The execution flow is a hybrid bash/Rust system where the bash script provides the interactive interface and service management, while calling the Rust binary for core security operations and monitoring tasks.