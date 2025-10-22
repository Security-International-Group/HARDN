//! # HARDN Main Entry Point
//!
//! ## Overview
//! This is the main entry point for the HARDN security hardening and threat detection system.
//! It serves as a CLI orchestrator that discovers and executes modular shell scripts for system
//! hardening, security configuration, and threat detection on Debian-based Linux systems.
//!
//! ## Architecture
//! HARDN follows a hybrid architecture:
//! - **Rust CLI** (this file): Provides the command-line interface, argument parsing, and module discovery
//! - **Shell Modules**: Individual bash scripts that perform specific security operations
//! - **Shell Tools**: Standalone security tools that can be executed independently
//!
//! ## Core Responsibilities
//! 1. **Module Discovery**: Automatically finds and lists available `.sh` scripts in configured directories
//! 2. **Script Orchestration**: Executes shell modules/tools with proper environment setup
//! 3. **Path Management**: Handles both development and production installation paths
//! 4. **Environment Setup**: Sets required environment variables before script execution
//! 5. **User Interface**: Provides colored output, help text, and command-line argument parsing
//! 6. **Error Handling**: Captures and reports script execution status with appropriate logging
//!
//! ## Features
//! - **Auto-discovery**: Automatically finds all `.sh` modules when run without arguments
//! - **Selective Execution**: Run specific modules or tools by name
//! - **Flexible Paths**: Supports custom module/tool paths via environment variables
//! - **Development Mode**: Searches multiple paths to support both dev and production environments
//! - **Colored Output**: Uses ANSI color codes for better readability (green=pass, red=error, etc.)
//! - **Dynamic Help**: Shows available modules and tools in the help output
//!
//! ## Usage Patterns
//! ```bash
//! # Run all modules (full security hardening)
//! sudo hardn
//!
//! # Run a specific module
//! sudo hardn run-module hardening
//!
//! # Run a specific security tool
//! sudo hardn run-tool lynis
//!
//! # List available modules
//! sudo hardn --list-modules
//!
    tool_score = (tool_points / max_tool_points * 60.0).min(60.0);
//! sudo hardn --help
//! ```
    println!("  \x1b[1;33mTool Score: {:.1}/60\x1b[0m\n", tool_score);
//! ## Environment Variables
//! The following environment variables are passed to all executed scripts:
//! - `HARDN_MODULES_DIR`: Primary module directory path
//! - `HARDN_LOG_DIR`: Directory for log files (/var/log/hardn)
//! - `HARDN_LIB_DIR`: Directory for data/backups (/var/lib/hardn)
//! - `HARDN_VERSION`: Current version of HARDN
//!
//! ## Path Resolution
//! The system searches for modules/tools in the following order:
//! 1. Custom paths from environment variables (HARDN_MODULE_PATH, HARDN_TOOL_PATH)
//! 2. Production path: /usr/share/hardn/{modules,tools}
//! 3. Development path: /usr/lib/hardn/src/setup/{modules,tools}
//! 4. Local install: /usr/local/share/hardn/{modules,tools}
//!
//! ## Module Requirements
//! Shell modules are expected to:
//! - Be executable bash scripts with `.sh` extension
//! - Source common utilities from $HARDN_MODULES_DIR
//! - Return appropriate exit codes (0 for success)
//! - Use the logging functions provided by the framework
//!
//! ## Error Handling
//! - Missing modules/tools are reported with search paths for debugging
//! - Script failures are logged with exit status
//! - Invalid arguments show help text with error messages
//! - All errors use colored output for visibility
//!
//! ## Security Considerations
//! - This binary must be run with sudo/root privileges
//! - All executed scripts run with inherited privileges
//! - Module scripts can make system-wide security changes
//! - Careful path validation prevents arbitrary script execution
//!
//! ## Future Improvements (TODOs)
//! - Clean up legacy development paths once deployment is finalized
//! - Add module dependency resolution
//! - Implement parallel module execution for performance
//! - Add dry-run mode for testing
//! - Enhance progress reporting for long-running modules
    module_score = (module_points / 10.0 * 40.0).min(40.0);
//! ## Author
//! Developed by the Security International Group (SIG) Team
//! License: MIT
    println!("  \x1b[1;33mModule Score: {:.1}/40\x1b[0m\n", module_score);

// main.rs

use std::env;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{self, Command, ExitStatus, Stdio};
use std::fmt;
use std::error::Error;
use std::time::{SystemTime, UNIX_EPOCH};

/// Application version - single source of truth
const VERSION: &str = "2.2.0";

/// Application name
const APP_NAME: &str = "HARDN";

/// Default environment variable values
const DEFAULT_LOG_DIR: &str = "/var/log/hardn";
const DEFAULT_LIB_DIR: &str = "/var/lib/hardn";

/// Exit codes
const EXIT_SUCCESS: i32 = 0;
const EXIT_FAILURE: i32 = 1;
const EXIT_USAGE: i32 = 2;

/// Custom error type for better error handling
/// 
/// Note: Some variants are marked as dead_code but are kept for future use.
/// As we continue refactoring, these will be utilized for more specific error cases.
#[derive(Debug)]
enum HardnError {
    #[allow(dead_code)]  // Will be used in future error handling improvements
    ModuleNotFound(String),
    #[allow(dead_code)]  // Will be used in future error handling improvements
    ToolNotFound(String),
    ExecutionFailed(String),
    IoError(io::Error),
    #[allow(dead_code)]  // Will be used in future error handling improvements
    InvalidArgument(String),
}

impl fmt::Display for HardnError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            HardnError::ModuleNotFound(name) => write!(f, "Module '{}' not found", name),
            HardnError::ToolNotFound(name) => write!(f, "Tool '{}' not found", name),
            HardnError::ExecutionFailed(msg) => write!(f, "Execution failed: {}", msg),
            HardnError::IoError(err) => write!(f, "I/O error: {}", err),
            HardnError::InvalidArgument(msg) => write!(f, "Invalid argument: {}", msg),
        }
    }
}

impl Error for HardnError {}

impl From<io::Error> for HardnError {
    fn from(err: io::Error) -> Self {
        HardnError::IoError(err)
    }
}

/// Result type alias for cleaner code
type HardnResult<T> = Result<T, HardnError>;

/// Default directories to search for module scripts
/// These are searched in order, with the first match being used
/// TODO: Clean up path detection - currently supporting both local dev and package install
/// Remove legacy paths once deployment strategy is finalized
const DEFAULT_MODULE_DIRS: &[&str] = &[
    "/usr/share/hardn/modules",              // Production: installed via package
    "/usr/lib/hardn/src/setup/modules",  // Development/legacy - TODO: remove
    "/usr/local/share/hardn/modules",        // Local installation
];

/// Default directories to search for tool scripts
/// Tools are standalone security utilities that can be run independently
const DEFAULT_TOOL_DIRS: &[&str] = &[
    "/usr/share/hardn/tools",                // Production: installed via package
    "/usr/lib/hardn/src/setup/tools",    // Development/legacy - TODO: remove
    "/usr/local/share/hardn/tools",          // Local installation
];

/* ---------- Banner and Help ---------- */

/// Prints the HARDN ASCII art banner
/// Displayed at the start of every program execution
fn print_banner() {
    println!(
        r#"
   ▄█    █▄           ▄████████        ▄████████     ████████▄      ███▄▄▄▄
  ███    ███         ███    ███       ███    ███     ███   ▀███     ███▀▀▀██▄
  ███    ███         ███    ███       ███    ███     ███    ███     ███   ███
 ▄███▄▄▄▄███▄▄       ███    ███      ▄███▄▄▄▄██▀     ███    ███     ███   ███
▀▀███▀▀▀▀███▀      ▀███████████     ▀▀███▀▀▀▀▀       ███    ███     ███   ███
  ███    ███         ███    ███     ▀███████████     ███    ███     ███   ███
  ███    ███         ███    ███       ███    ███     ███   ▄███     ███   ███
  ███    █▀          ███    █▀        ███    ███     ████████▀       ▀█   █▀
                                      ███    ███

                        Extended Detection & Response
"#
    );
}

/// Print list of available modules
fn print_modules() {
    let module_dirs = env_or_defaults("HARDN_MODULE_PATH", DEFAULT_MODULE_DIRS);
    
    println!("\n════════════════════════════════════════");
    println!("  AVAILABLE MODULES");
    println!("════════════════════════════════════════\n");
    
    println!("Search paths: {}", join_paths(&module_dirs));
    println!();
    
    match list_modules(&module_dirs) {
        Ok(modules) if !modules.is_empty() => {
            println!("Found {} modules:\n", modules.len());
            for module in modules {
                println!("  • {}", module);
            }
        }
        Ok(_) => {
            println!("  (no modules found)");
        }
        Err(e) => {
            println!("  Error listing modules: {}", e);
        }
    }
    
    println!("\n════════════════════════════════════════\n");
}

/// Print list of available tools
fn print_tools() {
    let tool_dirs = env_or_defaults("HARDN_TOOL_PATH", DEFAULT_TOOL_DIRS);
    
    println!("\n════════════════════════════════════════");
    println!("  AVAILABLE TOOLS");
    println!("════════════════════════════════════════\n");
    
    println!("Search paths: {}", join_paths(&tool_dirs));
    println!();
    
    match list_modules(&tool_dirs) {
        Ok(tools) if !tools.is_empty() => {
            println!("Found {} tools:\n", tools.len());
            
            // Categorize and display tools
            let categorized = categorize_tools(&tools);
            for (category, cat_tools) in categorized {
                println!("{}:", category);
                for tool in cat_tools {
                    println!("  • {}", tool);
                }
                println!();
            }
        }
        Ok(_) => {
            println!("  (no tools found)");
        }
        Err(e) => {
            println!("  Error listing tools: {}", e);
        }
    }
    
    println!("════════════════════════════════════════\n");
}

/// Generate and display comprehensive security report
fn generate_security_report() {
    println!("\n╔═══════════════════════════════════════════════════════════════════════════════╗");
    println!("║                     HARDN COMPREHENSIVE SECURITY REPORT                    ║");
    println!("╚═══════════════════════════════════════════════════════════════════════════════╝\n");
    
    // Track scoring components
    let tool_score: f64;
    let module_score: f64;
    
    // 1. Check active security tools (60% of total score)
    println!("\x1b[1;36m▶ SECURITY TOOLS ASSESSMENT (60% weight):\x1b[0m");
    let tools = get_security_tools();
    let mut active_tools = 0;
    let mut enabled_tools = 0;
    
    for tool in &tools {
        let status = check_service_status(tool.service_name);
        if status.active {
            active_tools += 1;
            print!("  \x1b[32m✓\x1b[0m {:<12}", tool.name);
            println!(" [ACTIVE]");
        } else if status.enabled {
            enabled_tools += 1;
            print!("  \x1b[33m●\x1b[0m {:<12}", tool.name);
            println!(" [ENABLED but not running]");
        } else {
            print!("  \x1b[31m✗\x1b[0m {:<12}", tool.name);
            println!(" [DISABLED]");
        }
    }
    
    // Calculate tool score: active tools get full points, enabled get half
    let max_tool_points = tools.len() as f64;
    let tool_points = (active_tools as f64) + (enabled_tools as f64 * 0.5);
    tool_score = (tool_points / max_tool_points * 60.0).min(60.0);
    
    println!("\n  Active: {}/{}, Enabled: {}/{}", active_tools, tools.len(), enabled_tools, tools.len());
    println!("  \x1b[1;33mTool Score: {:.1}/60\x1b[0m\n", tool_score);
    
    // 2. Check executed modules (40% of total score)
    println!("\x1b[1;36m▶ MODULE EXECUTION STATUS (40% weight):\x1b[0m");
    
    // Check if log directory exists and analyze module execution
    let mut executed_modules = Vec::new();
    if Path::new(DEFAULT_LOG_DIR).exists() {
        // Check for module execution logs
        let log_files = vec![
            "hardn.log",
            "hardn-tools.log",
            "hardn-modules.log",
            "hardening.log",
            "audit.log"
        ];
        
        for log_file in &log_files {
            let log_path = format!("{}/{}", DEFAULT_LOG_DIR, log_file);
            if Path::new(&log_path).exists() {
                executed_modules.push(log_file.to_string());
                println!("  \x1b[32m✓\x1b[0m {} found", log_file);
            }
        }
    }
    
    // Check HARDN services
    let hardn_services = vec!["hardn", "hardn", "hardn-monitor"];
    let mut active_services = 0;
    for service in &hardn_services {
        let status = check_service_status(service);
        if status.active || status.enabled {
            active_services += 1;
        }
    }
    
    // Calculate module score based on logs and services
    let expected_modules = 5; // Expected number of module logs
    let module_points = (executed_modules.len() as f64 / expected_modules as f64 * 10.0)
        + (active_services as f64 / hardn_services.len() as f64 * 10.0);
    module_score = (module_points / 20.0 * 40.0).min(40.0);

    println!("  HARDN services active: {}/{}", active_services, hardn_services.len());
    println!("  \x1b[1;33mModule Score: {:.1}/40\x1b[0m\n", module_score);

    // Calculate total score
    let total_score = tool_score + module_score;

    println!("╔═══════════════════════════════════════════════════════════════════════════════╗");
    println!("║                              SECURITY SCORE SUMMARY                            ║");
    println!("╠═══════════════════════════════════════════════════════════════════════════════╣");
    println!("║  Component                │    Score    │ Weight │         Status              ║");
    println!("╠───────────────────────────┼─────────────┼────────┼─────────────────────────────╣");

    let tool_status = if tool_score >= 45.0 { "✓" } else if tool_score >= 30.0 { "●" } else { "✗" };
    let module_status = if module_score >= 30.0 { "✓" } else if module_score >= 20.0 { "●" } else { "✗" };

    println!(
        "║  Security Tools           │  {:>6.1}/60  │  60%   │             {}               ║",
        tool_score, tool_status
    );
    println!(
        "║  Module Execution         │  {:>6.1}/40  │  40%   │             {}               ║",
        module_score, module_status
    );
    println!("╠═══════════════════════════╧═════════════╧════════╧═════════════════════════════╣");
    
    // Determine overall grade and color
    let (grade, grade_color) = match total_score as i32 {
        0..=49 => ("F", "\x1b[1;31m"),     // Red
        50..=59 => ("D", "\x1b[1;31m"),    // Red
        60..=69 => ("C", "\x1b[1;33m"),    // Yellow
        70..=79 => ("B", "\x1b[1;33m"),    // Yellow
        80..=89 => ("A", "\x1b[1;32m"),    // Green
        _ => ("A+", "\x1b[1;32m"),         // Green
    };
    
    let score_text = format!("TOTAL SCORE: {:.1}/100  Grade: {}", total_score, grade);
    let padding = 78 - score_text.len();

    println!(
        "║  {}{}{}{:width$}║",
        grade_color,
        score_text,
        "\x1b[0m",
        " ",
        width = padding
    );
    println!("╚════════════════════════════════════════════════════════════════════════════════╝");

    // Recommendations
    println!("\n\x1b[1;36m▶ RECOMMENDATIONS:\x1b[0m\n");

    if tool_score < 45.0 {
        println!("  • Enable more security tools to improve protection");
        println!("    Run: sudo hardn run-tool <tool-name>\n");
    }

    if module_score < 30.0 {
        println!("  • Execute HARDN modules for system hardening");
        println!("    Run: sudo hardn run-module hardening\n");
    }

    if total_score >= 80.0 {
        println!("  \x1b[1;32m✓ System security posture is strong. Maintain regular audits.\x1b[0m\n");
    }

    println!("═══════════════════════════════════════════════════════════════════════════════\n");
}

/// Run all available modules
/// NOTE: This function ONLY runs .sh scripts found in module directories
/// It does NOT include sandbox commands which are independent safety features
fn run_all_modules() -> i32 {
    let module_dirs = env_or_defaults("HARDN_MODULE_PATH", DEFAULT_MODULE_DIRS);
    
    println!("\n═══ RUNNING ALL MODULES ═══\n");
    log_message(LogLevel::Info, "Starting execution of all available modules...");
    log_message(LogLevel::Info, "Note: Sandbox commands are NOT included in batch operations");
    
    let modules = match list_modules(&module_dirs) {
        Ok(mods) => mods,
        Err(e) => {
            log_message(LogLevel::Error, &format!("Failed to list modules: {}", e));
            return EXIT_FAILURE;
        }
    };
    
    if modules.is_empty() {
        log_message(LogLevel::Warning, "No modules found to run");
        return EXIT_SUCCESS;
    }
    
    let mut failed = 0;
    let mut succeeded = 0;
    
    for module_name in &modules {
        println!("\n──────────────────────────────────────");
        log_message(LogLevel::Info, &format!("Running module: {}", module_name));
        
        if let Some(path) = find_script(&module_dirs, module_name) {
            match run_script(&path, "module", &module_dirs) {
                Ok(status) if status.success() => {
                    log_message(LogLevel::Pass, &format!("Module {} completed successfully", module_name));
                    succeeded += 1;
                },
                Ok(_) => {
                    log_message(LogLevel::Error, &format!("Module {} failed", module_name));
                    failed += 1;
                },
                Err(e) => {
                    log_message(LogLevel::Error, &format!("Failed to run {}: {}", module_name, e));
                    failed += 1;
                }
            }
        }
    }
    
    println!("\n═══════════════════════════════════════");
    log_message(LogLevel::Info, &format!("Module execution complete: {} succeeded, {} failed out of {} total", 
                                         succeeded, failed, modules.len()));
    
    if failed > 0 {
        EXIT_FAILURE
    } else {
        EXIT_SUCCESS
    }
}

/// Run all available tools
/// NOTE: This function ONLY runs .sh scripts found in tool directories
/// It does NOT include sandbox commands which are independent safety features
fn run_all_tools() -> i32 {
    let tool_dirs = env_or_defaults("HARDN_TOOL_PATH", DEFAULT_TOOL_DIRS);
    let module_dirs = env_or_defaults("HARDN_MODULE_PATH", DEFAULT_MODULE_DIRS);
    
    println!("\n═══ RUNNING ALL TOOLS ═══\n");
    log_message(LogLevel::Info, "Starting execution of all available tools...");
    log_message(LogLevel::Info, "Note: Sandbox commands are NOT included in batch operations");
    
    let tools = match list_modules(&tool_dirs) {
        Ok(tls) => tls,
        Err(e) => {
            log_message(LogLevel::Error, &format!("Failed to list tools: {}", e));
            return EXIT_FAILURE;
        }
    };
    
    if tools.is_empty() {
        log_message(LogLevel::Warning, "No tools found to run");
        return EXIT_SUCCESS;
    }
    
    let mut failed = 0;
    let mut succeeded = 0;
    
    for tool_name in &tools {
        println!("\n──────────────────────────────────────");
        log_message(LogLevel::Info, &format!("Running tool: {}", tool_name));
        
        if let Some(path) = find_script(&tool_dirs, tool_name) {
            match run_script(&path, "tool", &module_dirs) {
                Ok(status) if status.success() => {
                    log_message(LogLevel::Pass, &format!("Tool {} completed successfully", tool_name));
                    succeeded += 1;
                },
                Ok(_) => {
                    log_message(LogLevel::Error, &format!("Tool {} failed", tool_name));
                    failed += 1;
                },
                Err(e) => {
                    log_message(LogLevel::Error, &format!("Failed to run {}: {}", tool_name, e));
                    failed += 1;
                }
            }
        }
    }
    
    println!("\n═══════════════════════════════════════");
    log_message(LogLevel::Info, &format!("Tool execution complete: {} succeeded, {} failed out of {} total", 
                                         succeeded, failed, tools.len()));
    
    if failed > 0 {
        EXIT_FAILURE
    } else {
        EXIT_SUCCESS
    }
}

/// Run all modules and tools
/// IMPORTANT: This function runs ONLY the .sh scripts in modules and tools directories
/// Sandbox commands (--sandbox-on/--sandbox-off) are NEVER included in this batch operation
/// They must be run independently for safety reasons
fn run_everything() -> i32 {
    println!("\n╔═══════════════════════════════════════╗");
    println!("║     RUNNING ALL MODULES AND TOOLS     ║");
    println!("╚═══════════════════════════════════════╝\n");
    
    log_message(LogLevel::Warning, "⚠️  Note: Sandbox mode is NOT included in batch operations");
    log_message(LogLevel::Info, "Starting complete system hardening...");
    
    // Run all modules first
    println!("\n▶ PHASE 1: MODULES");
    let module_result = run_all_modules();
    
    // Run all tools second
    println!("\n▶ PHASE 2: TOOLS");
    let tool_result = run_all_tools();
    
    // Report overall status
    println!("\n╔═══════════════════════════════════════╗");
    println!("║           EXECUTION SUMMARY            ║");
    println!("╚═══════════════════════════════════════╝\n");
    
    if module_result == EXIT_SUCCESS && tool_result == EXIT_SUCCESS {
        log_message(LogLevel::Pass, "All modules and tools executed successfully");
        EXIT_SUCCESS
    } else if module_result != EXIT_SUCCESS && tool_result != EXIT_SUCCESS {
        log_message(LogLevel::Error, "Both modules and tools had failures");
        EXIT_FAILURE
    } else if module_result != EXIT_SUCCESS {
        log_message(LogLevel::Warning, "Some modules failed, but tools succeeded");
        EXIT_FAILURE
    } else {
        log_message(LogLevel::Warning, "Modules succeeded, but some tools failed");
        EXIT_FAILURE
    }
}

/// Enable sandbox mode - disconnect from internet and close all ports
/// IMPORTANT: This function is ONLY called directly via --sandbox-on flag
/// It is NEVER included in batch operations (--run-all-modules, --run-all-tools, --run-everything)
/// This is a critical safety feature to prevent accidental network isolation during automated runs
fn sandbox_on() -> i32 {
    println!("\n╔═══════════════════════════════════════╗");
    println!("║         ENABLING SANDBOX MODE         ║");
    println!("╚═══════════════════════════════════════╝\n");
    
    log_message(LogLevel::Warning, "  SANDBOX MODE - Manual activation only");
    log_message(LogLevel::Warning, "This command must be run independently");
    log_message(LogLevel::Warning, "Activating network isolation...");
    
    // Save current network configuration
    let backup_dir = "/var/lib/hardn/sandbox-backup";
    let _ = fs::create_dir_all(backup_dir);
    
    // Backup current iptables rules
    let iptables_backup = Command::new("iptables-save")
        .output();
    
    match iptables_backup {
        Ok(output) => {
            let backup_file = format!("{}/iptables.rules", backup_dir);
            if fs::write(&backup_file, output.stdout).is_ok() {
                log_message(LogLevel::Pass, "Current firewall rules backed up");
            }
        }
        Err(_) => {
            log_message(LogLevel::Warning, "Could not backup iptables rules");
        }
    }
    
    // Backup current network interfaces state
    let _ = Command::new("ip")
        .args(["addr", "show"])
        .output()
        .and_then(|output| {
            fs::write(format!("{}/network-interfaces.txt", backup_dir), output.stdout)
        });
    
    // Drop all network traffic
    let mut success = true;
    
    // Set default policies to DROP
    let policies = vec![
        ("INPUT", "DROP"),
        ("OUTPUT", "DROP"),
        ("FORWARD", "DROP"),
    ];
    
    for (chain, policy) in policies {
        match Command::new("iptables")
            .args(["-P", chain, policy])
            .status()
        {
            Ok(status) if status.success() => {
                log_message(LogLevel::Pass, &format!("Set {} policy to {}", chain, policy));
            }
            _ => {
                log_message(LogLevel::Error, &format!("Failed to set {} policy", chain));
                success = false;
            }
        }
    }
    
    // Allow only loopback traffic
    let loopback_rules = vec![
        vec!["-A", "INPUT", "-i", "lo", "-j", "ACCEPT"],
        vec!["-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT"],
    ];
    
    for rule in loopback_rules {
        let _ = Command::new("iptables")
            .args(rule)
            .status();
    }
    
    // Disable all network interfaces except loopback
    let interfaces_output = Command::new("ip")
        .args(["link", "show"])
        .output();
    
    if let Ok(output) = interfaces_output {
        let output_str = String::from_utf8_lossy(&output.stdout);
        for line in output_str.lines() {
            if let Some(iface_name) = line.split(':').nth(1) {
                let iface = iface_name.trim();
                if iface != "lo" && !iface.starts_with("@") {
                    match Command::new("ip")
                        .args(["link", "set", iface, "down"])
                        .status()
                    {
                        Ok(status) if status.success() => {
                            log_message(LogLevel::Pass, &format!("Disabled interface: {}", iface));
                        }
                        _ => {
                            log_message(LogLevel::Warning, &format!("Could not disable interface: {}", iface));
                        }
                    }
                }
            }
        }
    }
    
    // Create sandbox marker file
    let _ = fs::write("/var/lib/hardn/sandbox.active", "active");
    
    println!("\n═══════════════════════════════════════");
    if success {
        log_message(LogLevel::Pass, "SANDBOX MODE ACTIVATED");
        println!("\n⚠️  WARNING: Network access has been disabled");
        println!("   - All network interfaces are down (except loopback)");
        println!("   - All network ports are closed");
        println!("   - No internet connectivity");
        println!("\nTo restore network access, run: sudo hardn --sandbox-off");
        EXIT_SUCCESS
    } else {
        log_message(LogLevel::Error, "Sandbox mode activation had some failures");
        EXIT_FAILURE
    }
}

/// Enable SELinux (DANGEROUS - requires system reboot)
/// CRITICAL: This function is ONLY called directly via --enable-selinux flag
/// It is NEVER included in batch operations for safety reasons
/// WARNING: This will DISABLE AppArmor and REQUIRE a system reboot
fn enable_selinux() -> i32 {
    println!("\n╔═══════════════════════════════════════╗");
    println!("║           ⚠️  DANGER ZONE ⚠️            ║");
    println!("║         SELINUX ACTIVATION          ║");
    println!("╚═══════════════════════════════════════╝\n");
    
    log_message(LogLevel::Error, "⚠️  CRITICAL WARNING: SELinux activation will:");
    log_message(LogLevel::Error, "   1. DISABLE AppArmor (if active)");
    log_message(LogLevel::Error, "   2. Modify GRUB bootloader configuration");
    log_message(LogLevel::Error, "   3. REQUIRE a system reboot");
    log_message(LogLevel::Error, "   4. May break existing applications");
    println!();
    log_message(LogLevel::Warning, "This is a MAJOR system change that cannot be easily reversed.");
    println!();
    
    // Ask for explicit confirmation
    println!("Type 'YES I UNDERSTAND THE RISKS' to proceed, or anything else to abort:");
    
    use std::io::{self, BufRead};
    let stdin = io::stdin();
    let mut input = String::new();
    let _ = stdin.lock().read_line(&mut input);
    
    if input.trim() != "YES I UNDERSTAND THE RISKS" {
        log_message(LogLevel::Pass, "SELinux activation ABORTED - good choice!");
        return EXIT_SUCCESS;
    }
    
    // Check if the SELinux script exists
    let selinux_script = "/usr/share/hardn/tools/selinux.sh.DANGEROUS";
    if !Path::new(selinux_script).exists() {
        log_message(LogLevel::Error, "SELinux script not found. This is intentional for safety.");
        log_message(LogLevel::Info, "SELinux must be configured manually or the script restored.");
        return EXIT_FAILURE;
    }
    
    // Run the dangerous SELinux script
    log_message(LogLevel::Warning, "Proceeding with SELinux activation...");
    
    match Command::new("bash")
        .arg(selinux_script)
        .status()
    {
        Ok(status) if status.success() => {
            println!("\n═══════════════════════════════════════");
            log_message(LogLevel::Pass, "SELinux configuration completed");
            log_message(LogLevel::Error, "⚠️  SYSTEM REBOOT REQUIRED!");
            log_message(LogLevel::Warning, "Run: sudo reboot");
            EXIT_SUCCESS
        }
        _ => {
            log_message(LogLevel::Error, "SELinux configuration failed");
            EXIT_FAILURE
        }
    }
}

/// Disable sandbox mode - restore network configuration
/// IMPORTANT: This function is ONLY called directly via --sandbox-off flag
/// It is NEVER included in batch operations (--run-all-modules, --run-all-tools, --run-everything)
/// This is a critical safety feature to ensure manual control over network restoration
fn sandbox_off() -> i32 {
    println!("\n╔═══════════════════════════════════════╗");
    println!("║        DISABLING SANDBOX MODE          ║");
    println!("╚═══════════════════════════════════════╝\n");
    
    // Check if sandbox is active
    if !Path::new("/var/lib/hardn/sandbox.active").exists() {
        log_message(LogLevel::Warning, "Sandbox mode is not currently active");
        return EXIT_SUCCESS;
    }
    
    log_message(LogLevel::Info, "Restoring network configuration...");
    
    let backup_dir = "/var/lib/hardn/sandbox-backup";
    let mut success = true;
    
    // Restore iptables rules
    let iptables_backup = format!("{}/iptables.rules", backup_dir);
    if Path::new(&iptables_backup).exists() {
        match Command::new("iptables-restore")
            .stdin(Stdio::from(fs::File::open(&iptables_backup).unwrap_or_else(|_| {
                log_message(LogLevel::Error, "Could not open iptables backup file");
                process::exit(EXIT_FAILURE);
            })))
            .status()
        {
            Ok(status) if status.success() => {
                log_message(LogLevel::Pass, "Firewall rules restored");
            }
            _ => {
                log_message(LogLevel::Error, "Failed to restore firewall rules");
                success = false;
                
                // Fallback: set default ACCEPT policies
                let _ = Command::new("iptables").args(["-P", "INPUT", "ACCEPT"]).status();
                let _ = Command::new("iptables").args(["-P", "OUTPUT", "ACCEPT"]).status();
                let _ = Command::new("iptables").args(["-P", "FORWARD", "ACCEPT"]).status();
                let _ = Command::new("iptables").args(["-F"]).status();
            }
        }
    } else {
        // No backup found, set permissive defaults
        log_message(LogLevel::Warning, "No firewall backup found, setting default policies");
    let _ = Command::new("iptables").args(["-P", "INPUT", "ACCEPT"]).status();
    let _ = Command::new("iptables").args(["-P", "OUTPUT", "ACCEPT"]).status();
    let _ = Command::new("iptables").args(["-P", "FORWARD", "DROP"]).status();
    let _ = Command::new("iptables").args(["-F"]).status();
    }
    
    // Re-enable network interfaces
    let interfaces_output = Command::new("ip")
        .args(["link", "show"])
        .output();
    
    if let Ok(output) = interfaces_output {
        let output_str = String::from_utf8_lossy(&output.stdout);
        for line in output_str.lines() {
            if let Some(iface_name) = line.split(':').nth(1) {
                let iface = iface_name.trim();
                if iface != "lo" && !iface.starts_with("@") && !iface.starts_with("veth") {
                    match Command::new("ip")
                        .args(["link", "set", iface, "up"])
                        .status()
                    {
                        Ok(status) if status.success() => {
                            log_message(LogLevel::Pass, &format!("Enabled interface: {}", iface));
                        }
                        _ => {
                            log_message(LogLevel::Warning, &format!("Could not enable interface: {}", iface));
                        }
                    }
                }
            }
        }
    }
    
    // Restart networking service
    let _ = Command::new("systemctl")
        .args(["restart", "networking"])
        .status();
    
    // Remove sandbox marker
    let _ = fs::remove_file("/var/lib/hardn/sandbox.active");
    
    println!("\n═══════════════════════════════════════");
    if success {
        log_message(LogLevel::Pass, "SANDBOX MODE DEACTIVATED");
        println!("\n✓ Network access has been restored");
        println!("  - Network interfaces are back online");
        println!("  - Firewall rules have been restored");
        println!("  - Internet connectivity should be available");
        EXIT_SUCCESS
    } else {
        log_message(LogLevel::Warning, "Sandbox deactivation completed with some warnings");
        println!("\n⚠️  Some network settings may need manual verification");
        EXIT_FAILURE
    }
}

/// Tool category definition for scalable categorization
struct ToolCategory {
    name: &'static str,
    tools: Vec<&'static str>,
}

impl ToolCategory {
    fn new(name: &'static str, tools: Vec<&'static str>) -> Self {
        Self { name, tools }
    }
    
    fn contains(&self, tool: &str) -> bool {
        self.tools.iter().any(|&t| t == tool)
    }
}

/// Get tool categories configuration
/// This can be easily extended or loaded from a config file in the future
fn get_tool_categories() -> Vec<ToolCategory> {
    vec![
        ToolCategory::new(
            "Security Scanners",
            vec!["lynis", "rkhunter", "aide", "debsums", "yara", "legion", "chkrootkit"],
        ),
        ToolCategory::new(
            "Access Control",
            vec!["apparmor", "selinux", "firejail", "tcpd"],
        ),
        ToolCategory::new(
            "Network Security",
            vec!["ufw", "fail2ban", "legion", "openssh", "iptables"],
        ),
        ToolCategory::new(
            "System Monitoring",
            vec!["audit", "prometheus_monitoring", "centralized_logging", "auditd"],
        ),
        ToolCategory::new(
            "System Management",
            vec!["auto_update", "update_system_packages", "cron", "ntp",
                 "cleanup", "firmware", "enable_apparmor", "systemd"],
        ),
        ToolCategory::new(
            "Development Tools",
            vec!["rust", "libvirt", "qemu", "test_output", "docker"],
        ),
        ToolCategory::new(
            "Utility Tools",
            vec!["functions", "detect_os", "install_pkgdeps"],
        ),
    ]
}

/// Categorize tools into logical groups for better display
fn categorize_tools(tools: &[String]) -> Vec<(&'static str, Vec<&String>)> {
    let categories = get_tool_categories();
    let mut result: Vec<(&'static str, Vec<&String>)> = Vec::new();
    let mut uncategorized: Vec<&String> = Vec::new();
    
    // Categorize each tool
    for tool in tools {
        let mut found = false;
        
        for category in &categories {
            if category.contains(tool) {
                // Find or create category in result
                if let Some(existing) = result.iter_mut().find(|(name, _)| *name == category.name) {
                    existing.1.push(tool);
                } else {
                    result.push((category.name, vec![tool]));
                }
                found = true;
                break;
            }
        }
        
        if !found {
            uncategorized.push(tool);
        }
    }
    
    // Add uncategorized tools if any
    if !uncategorized.is_empty() {
        result.push(("Other Tools", uncategorized));
    }
    
    result
}

// Note: print_script_list removed as it's no longer needed
// The print_modules and print_tools functions now have their own implementations

fn print_about() {
    println!(
        r#"
{} - Linux Security Hardening and Extended Detection & Response Toolkit
Version: {}

Developed by: Security International Group (SIG) Team
License: MIT

HARDN is a comprehensive security hardening and threat detection system
designed for Debian-based Linux distributions. It provides:

  • STIG-compliant security hardening
  • Real-time threat detection and response
  • Automated security configuration management
  • System integrity monitoring
  • Network security hardening
  • Comprehensive audit logging
  • Vulnerability scanning and mitigation
  • Endpoint protection and monitoring

For more information, visit: https://github.com/Security-International-Group/HARDN
"#,
        APP_NAME, VERSION
    );
}

/// Service status information
#[derive(Debug)]
struct ServiceStatus {
    name: String,
    active: bool,
    enabled: bool,
    description: String,
    pid: Option<u32>,
}

/// Security tool information
struct SecurityToolInfo {
    name: &'static str,
    service_name: &'static str,
    _process_name: &'static str,  // Reserved for future process monitoring
    description: &'static str,
}

/// Get list of security tools to monitor
fn get_security_tools() -> Vec<SecurityToolInfo> {
    vec![
        SecurityToolInfo {
            name: "AIDE",
            service_name: "aide",
            _process_name: "aide",
            description: "Advanced Intrusion Detection Environment - File integrity monitoring",
        },
        SecurityToolInfo {
            name: "AppArmor",
            service_name: "apparmor",
            _process_name: "apparmor",
            description: "Mandatory Access Control system for applications",
        },
        SecurityToolInfo {
            name: "Fail2Ban",
            service_name: "fail2ban",
            _process_name: "fail2ban-server",
            description: "Intrusion prevention - Bans IPs with multiple auth failures",
        },
        SecurityToolInfo {
            name: "UFW",
            service_name: "ufw",
            _process_name: "ufw",
            description: "Uncomplicated Firewall - Network traffic filtering",
        },
        SecurityToolInfo {
            name: "Auditd",
            service_name: "auditd",
            _process_name: "auditd",
            description: "Linux Audit Framework - Security event logging",
        },
        SecurityToolInfo {
            name: "RKHunter",
            service_name: "rkhunter",
            _process_name: "rkhunter",
            description: "Rootkit Hunter - Scans for rootkits and exploits",
        },
        SecurityToolInfo {
            name: "ClamAV",
            service_name: "clamav-daemon",
            _process_name: "clamd",
            description: "Antivirus engine for detecting trojans and malware",
        },
        SecurityToolInfo {
            name: "Legion",
            service_name: "legion-daemon",
            _process_name: "legion",
            description: "Continuous anomaly detection and network telemetry",
        },
        SecurityToolInfo {
            name: "OSSEC",
            service_name: "ossec",
            _process_name: "ossec-analysisd",
            description: "Host-based Intrusion Detection System",
        },
        SecurityToolInfo {
            name: "Lynis",
            service_name: "lynis",
            _process_name: "lynis",
            description: "Security auditing and compliance testing",
        },
    ]
}

/// Check if a systemd service is active
fn check_service_status(service_name: &str) -> ServiceStatus {
    // Check if service is active
    let active_output = match Command::new("systemctl")
        .args(["is-active", service_name])
        .output() 
    {
        Ok(output) => output,
        Err(_) => return ServiceStatus {
            name: service_name.to_string(),
            active: false,
            enabled: false,
            description: String::new(),
            pid: None,
        },
    };
    
    let active = String::from_utf8_lossy(&active_output.stdout).trim() == "active";
    
    // Check if service is enabled
    let enabled_output = match Command::new("systemctl")
        .args(["is-enabled", service_name])
        .output()
    {
        Ok(output) => output,
        Err(_) => return ServiceStatus {
            name: service_name.to_string(),
            active,
            enabled: false,
            description: String::new(),
            pid: None,
        },
    };
    
    let enabled = String::from_utf8_lossy(&enabled_output.stdout).trim() == "enabled";
    
    // Get PID if service is active
    let pid = if active {
        Command::new("systemctl")
            .args(["show", service_name, "--property=MainPID"])
            .output()
            .ok()
            .and_then(|output| {
                String::from_utf8_lossy(&output.stdout)
                    .trim()
                    .strip_prefix("MainPID=")
                    .and_then(|pid_str| pid_str.parse::<u32>().ok())
                    .filter(|&pid| pid > 0)
            })
    } else {
        None
    };
    
    ServiceStatus {
        name: service_name.to_string(),
        active,
        enabled,
        description: String::new(),
        pid,
    }
}

/// Check for running HARDN processes
fn check_hardn_processes() -> Vec<String> {
    let output = match Command::new("ps")
        .arg("aux")
        .output()
    {
        Ok(output) => output,
        Err(_) => return Vec::new(),
    };
    
    let ps_output = String::from_utf8_lossy(&output.stdout);
    let mut processes = Vec::new();
    
    for line in ps_output.lines() {
        if line.contains("hardn") && !line.contains("grep") && !line.contains("hardn status") {
            // Extract relevant info from ps output
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 11 {
                let pid = parts[1];
                let cpu = parts[2];
                let mem = parts[3];
                let cmd = parts[10..].join(" ")
                    .chars()
                    .take(50)
                    .collect::<String>();
                
                processes.push(format!("  PID: {} | CPU: {}% | MEM: {}% | CMD: {}...", 
                    pid, cpu, mem, cmd));
            }
        }
    }
    
    processes
}

/// Manage HARDN services (enable, disable, start, stop, restart)
fn manage_service(action: &str) -> i32 {
    // List of manageable HARDN services (in dependency order)
    // Note: hardn-monitor is optional and may not be present
    let services = vec!["hardn", "hardn"];
    let optional_services = vec!["hardn-monitor"];
    
    match action {
        "enable" => {
            println!("\n═══ ENABLING HARDN SERVICES ═══\n");
            for service in &services {
                enable_systemd_service(service, false);
            }
            for service in &optional_services {
                enable_systemd_service(service, true);
            }
            EXIT_SUCCESS
        }
        "disable" => {
            println!("\n═══ DISABLING HARDN SERVICES ═══\n");
            for service in &services {
                disable_systemd_service(service, false);
            }
            for service in &optional_services {
                disable_systemd_service(service, true);
            }
            EXIT_SUCCESS
        }
        "start" => {
            println!("\n═══ STARTING HARDN SERVICES ═══\n");
            for service in &services {
                start_systemd_service(service, false);
            }
            for service in &optional_services {
                start_systemd_service(service, true);
            }
            EXIT_SUCCESS
        }
        "stop" => {
            println!("\n═══ STOPPING HARDN SERVICES ═══\n");
            for service in &optional_services {
                stop_systemd_service(service, true);
            }
            for service in services.iter().rev() {
                stop_systemd_service(service, false);
            }
            EXIT_SUCCESS
        }
        "restart" => {
            println!("\n═══ RESTARTING HARDN SERVICES ═══\n");
            for service in &services {
                restart_systemd_service(service, false);
            }
            for service in &optional_services {
                restart_systemd_service(service, true);
            }
            EXIT_SUCCESS
        }
        _ => {
            log_message(LogLevel::Error, &format!("Unknown service action: {}", action));
            println!("\nValid actions: enable, disable, start, stop, restart");
            println!("Example: sudo hardn service enable");
            EXIT_USAGE
        }
    }
}

/// Enable a systemd service
fn enable_systemd_service(service_name: &str, optional: bool) {
    print!("  Enabling {}... ", service_name);
    
    let output = Command::new("systemctl")
        .arg("enable")
        .arg(format!("{}.service", service_name))
        .output();
    
    match output {
        Ok(result) if result.status.success() => {
            println!("\x1b[32m✓ Enabled\x1b[0m");
        }
        Ok(result) => {
            if optional && String::from_utf8_lossy(&result.stderr).contains("not found") {
                println!("\x1b[33m⚠ Skipped (not installed)\x1b[0m");
            } else {
                println!("\x1b[31m✗ Failed\x1b[0m");
                if !result.stderr.is_empty() {
                    println!("    Error: {}", String::from_utf8_lossy(&result.stderr).trim());
                }
            }
        }
        Err(e) => {
            if optional {
                println!("\x1b[33m⚠ Skipped: {}\x1b[0m", e);
            } else {
                println!("\x1b[31m✗ Error: {}\x1b[0m", e);
            }
        }
    }
}

/// Disable a systemd service
fn disable_systemd_service(service_name: &str, optional: bool) {
    print!("  Disabling {}... ", service_name);
    
    let output = Command::new("systemctl")
        .arg("disable")
        .arg(format!("{}.service", service_name))
        .output();
    
    match output {
        Ok(result) if result.status.success() => {
            println!("\x1b[32m✓ Disabled\x1b[0m");
        }
        Ok(result) => {
            if optional && String::from_utf8_lossy(&result.stderr).contains("not found") {
                println!("\x1b[33m⚠ Skipped (not installed)\x1b[0m");
            } else {
                println!("\x1b[31m✗ Failed\x1b[0m");
                if !result.stderr.is_empty() {
                    println!("    Error: {}", String::from_utf8_lossy(&result.stderr).trim());
                }
            }
        }
        Err(e) => {
            if optional {
                println!("\x1b[33m⚠ Skipped: {}\x1b[0m", e);
            } else {
                println!("\x1b[31m✗ Error: {}\x1b[0m", e);
            }
        }
    }
}

/// Start a systemd service
fn start_systemd_service(service_name: &str, optional: bool) {
    print!("  Starting {}... ", service_name);
    
    let output = Command::new("systemctl")
        .arg("start")
        .arg(format!("{}.service", service_name))
        .output();
    
    match output {
        Ok(result) if result.status.success() => {
            println!("\x1b[32m✓ Started\x1b[0m");
        }
        Ok(result) => {
            if optional && String::from_utf8_lossy(&result.stderr).contains("not found") {
                println!("\x1b[33m⚠ Skipped (not installed)\x1b[0m");
            } else {
                println!("\x1b[31m✗ Failed\x1b[0m");
                if !result.stderr.is_empty() {
                    println!("    Error: {}", String::from_utf8_lossy(&result.stderr).trim());
                }
            }
        }
        Err(e) => {
            if optional {
                println!("\x1b[33m⚠ Skipped: {}\x1b[0m", e);
            } else {
                println!("\x1b[31m✗ Error: {}\x1b[0m", e);
            }
        }
    }
}

/// Stop a systemd service
fn stop_systemd_service(service_name: &str, optional: bool) {
    print!("  Stopping {}... ", service_name);
    
    let output = Command::new("systemctl")
        .arg("stop")
        .arg(format!("{}.service", service_name))
        .output();
    
    match output {
        Ok(result) if result.status.success() => {
            println!("\x1b[32m✓ Stopped\x1b[0m");
        }
        Ok(result) => {
            if optional && String::from_utf8_lossy(&result.stderr).contains("not found") {
                println!("\x1b[33m⚠ Skipped (not installed)\x1b[0m");
            } else {
                println!("\x1b[31m✗ Failed\x1b[0m");
                if !result.stderr.is_empty() {
                    println!("    Error: {}", String::from_utf8_lossy(&result.stderr).trim());
                }
            }
        }
        Err(e) => {
            if optional {
                println!("\x1b[33m⚠ Skipped: {}\x1b[0m", e);
            } else {
                println!("\x1b[31m✗ Error: {}\x1b[0m", e);
            }
        }
    }
}

/// Restart a systemd service
fn restart_systemd_service(service_name: &str, optional: bool) {
    print!("  Restarting {}... ", service_name);
    
    let output = Command::new("systemctl")
        .arg("restart")
        .arg(format!("{}.service", service_name))
        .output();
    
    match output {
        Ok(result) if result.status.success() => {
            println!("\x1b[32m✓ Restarted\x1b[0m");
        }
        Ok(result) => {
            if optional && String::from_utf8_lossy(&result.stderr).contains("not found") {
                println!("\x1b[33m⚠ Skipped (not installed)\x1b[0m");
            } else {
                println!("\x1b[31m✗ Failed\x1b[0m");
                if !result.stderr.is_empty() {
                    println!("    Error: {}", String::from_utf8_lossy(&result.stderr).trim());
                }
            }
        }
        Err(e) => {
            if optional {
                println!("\x1b[33m⚠ Skipped: {}\x1b[0m", e);
            } else {
                println!("\x1b[31m✗ Error: {}\x1b[0m", e);
            }
        }
    }
}

/// Display comprehensive status of HARDN
fn show_status() {
    println!("\n═══════════════════════════════════════════════════════════════════════════════");
    println!("                          HARDN SYSTEM STATUS");
    println!("═══════════════════════════════════════════════════════════════════════════════\n");
    
    // System Information
    let (version, codename) = detect_debian_version();
    println!("▶ SYSTEM INFORMATION:");
    println!("  OS: Debian {} ({})", version, codename);
    println!("  HARDN Version: {}", VERSION);
    // Get current timestamp
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    
    // Simple timestamp display (can be enhanced with external crate if needed)
    println!("  Timestamp: {} (Unix epoch)", timestamp);
    println!();
    
    // Check HARDN Services
    println!("▶ HARDN SERVICES:");
    let hardn_services = vec!["hardn-monitor", "hardn", "hardn"];
    let mut any_active = false;
    
    for service_name in &hardn_services {
        let status = check_service_status(service_name);
        let status_icon = if status.active { "✓" } else { "✗" };
        let status_color = if status.active { "\x1b[32m" } else { "\x1b[31m" };
        let enabled_text = if status.enabled { "enabled" } else { "disabled" };
        
        print!("  {} {}{:<15}\x1b[0m", status_icon, status_color, service_name);
        
        if status.active {
            if let Some(pid) = status.pid {
                println!(" [ACTIVE] [{}] (PID: {})", enabled_text, pid);
            } else {
                println!(" [ACTIVE] [{}]", enabled_text);
            }
            any_active = true;
        } else {
            println!(" [INACTIVE] [{}]", enabled_text);
        }
    }
    
    if !any_active {
        println!("  ⚠ No HARDN services are currently active");
    }
    println!();
    
    // Check Security Tools
    println!("▶ SECURITY TOOLS STATUS:");
    let tools = get_security_tools();
    let mut active_tools = 0;
    
    for tool in &tools {
        let status = check_service_status(tool.service_name);
        if status.active {
            active_tools += 1;
            print!("  \x1b[32m✓ {:<12}\x1b[0m", tool.name);
            if let Some(pid) = status.pid {
                print!(" [PID: {}]", pid);
            }
            println!(" - {}", tool.description);
        }
    }
    
    if active_tools == 0 {
        println!("  ⚠ No security tools are currently active");
    } else {
        println!("\n  Total active security tools: {}/{}", active_tools, tools.len());
    }
    println!();
    
    // Check Running HARDN Processes
    println!("▶ RUNNING HARDN PROCESSES:");
    let processes = check_hardn_processes();
    
    if processes.is_empty() {
        println!("  No HARDN processes currently running");
    } else {
        for process in processes {
            println!("{}", process);
        }
    }
    println!();
    
    // Check Recent HARDN Logs
    println!("▶ RECENT ACTIVITY:");
    if Path::new(DEFAULT_LOG_DIR).exists() {
        let log_output = Command::new("tail")
            .arg("-n")
            .arg("5")
            .arg(format!("{}/hardn.log", DEFAULT_LOG_DIR))
            .output();
        
        match log_output {
            Ok(output) if output.status.success() => {
                let logs = String::from_utf8_lossy(&output.stdout);
                if logs.trim().is_empty() {
                    println!("  No recent log entries");
                } else {
                    for line in logs.lines() {
                        println!("  {}", line);
                    }
                }
            }
            _ => {
                println!("  Log file not accessible or empty");
            }
        }
    } else {
        println!("  Log directory not found");
    }
    
    println!("\n═══════════════════════════════════════════════════════════════════════════════\n");
}

fn print_help() {
    // Get available modules and tools dynamically
    let module_dirs = env_or_defaults("HARDN_MODULE_PATH", DEFAULT_MODULE_DIRS);
    let tool_dirs = env_or_defaults("HARDN_TOOL_PATH", DEFAULT_TOOL_DIRS);
    let modules = list_modules(&module_dirs).unwrap_or_default();
    let tools = list_modules(&tool_dirs).unwrap_or_default();
    
    println!(
        r#"
{} - Linux Security Hardening and Extended Detection & Response Toolkit
A comprehensive STIG-compliant security hardening system for Debian-based systems.

Usage: sudo hardn [OPTIONS] [COMMAND]

═══════════════════════════════════════════════════════════════════════════════

▶ GENERAL OPTIONS:
  -a, --about          Show information about hardn
  -h, --help           Show help information
  -s, --status         Show current status of HARDN services and tools
  --version            Show version
  --list-modules       List all available modules
  --list-tools         List all available tools
  --security-report    Generate comprehensive security score report

▶ QUICK SERVICE COMMANDS:
  --service-enable     Enable HARDN services (shortcut for: service enable)
  --service-start      Start HARDN services (shortcut for: service start)
  --service-status     Show service status (shortcut for: --status)

▶ EXECUTION COMMANDS:
  --run-all-modules    Run all available modules
  --run-all-tools      Run all available tools  
  --run-everything     Run all modules and tools

▶ SANDBOX MODE:
  --sandbox-on         Enable sandbox mode (disconnect internet, close all ports)
  --sandbox-off        Disable sandbox mode (restore network configuration)

▶ DANGEROUS OPERATIONS (Manual Only - Never in batch operations):
  --enable-selinux     ⚠️  Enable SELinux (DISABLES AppArmor, REQUIRES REBOOT)

▶ STANDARD COMMANDS:
  status               Show current status of HARDN services and tools
  service <action>     Manage HARDN services (enable/disable/start/stop/restart)
  run-module <name>    Run a specific module by name
  run-tool <name>      Run a specific tool by name
  (no command)         Run full module suite (auto-discovers *.sh)

═══════════════════════════════════════════════════════════════════════════════
"#,
        APP_NAME
    );
    
    // Print available modules
    println!("▶ AVAILABLE MODULES ({} found):", modules.len());
    if modules.is_empty() {
        println!("    (no modules found)");
    } else {
        for module in &modules {
            println!("    • {}", module);
        }
    }
    
    println!();
    
    // Print available tools with categorization
    println!("▶ AVAILABLE TOOLS ({} found):", tools.len());
    if tools.is_empty() {
        println!("    (no tools found)");
    } else {
        // Categorize tools for better organization
        let categorized = categorize_tools(&tools);
        
        for (category, cat_tools) in categorized {
            println!("\n  {}:", category);
            for tool in cat_tools {
                println!("    • {}", tool);
            }
        }
    }
    
    println!(
        r#"
═══════════════════════════════════════════════════════════════════════════════

▶ PATH CONFIGURATION:
  Environment Variables (colon-separated):
    HARDN_MODULE_PATH=/path1:/path2   # Custom module search paths
    HARDN_TOOL_PATH=/pathA:/pathB     # Custom tool search paths

  Default Search Paths:
    Modules: /usr/share/hardn/modules,
             /usr/lib/hardn/src/setup/modules,
             /usr/local/share/hardn/modules
    
    Tools:   /usr/share/hardn/tools,
             /usr/lib/hardn/src/setup/tools,
             /usr/local/share/hardn/tools

═══════════════════════════════════════════════════════════════════════════════
"#
    );
}

/* ---------- Utility Functions ---------- */

/// Log levels for colored console output
#[derive(Debug, Clone, Copy)]
enum LogLevel {
    Pass,
    Info,
    Warning,
    Error,
}

impl LogLevel {
    fn color_code(&self) -> &'static str {
        match self {
            Self::Pass => "\x1b[1;32m",    // Green
            Self::Info => "\x1b[1;34m",    // Blue
            Self::Warning => "\x1b[1;33m", // Yellow
            Self::Error => "\x1b[1;31m",   // Red
        }
    }

    fn prefix(&self) -> &'static str {
        match self {
            Self::Pass => "[PASS]",
            Self::Info => "[INFO]",
            Self::Warning => "[WARNING]",
            Self::Error => "[ERROR]",
        }
    }
}

impl fmt::Display for LogLevel {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}{}{}", self.color_code(), self.prefix(), "\x1b[0m")
    }
}

/// Improved logging function with direct enum usage
fn log_message(level: LogLevel, message: &str) {
    println!("{} {}", level, message);
}

/// Detect the Debian version and codename from /etc/os-release
/// Returns ("unknown", "unknown") if detection fails
fn detect_debian_version() -> (String, String) {
    match fs::read_to_string("/etc/os-release") {
        Ok(content) => parse_os_release(&content),
        Err(_) => ("unknown".to_string(), "unknown".to_string()),
    }
}

/// Parse os-release file content to extract version info
fn parse_os_release(content: &str) -> (String, String) {
    let version_id = extract_os_field(content, "VERSION_ID");
    let codename = extract_os_field(content, "VERSION_CODENAME");
    (version_id, codename)
}

/// Extract a field value from os-release format
/// Handles both KEY=value and KEY="value" formats
fn extract_os_field(content: &str, field_name: &str) -> String {
    content
        .lines()
        .find(|line| line.starts_with(&format!("{}=", field_name)))
        .and_then(|line| {
            line.split_once('=')
                .map(|(_, value)| value.trim_matches('"').to_string())
        })
        .unwrap_or_else(|| "unknown".to_string())
}

/* ---------- Path Helpers ---------- */

/// Returns paths from environment variable or defaults if not set
/// Supports colon-separated paths like Unix PATH variable
/// Example: HARDN_MODULE_PATH="/path1:/path2:/path3"
fn env_or_defaults(var: &str, defaults: &[&str]) -> Vec<PathBuf> {
    match env::var(var) {
        Ok(value) if !value.trim().is_empty() => {
            parse_path_list(&value)
        }
        _ => {
            defaults.iter()
                .map(|&s| PathBuf::from(s))
                .collect()
        }
    }
}

/// Parse a colon-separated list of paths into a vector of PathBufs
/// Filters out empty paths and trims whitespace
fn parse_path_list(path_str: &str) -> Vec<PathBuf> {
    path_str
        .split(':')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
        .collect()
}

/// Searches for a script by name in the given directories
/// Handles both with and without .sh extension
/// Returns the first matching file found
fn find_script(dirs: &[PathBuf], name: &str) -> Option<PathBuf> {
    // Build list of possible filenames to search for
    let candidates = build_script_candidates(name);
    
    // Search through directories and candidates
    dirs.iter()
        .filter(|dir| dir.is_dir())
        .flat_map(|dir| candidates.iter().map(move |candidate| dir.join(candidate)))
        .find(|path| is_valid_script_file(path))
}

/// Build list of candidate filenames for a given script name
fn build_script_candidates(name: &str) -> Vec<String> {
    if name.ends_with(".sh") {
        vec![name.to_string()]
    } else {
        vec![format!("{}.sh", name), name.to_string()]
    }
}

/// Check if a path points to a valid script file
fn is_valid_script_file(path: &Path) -> bool {
    path.is_file() && {
        // Additional check: ensure the file is readable
        match fs::metadata(path) {
            Ok(metadata) => {
                // On Unix, check if file has read permission
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let mode = metadata.permissions().mode();
                    (mode & 0o444) != 0  // Check if any read bit is set
                }
                #[cfg(not(unix))]
                {
                    true  // On non-Unix, just check if it's a file
                }
            }
            Err(_) => false,
        }
    }
}

/// Lists all .sh files in the given directories
/// Returns a sorted list of module/tool names (without .sh extension)
/// Collects modules from ALL directories, not just the first one found
fn list_modules(dirs: &[PathBuf]) -> HardnResult<Vec<String>> {
    use std::collections::HashSet;
    
    // Use HashSet for automatic deduplication
    let mut module_names: HashSet<String> = HashSet::new();
    
    // Process each directory
    for dir in dirs {
        // Skip non-existent directories
        if !dir.is_dir() {
            continue;
        }
        
        // Read directory and handle errors gracefully
        let entries = match fs::read_dir(dir) {
            Ok(entries) => entries,
            Err(e) => {
                // Log warning but continue with other directories
                eprintln!("Warning: Could not read directory {}: {}", dir.display(), e);
                continue;
            }
        };
        
        // Process each entry in the directory
        for entry in entries {
            // Extract the module name if valid
            if let Some(module_name) = extract_module_name(entry) {
                module_names.insert(module_name);
            }
        }
    }
    
    // Convert to sorted vector
    let mut sorted_names: Vec<String> = module_names.into_iter().collect();
    sorted_names.sort();
    
    Ok(sorted_names)
}

/// Helper function to extract module name from a directory entry
/// Returns Some(name) if the entry is a valid .sh file, None otherwise
fn extract_module_name(entry: io::Result<fs::DirEntry>) -> Option<String> {
    // Handle potential I/O error for the entry
    let entry = entry.ok()?;
    let path = entry.path();
    
    // Check if it's a .sh file
    let extension = path.extension()?.to_str()?;
    if extension != "sh" {
        return None;
    }
    
    // Extract the filename without extension
    let stem = path.file_stem()?.to_str()?;
    
    // Additional validation: ensure it's a regular file (not directory or symlink to directory)
    match entry.metadata() {
        Ok(metadata) if metadata.is_file() => Some(stem.to_string()),
        _ => None,
    }
}

fn join_paths(dirs: &[PathBuf]) -> String {
    dirs.iter()
        .map(|p| p.display().to_string())
        .collect::<Vec<_>>()
        .join(":")
}

/* ---------- Script Runner ---------- */

/// Executes a shell script with proper environment setup
/// Returns the exit status for proper error propagation
fn run_script(path: &Path, kind: &str, module_dirs: &[PathBuf]) -> HardnResult<ExitStatus> {
    // Validate the script exists and is readable
    if !path.exists() {
        return Err(HardnError::ExecutionFailed(
            format!("Script does not exist: {}", path.display())
        ));
    }
    
    // Security: Ensure the path is absolute to prevent directory traversal
    let absolute_path = path.canonicalize()
        .map_err(|e| HardnError::ExecutionFailed(
            format!("Failed to resolve path {}: {}", path.display(), e)
        ))?;
    
    log_message(LogLevel::Info, &format!("Executing {}: {}", kind, absolute_path.display()));

    // Set required environment variables for shell modules
    let module_dir = module_dirs.first()
        .map(|d| d.display().to_string())
        .unwrap_or_else(|| DEFAULT_MODULE_DIRS[0].to_string());
    
    let status = Command::new("bash")
        .arg(&absolute_path)
        .env("HARDN_MODULES_DIR", &module_dir)
        .env("HARDN_LOG_DIR", DEFAULT_LOG_DIR)
        .env("HARDN_LIB_DIR", DEFAULT_LIB_DIR)
        .env("HARDN_VERSION", VERSION)
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .map_err(|e| HardnError::ExecutionFailed(
            format!("Failed to execute {}: {}", kind, e)
        ))?;

    if status.success() {
        log_message(LogLevel::Pass, &format!("{} completed successfully", kind));
    } else {
        log_message(LogLevel::Warning, &format!("{} exited with status: {}", kind, status));
    }
    
    Ok(status)
}

/* ---------- Command Handlers ---------- */

/// Handles the "run-module" command
/// Returns proper exit code based on execution result
fn handle_run_module(module_dirs: &[PathBuf], module_name: &str) -> i32 {
    match find_script(module_dirs, module_name) {
        Some(path) => {
            match run_script(&path, "module", module_dirs) {
                Ok(status) => {
                    if status.success() {
                        EXIT_SUCCESS
                    } else {
                        status.code().unwrap_or(EXIT_FAILURE)
                    }
                }
                Err(e) => {
                    log_message(LogLevel::Error, &format!("Failed to run module: {}", e));
                    EXIT_FAILURE
                }
            }
        }
        None => {
            log_message(
                LogLevel::Error,
                &format!(
                    "Module script '{}' not found in: {}",
                    module_name,
                    join_paths(module_dirs)
                ),
            );
            EXIT_FAILURE
        }
    }
}

/// Handles the "run-tool" command
/// Returns proper exit code based on execution result
fn handle_run_tool(tool_dirs: &[PathBuf], tool_name: &str, module_dirs: &[PathBuf]) -> i32 {
    match find_script(tool_dirs, tool_name) {
        Some(path) => {
            match run_script(&path, "tool", module_dirs) {
                Ok(status) => {
                    if status.success() {
                        EXIT_SUCCESS
                    } else {
                        status.code().unwrap_or(EXIT_FAILURE)
                    }
                }
                Err(e) => {
                    log_message(LogLevel::Error, &format!("Failed to run tool: {}", e));
                    EXIT_FAILURE
                }
            }
        }
        None => {
            log_message(
                LogLevel::Error,
                &format!(
                    "Tool script '{}' not found in: {}",
                    tool_name,
                    join_paths(tool_dirs)
                ),
            );
            EXIT_FAILURE
        }
    }
}

/// Handles the default behavior when no command is specified
/// Returns exit code based on overall success
fn handle_run_all_modules(module_dirs: &[PathBuf]) -> i32 {
    let (version, codename) = detect_debian_version();
    log_message(LogLevel::Pass, &format!("Detected: Debian {} ({})", version, codename));
    log_message(LogLevel::Info, "No arguments provided. Discovering and running all modules...");

    let modules = match list_modules(module_dirs) {
        Ok(mods) => mods,
        Err(e) => {
            log_message(LogLevel::Error, &format!("Failed to list modules: {}", e));
            return EXIT_FAILURE;
        }
    };

    if modules.is_empty() {
        log_message(
            LogLevel::Warning,
            &format!("No modules found. Checked: {}", join_paths(module_dirs)),
        );
        return EXIT_SUCCESS; // Not an error if no modules exist
    }

    let mut failed = 0;
    let mut succeeded = 0;
    
    for module_name in &modules {
        if let Some(path) = find_script(module_dirs, module_name) {
            match run_script(&path, "module", module_dirs) {
                Ok(status) if status.success() => succeeded += 1,
                Ok(_) => failed += 1,
                Err(e) => {
                    log_message(LogLevel::Error, &format!("Failed to run {}: {}", module_name, e));
                    failed += 1;
                }
            }
        }
    }

    log_message(
        LogLevel::Info, 
        &format!("Completed: {} succeeded, {} failed out of {} modules", 
                 succeeded, failed, modules.len())
    );
    
    if failed > 0 {
        EXIT_FAILURE
    } else {
        EXIT_SUCCESS
    }
}

/* ---------- Main Entry Point ---------- */

/// Main entry point for HARDN
fn main() {

    let args: Vec<String> = env::args().collect();
    let module_dirs = env_or_defaults("HARDN_MODULE_PATH", DEFAULT_MODULE_DIRS);
    let tool_dirs = env_or_defaults("HARDN_TOOL_PATH", DEFAULT_TOOL_DIRS);

    let exit_code = match args.len() {
        1 => handle_run_all_modules(&module_dirs),
        2 => {
            match args[1].as_str() {
                "-v" | "--version" | "version" => {
                    println!("{} version {}", APP_NAME, VERSION);
                    EXIT_SUCCESS
                }
                "-h" | "--help" | "help" => {
                    print_help();
                    EXIT_SUCCESS
                }
                "-a" | "--about" | "about" => {
                    print_about();
                    EXIT_SUCCESS
                }
                "-s" | "--status" | "status" => {
                    show_status();
                    EXIT_SUCCESS
                }
                "--list-modules" | "list-modules" => {
                    print_modules();
                    EXIT_SUCCESS
                }
                "--list-tools" | "list-tools" => {
                    print_tools();
                    EXIT_SUCCESS
                }
                "--security-report" | "security-report" => {
                    generate_security_report();
                    EXIT_SUCCESS
                }
                "--run-all-modules" | "run-all-modules" => {
                    run_all_modules()
                }
                "--run-all-tools" | "run-all-tools" => {
                    run_all_tools()
                }
                "--run-everything" | "run-everything" => {
                    run_everything()
                }
                "--sandbox-on" | "sandbox-on" => {
                    sandbox_on()
                }
                "--sandbox-off" | "sandbox-off" => {
                    sandbox_off()
                }
                "--service-enable" | "service-enable" => {
                    manage_service("enable")
                }
                "--service-start" | "service-start" => {
                    manage_service("start")
                }
                "--service-status" | "service-status" => {
                    show_status();
                    EXIT_SUCCESS
                }
                "--enable-selinux" | "enable-selinux" => {
                    enable_selinux()
                }
                _ => {
                    log_message(LogLevel::Error, &format!("Unknown option: {}", args[1]));
                    print_help();
                    EXIT_USAGE
                }
            }
        }
        3 => {
            match args[1].as_str() {
                "service" => manage_service(&args[2]),
                "run-module" => handle_run_module(&module_dirs, &args[2]),
                "run-tool" => handle_run_tool(&tool_dirs, &args[2], &module_dirs),
                _ => {
                    log_message(LogLevel::Error, &format!("Unknown command: {}", args[1]));
                    print_help();
                    EXIT_USAGE
                }
            }
        }
        _ => {
            log_message(LogLevel::Error, "Invalid number of arguments");
            print_help();
            EXIT_USAGE
        }
    };
    
    process::exit(exit_code);
}
