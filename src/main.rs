// Refactored main.rs - now using modular architecture

mod cli;
mod core;
mod display;
mod execution;
mod services;
mod utils;
mod legion;

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{self, Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};
use ctrlc;
use crate::core::config::*;
use crate::core::types::*;
use crate::utils::{LogLevel, log_message, detect_debian_version};
use crate::utils::{env_or_defaults, find_script, list_modules, join_paths};
use crate::display::banner::print_banner;
use crate::execution::run_script;

// Core types and constants are now imported from modules

/* ---------- Banner and Help ---------- */

// print_banner is now in display::banner module

/// Print list of available modules
fn print_modules() {
    let module_dirs = env_or_defaults("HARDN_MODULE_PATH", DEFAULT_MODULE_DIRS);
    
    println!("\n════════════════════════════════════════");
    println!("  AVAILABLE MODULES");
    println!("══════════════════════════════════════════\n");
    
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
    println!("══════════════════════════════════════════\n");
    
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

/// Interactive tool selection and execution
fn select_and_run_tool() {
    let tool_dirs = env_or_defaults("HARDN_TOOL_PATH", DEFAULT_TOOL_DIRS);
    let module_dirs = env_or_defaults("HARDN_MODULE_PATH", DEFAULT_MODULE_DIRS);
    
    println!("\n\x1b[1;36m▶ SELECT A SECURITY TOOL TO RUN:\x1b[0m\n");
    
    match list_modules(&tool_dirs) {
        Ok(tools) if !tools.is_empty() => {
            // Display tools with numbers
            for (i, tool) in tools.iter().enumerate() {
                println!("  {}) {}", i + 1, tool);
            }
            println!("  0) Cancel and return\n");
            
            print!("Enter your selection [0-{}]: ", tools.len());
            use std::io::{self, Write};
            io::stdout().flush().unwrap();
            
            let mut input = String::new();
            io::stdin().read_line(&mut input).unwrap_or_default();
            
            match input.trim().parse::<usize>() {
                Ok(0) => {
                    println!("\nReturning to recommendations...");
                }
                Ok(choice) if choice > 0 && choice <= tools.len() => {
                    let tool_name = &tools[choice - 1];
                    println!("\nRunning tool: {}...\n", tool_name);
                    handle_run_tool(&tool_dirs, tool_name, &module_dirs);
                }
                _ => {
                    println!("\nInvalid selection. Returning to recommendations...");
                }
            }
        }
        Ok(_) => {
            println!("  No tools found.");
        }
        Err(e) => {
            println!("  Error listing tools: {}", e);
        }
    }
}

/// Interactive module selection and execution
fn select_and_run_module() {
    let module_dirs = env_or_defaults("HARDN_MODULE_PATH", DEFAULT_MODULE_DIRS);
    
    println!("\n\x1b[1;36m▶ SELECT A HARDENING MODULE TO RUN:\x1b[0m\n");
    
    match list_modules(&module_dirs) {
        Ok(modules) if !modules.is_empty() => {
            // Display modules with numbers
            for (i, module) in modules.iter().enumerate() {
                println!("  {}) {}", i + 1, module);
            }
            println!("  0) Cancel and return\n");
            
            print!("Enter your selection [0-{}]: ", modules.len());
            use std::io::{self, Write};
            io::stdout().flush().unwrap();
            
            let mut input = String::new();
            io::stdin().read_line(&mut input).unwrap_or_default();
            
            match input.trim().parse::<usize>() {
                Ok(0) => {
                    println!("\nReturning to recommendations...");
                }
                Ok(choice) if choice > 0 && choice <= modules.len() => {
                    let module_name = &modules[choice - 1];
                    println!("\nRunning module: {}...\n", module_name);
                    handle_run_module(&module_dirs, module_name);
                }
                _ => {
                    println!("\nInvalid selection. Returning to recommendations...");
                }
            }
        }
        Ok(_) => {
            println!("  No modules found.");
        }
        Err(e) => {
            println!("  Error listing modules: {}", e);
        }
    }
}

/// Display Lynis audit report
fn display_lynis_report() {
    println!("\n\x1b[1;36m▶ LYNIS AUDIT REPORT:\x1b[0m\n");
    
    let report_path = "/var/log/lynis/lynis-report-concise.log";
    let alt_report_path = "/var/log/lynis/report.log";
    
    // Try the concise report first, then the regular report
    let path_to_use = if Path::new(report_path).exists() {
        report_path
    } else if Path::new(alt_report_path).exists() {
        alt_report_path
    } else {
        println!("  \x1b[33m⚠\x1b[0m No Lynis report found.");
        println!("  Run 'sudo lynis audit system' to generate a report.");
        println!("\nPress Enter to continue...");
        let mut input = String::new();
        let _ = std::io::stdin().read_line(&mut input);
        return;
    };
    
    // Display the report using less or cat
    let output = Command::new("less")
        .arg(path_to_use)
        .status()
        .or_else(|_| {
            // Fallback to cat if less is not available
            Command::new("cat")
                .arg(path_to_use)
                .status()
        });
    
    match output {
        Ok(_) => {
            println!("\n\x1b[1;32m✓\x1b[0m Report displayed successfully.");
        }
        Err(e) => {
            println!("  \x1b[31m✗\x1b[0m Error displaying report: {}", e);
            println!("  You can manually view the report at: {}", path_to_use);
        }
    }
    
    println!("\nPress Enter to continue...");
    let mut input = String::new();
    let _ = std::io::stdin().read_line(&mut input);
}

/// Generate and display comprehensive security report
fn generate_security_report() {
    println!("\n╔═══════════════════════════════════════════════════════════════════════════════╗");
    println!("║                     HARDN COMPREHENSIVE SECURITY REPORT                     ║");
    println!("╚═════════════════════════════════════════════════════════════════════════════════╝\n");
    
    // Track scoring components
    let tool_score: f64;
    let module_score: f64;
    let mut lynis_score: f64;
    
    // 1. Check active security tools (40% of total score)
    println!("\x1b[1;36m▶ SECURITY TOOLS ASSESSMENT (40% weight):\x1b[0m");
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
    tool_score = (tool_points / max_tool_points * 40.0).min(40.0);
    
    println!("\n  Active: {}/{}, Enabled: {}/{}", active_tools, tools.len(), enabled_tools, tools.len());
    println!("  \x1b[1;33mTool Score: {:.1}/40\x1b[0m\n", tool_score);
    
    // 2. Check executed modules (20% of total score)
    println!("\x1b[1;36m▶ MODULE EXECUTION STATUS (20% weight):\x1b[0m");
    
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
    let module_points = (executed_modules.len() as f64 / expected_modules as f64 * 10.0) + 
                       (active_services as f64 / hardn_services.len() as f64 * 10.0);
    module_score = module_points.min(20.0);
    
    println!("\n  Module logs found: {}/{}", executed_modules.len(), expected_modules);
    println!("  HARDN services active: {}/{}", active_services, hardn_services.len());
    println!("  \x1b[1;33mModule Score: {:.1}/20\x1b[0m\n", module_score);
    
    // 3. Run Lynis audit and get score (40% of total score)
    println!("\x1b[1;36m▶ LYNIS SECURITY AUDIT (40% weight):\x1b[0m");
    println!("  Running Lynis security audit (this may take a moment)...\n");
    
    // Create log directory if it doesn't exist
    let _ = fs::create_dir_all("/var/log/lynis");
    
    // Initialize lynis_score
    lynis_score = 0.0;
    
    // Run Lynis audit
    let lynis_output = Command::new("lynis")
        .args(&["audit", "system", "--quick", "--quiet", "--no-colors"])
        .output();
    
    match lynis_output {
        Ok(output) => {
            let output_str = String::from_utf8_lossy(&output.stdout);
            
            // Extract hardening index using regex-like pattern matching
            let hardening_index = output_str
                .lines()
                .find(|line| line.contains("Hardening index"))
                .and_then(|line| {
                    // Extract number between brackets
                    line.find('[')
                        .and_then(|start| {
                            line[start+1..].find(']')
                                .and_then(|end| {
                                    line[start+1..start+1+end].trim().parse::<f64>().ok()
                                })
                        })
                })
                .unwrap_or(0.0);
            
            // If we couldn't get it from quick scan, try checking the log file
            let hardening_index = if hardening_index == 0.0 {
                // Try to get from existing log file using ripgrep if available
                Command::new("rg")
                    .args(&["-i", "Hardening index", "/var/log/lynis/hardn-audit.log"])
                    .output()
                    .ok()
                    .and_then(|rg_output| {
                        String::from_utf8_lossy(&rg_output.stdout)
                            .lines()
                            .find(|line| line.contains("Hardening index"))
                            .and_then(|line| {
                                // Extract the number
                                line.split('[').nth(1)
                                    .and_then(|s| s.split(']').next())
                                    .and_then(|s| s.trim().parse::<f64>().ok())
                            })
                    })
                    .unwrap_or(hardening_index)
            } else {
                hardening_index
            };
            
            // Lynis score is 40% of its hardening index
            lynis_score = (hardening_index / 100.0 * 40.0).min(40.0);
            
            if hardening_index > 0.0 {
                println!("  \x1b[32m✓\x1b[0m Lynis audit completed successfully");
                println!("  Hardening Index: \x1b[1;33m{}\x1b[0m/100", hardening_index);
                
                // Show security status indicator
                let status_msg = match hardening_index as i32 {
                    0..=49 => "\x1b[1;31mCRITICAL - Immediate attention required\x1b[0m",
                    50..=64 => "\x1b[1;31mPOOR - Significant improvements needed\x1b[0m",
                    65..=74 => "\x1b[1;33mFAIR - Some improvements recommended\x1b[0m",
                    75..=84 => "\x1b[1;32mGOOD - Minor improvements possible\x1b[0m",
                    85..=94 => "\x1b[1;32mEXCELLENT - Well hardened system\x1b[0m",
                    _ => "\x1b[1;32mOUTSTANDING - Exceptional security posture\x1b[0m",
                };
                println!("  Security Level: {}", status_msg);
            } else {
                println!("  \x1b[33m⚠\x1b[0m Could not determine Lynis hardening index");
                println!("  Run 'sudo lynis audit system' for detailed results");
            }
        }
        Err(_) => {
            println!("  \x1b[31m✗\x1b[0m Lynis not installed or not accessible");
            println!("  Install with: sudo apt install lynis");
        }
    }
    
    println!("  \x1b[1;33mLynis Score: {:.1}/40\x1b[0m\n", lynis_score);
    
    // Calculate total score
    let total_score = tool_score + module_score + lynis_score;
    
    // Display final report
    println!("╔════════════════════════════════════════════════════════════════════════════════╗");
    println!("║                              SECURITY SCORE SUMMARY                            ║");
    println!("╠════════════════════════════════════════════════════════════════════════════════╣");
    println!("║  Component                │    Score    │ Weight │         Status              ║");
    println!("╠───────────────────────────┼─────────────┼────────┼─────────────────────────────╣");
    
    let tool_status = if tool_score >= 30.0 { "✓" } else if tool_score >= 20.0 { "●" } else { "✗" };
    let module_status = if module_score >= 15.0 { "✓" } else if module_score >= 10.0 { "●" } else { "✗" };
    let lynis_status = if lynis_score >= 30.0 { "✓" } else if lynis_score >= 20.0 { "●" } else { "✗" };
    
    println!("║  Security Tools           │  {:>6.1}/40  │  40%   │             {}               ║", tool_score, tool_status);
    println!("║  Module Execution         │  {:>6.1}/20  │  20%   │             {}               ║", module_score, module_status);
    println!("║  Lynis Audit              │  {:>6.1}/40  │  40%   │             {}               ║", lynis_score, lynis_status);
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
    
    // Format the total score line with proper padding
    let score_text = format!("TOTAL SCORE: {:.1}/100  Grade: {}", total_score, grade);
    // Calculate padding - total width is 80 characters inside the box borders
    // Subtracting 2 for initial spaces leaves 78 characters for content
    let padding = 78 - score_text.len();
    
    println!("║  {}{}{}{:width$}║", 
             grade_color, score_text, "\x1b[0m", " ", width = padding);
    println!("╚════════════════════════════════════════════════════════════════════════════════╝");
    
    // Recommendations
    println!("\n\x1b[1;36m▶ RECOMMENDATIONS:\x1b[0m\n");
    
    let mut has_recommendations = false;
    
    if tool_score < 30.0 {
        println!("  • Enable more security tools to improve protection");
        println!("    Run: sudo hardn run-tool <tool-name>\n");
        has_recommendations = true;
    }
    
    if module_score < 15.0 {
        println!("  • Execute HARDN modules for system hardening");
        println!("    Run: sudo hardn run-module hardening\n");
        has_recommendations = true;
    }
    
    if lynis_score < 30.0 {
        println!("  • Review Lynis audit findings and apply recommendations");
        println!("    View: /var/log/lynis/lynis-report-concise.log\n");
        has_recommendations = true;
    }
    
    if total_score >= 80.0 {
        println!("  \x1b[1;32m✓ System security posture is strong. Maintain regular audits.\x1b[0m\n");
    }
    
    // Add interactive menu if there are recommendations
    if has_recommendations {
        println!(" What would you like to do?\n");
        
        if tool_score < 30.0 {
            println!("  a) Enable more security tools?");
        }
        if module_score < 15.0 {
            println!("  b) Execute HARDN modules for system hardening?");
        }
        if lynis_score < 30.0 {
            println!("  c) Review Lynis audit findings and apply recommendations?");
        }
        println!("  d) None, return to the main menu.");
        
        print!("\nEnter your selection: ");
        use std::io::{self, Write};
        io::stdout().flush().unwrap();
        
        let mut input = String::new();
        io::stdin().read_line(&mut input).unwrap_or_default();
        let choice = input.trim().to_lowercase();
        
        match choice.as_str() {
            "a" if tool_score < 30.0 => {
                println!("\n═══════════════════════════════════════════════════════════════════════════════\n");
                // Run tool selection menu
                select_and_run_tool();
            },
            "b" if module_score < 15.0 => {
                println!("\n═══════════════════════════════════════════════════════════════════════════════\n");
                // Run module selection menu  
                select_and_run_module();
            },
            "c" if lynis_score < 30.0 => {
                println!("\n═══════════════════════════════════════════════════════════════════════════════\n");
                // Display Lynis report
                display_lynis_report();
            },
            "d" => {
                println!("\n═══════════════════════════════════════════════════════════════════════════════\n");
                // Return to main menu
            },
            _ => {
                println!("\nInvalid selection. Returning to main menu.");
                println!("\n═══════════════════════════════════════════════════════════════════════════════\n");
            }
        }
    } else {
        println!("\n═══════════════════════════════════════════════════════════════════════════════\n");
    }
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
fn run_everything() -> i32 {
    println!("\n╔═══════════════════════════════════════╗");
    println!("║     RUNNING ALL MODULES AND TOOLS       ║");
    println!("╚═════════════════════════════════════════╝\n");
    
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
    println!("║           EXECUTION SUMMARY             ║");
    println!("╚═════════════════════════════════════════╝\n");
    
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
    println!("║         ENABLING SANDBOX MODE           ║");
    println!("╚═════════════════════════════════════════╝\n");
    
    log_message(LogLevel::Warning, "⚠️  SANDBOX MODE - Manual activation only");
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
        .args(&["addr", "show"])
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
            .args(&["-P", chain, policy])
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
            .args(&rule)
            .status();
    }
    
    // Disable all network interfaces except loopback
    let interfaces_output = Command::new("ip")
        .args(&["link", "show"])
        .output();
    
    if let Ok(output) = interfaces_output {
        let output_str = String::from_utf8_lossy(&output.stdout);
        for line in output_str.lines() {
            if let Some(iface_name) = line.split(':').nth(1) {
                let iface = iface_name.trim();
                if iface != "lo" && !iface.starts_with("@") {
                    match Command::new("ip")
                        .args(&["link", "set", iface, "down"])
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
    println!("\n╔══════════════════════════════════════╗");
    println!("║           ⚠️  DANGER ZONE ⚠️           ║");
    println!("║         SELINUX ACTIVATION             ║");
    println!("╚════════════════════════════════════════╝\n");
    
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
    println!("║        DISABLING SANDBOX MODE           ║");
    println!("╚═════════════════════════════════════════╝\n");
    
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
                let _ = Command::new("iptables").args(&["-P", "INPUT", "ACCEPT"]).status();
                let _ = Command::new("iptables").args(&["-P", "OUTPUT", "ACCEPT"]).status();
                let _ = Command::new("iptables").args(&["-P", "FORWARD", "ACCEPT"]).status();
                let _ = Command::new("iptables").args(&["-F"]).status();
            }
        }
    } else {
        // No backup found, set permissive defaults
        log_message(LogLevel::Warning, "No firewall backup found, setting default policies");
        let _ = Command::new("iptables").args(&["-P", "INPUT", "ACCEPT"]).status();
        let _ = Command::new("iptables").args(&["-P", "OUTPUT", "ACCEPT"]).status();
        let _ = Command::new("iptables").args(&["-P", "FORWARD", "DROP"]).status();
        let _ = Command::new("iptables").args(&["-F"]).status();
    }
    
    // Re-enable network interfaces
    let interfaces_output = Command::new("ip")
        .args(&["link", "show"])
        .output();
    
    if let Ok(output) = interfaces_output {
        let output_str = String::from_utf8_lossy(&output.stdout);
        for line in output_str.lines() {
            if let Some(iface_name) = line.split(':').nth(1) {
                let iface = iface_name.trim();
                if iface != "lo" && !iface.starts_with("@") && !iface.starts_with("veth") {
                    match Command::new("ip")
                        .args(&["link", "set", iface, "up"])
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
        .args(&["restart", "networking"])
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

// ToolCategory is now in core::types

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
            vec!["ufw", "fail2ban", "suricata", "openssh", "iptables"],
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

// ServiceStatus and SecurityToolInfo are now in core::types

/// Get list of security tools to monitor
fn get_security_tools() -> Vec<SecurityToolInfo> {
    vec![
        SecurityToolInfo {
            name: "AIDE",
            service_name: "aide",
            process_name: "aide",
            description: "Advanced Intrusion Detection Environment - File integrity monitoring",
        },
        SecurityToolInfo {
            name: "AppArmor",
            service_name: "apparmor",
            process_name: "apparmor",
            description: "Mandatory Access Control system for applications",
        },
        SecurityToolInfo {
            name: "Fail2Ban",
            service_name: "fail2ban",
            process_name: "fail2ban-server",
            description: "Intrusion prevention - Bans IPs with multiple auth failures",
        },
        SecurityToolInfo {
            name: "UFW",
            service_name: "ufw",
            process_name: "ufw",
            description: "Uncomplicated Firewall - Network traffic filtering",
        },
        SecurityToolInfo {
            name: "Auditd",
            service_name: "auditd",
            process_name: "auditd",
            description: "Linux Audit Framework - Security event logging",
        },
        SecurityToolInfo {
            name: "RKHunter",
            service_name: "rkhunter",
            process_name: "rkhunter",
            description: "Rootkit Hunter - Scans for rootkits and exploits",
        },
        SecurityToolInfo {
            name: "ClamAV",
            service_name: "clamav-daemon",
            process_name: "clamd",
            description: "Antivirus engine for detecting trojans and malware",
        },
        SecurityToolInfo {
            name: "Suricata",
            service_name: "suricata",
            process_name: "suricata",
            description: "Network IDS/IPS and security monitoring",
        },
        SecurityToolInfo {
            name: "OSSEC",
            service_name: "ossec",
            process_name: "ossec-analysisd",
            description: "Host-based Intrusion Detection System",
        },
        SecurityToolInfo {
            name: "Lynis",
            service_name: "lynis",
            process_name: "lynis",
            description: "Security auditing and compliance testing",
        },
    ]
}

/// Check if a systemd service is active
fn check_service_status(service_name: &str) -> ServiceStatus {
    // Check if service is active
    let active_output = match Command::new("systemctl")
        .args(&["is-active", service_name])
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
        .args(&["is-enabled", service_name])
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
            .args(&["show", service_name, "--property=MainPID"])
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
        .args(&["aux"])
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

/// Get simple service status (active/inactive/failed)
fn get_service_status_simple(service: &str) -> String {
    let output = Command::new("systemctl")
        .args(&["is-active", service])
        .output();
    
    match output {
        Ok(result) => {
            let status = String::from_utf8_lossy(&result.stdout).trim().to_string();
            if result.status.success() {
                status
            } else {
                "inactive".to_string()
            }
        }
        Err(_) => "unknown".to_string()
    }
}

/// Get detailed service status information
fn get_service_status_detailed(service: &str) -> String {
    let output = Command::new("systemctl")
        .args(&["status", service, "--no-pager", "-l"])
        .output();
    
    match output {
        Ok(result) => {
            if result.status.success() {
                String::from_utf8_lossy(&result.stdout).to_string()
            } else {
                format!("{}: Failed to get status - {}", service, String::from_utf8_lossy(&result.stderr))
            }
        }
        Err(e) => format!("{}: Error - {}", service, e)
    }
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
        .args(&["enable", &format!("{}.service", service_name)])
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
        .args(&["disable", &format!("{}.service", service_name)])
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
        .args(&["start", &format!("{}.service", service_name)])
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
        .args(&["stop", &format!("{}.service", service_name)])
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
        .args(&["restart", &format!("{}.service", service_name)])
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

/// Interactive service monitor with log viewing capabilities
fn interactive_service_monitor() -> i32 {
    use std::io::{self, Write};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::thread;
    use std::time::Duration;

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();

    // Set up Ctrl+C handler
    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
        print!("\n\rReturning to main menu... ");
        io::stdout().flush().unwrap();
        thread::sleep(Duration::from_millis(500));
        println!("Done.");
    }).expect("Error setting Ctrl+C handler");

    let services = vec![
        "hardn.service",
        "hardn-api.service",
        "legion-daemon.service",
        "hardn-monitor.service"
    ];

    loop {
        if !running.load(Ordering::SeqCst) {
            break;
        }

        println!("\n╔══════════════════════════════════════════════════════════════╗");
        println!("║                  HARDN SERVICE MONITOR                      ║");
        println!("╚══════════════════════════════════════════════════════════════╝");
        println!();
        println!("Available services:");

        for (i, service) in services.iter().enumerate() {
            let status = get_service_status_simple(service);
            let status_color = match status.as_str() {
                "active" => "\x1b[32m",
                "inactive" => "\x1b[31m",
                "failed" => "\x1b[31m",
                _ => "\x1b[33m"
            };
            println!("  {}. {} - {}{} \x1b[0m", i + 1, service, status_color, status);
        }

        println!();
        println!("Options:");
        println!("  1-{}: View logs for specific service", services.len());
        println!("  a: View logs for ALL services");
        println!("  s: Show service status");
        println!("  r: Restart all services");
        println!("  q: Quit to main menu");
        println!();
        print!("Choice: ");
        io::stdout().flush().unwrap();

        let mut input = String::new();
        if io::stdin().read_line(&mut input).is_err() {
            break;
        }

        let choice = input.trim();

        match choice {
            "q" | "Q" => break,
            "s" | "S" => {
                println!("\n═══ SERVICE STATUS ═══");
                for service in &services {
                    let status = get_service_status_detailed(service);
                    println!("{}", status);
                }
                println!("\nPress Enter to continue...");
                let mut dummy = String::new();
                let _ = io::stdin().read_line(&mut dummy);
            }
            "r" | "R" => {
                println!("\n═══ RESTARTING SERVICES ═══");
                for service in &services {
                    print!("Restarting {}... ", service);
                    io::stdout().flush().unwrap();

                    let output = Command::new("systemctl")
                        .args(&["restart", service])
                        .output();

                    match output {
                        Ok(result) if result.status.success() => {
                            println!("\x1b[32m✓ Done\x1b[0m");
                        }
                        _ => {
                            println!("\x1b[31m✗ Failed\x1b[0m");
                        }
                    }
                }
                println!("\nPress Enter to continue...");
                let mut dummy = String::new();
                let _ = io::stdin().read_line(&mut dummy);
            }
            "a" | "A" => {
                println!("\n═══ ALL SERVICE LOGS ═══");
                println!("Showing logs for all HARDN services (press Ctrl+C to return to menu)");
                println!();

                let running_clone = running.clone();
                thread::spawn(move || {
                    let mut child = Command::new("journalctl")
                        .args(&["-f", "-u", "hardn", "-u", "hardn-api", "-u", "legion-daemon", "-u", "hardn-monitor", "--since", "today"])
                        .stdout(Stdio::piped())
                        .spawn()
                        .expect("Failed to start journalctl");

                    if let Some(stdout) = child.stdout.take() {
                        use std::io::{BufRead, BufReader};
                        let reader = BufReader::new(stdout);

                        for line in reader.lines() {
                            if !running_clone.load(Ordering::SeqCst) {
                                let _ = child.kill();
                                break;
                            }

                            if let Ok(line) = line {
                                println!("{}", line);
                            }
                        }
                    }
                });

                // Wait for Ctrl+C
                while running.load(Ordering::SeqCst) {
                    thread::sleep(Duration::from_millis(100));
                }
            }
            choice => {
                // Try to parse as service number
                if let Ok(index) = choice.parse::<usize>() {
                    if index >= 1 && index <= services.len() {
                        let service = services[index - 1];
                        println!("\n═══ LOGS FOR {} ═══", service);
                        println!("Press Ctrl+C to return to menu");
                        println!();

                        let running_clone = running.clone();
                        let service_name = service.to_string();

                        thread::spawn(move || {
                            let mut child = Command::new("journalctl")
                                .args(&["-f", "-u", &service_name, "--since", "today"])
                                .stdout(Stdio::piped())
                                .spawn()
                                .expect("Failed to start journalctl");

                            if let Some(stdout) = child.stdout.take() {
                                use std::io::{BufRead, BufReader};
                                let reader = BufReader::new(stdout);

                                for line in reader.lines() {
                                    if !running_clone.load(Ordering::SeqCst) {
                                        let _ = child.kill();
                                        break;
                                    }

                                    if let Ok(line) = line {
                                        println!("{}", line);
                                    }
                                }
                            }
                        });

                        // Wait for Ctrl+C
                        while running.load(Ordering::SeqCst) {
                            thread::sleep(Duration::from_millis(100));
                        }
                    } else {
                        println!("Invalid service number. Please try again.");
                        thread::sleep(Duration::from_secs(2));
                    }
                } else {
                    println!("Invalid choice. Please try again.");
                    thread::sleep(Duration::from_secs(2));
                }
            }
        }
    }

    EXIT_SUCCESS
}
/// Format and display log entries in a user-friendly way
fn display_formatted_logs(logs: &str) {
    let mut formatted_entries = Vec::new();
    let mut current_entry = String::new();
    
    for line in logs.lines() {
        // Skip empty lines
        if line.trim().is_empty() {
            continue;
        }
        
        // Check if this is a new log entry (starts with timestamp or contains service name with PID)
        let is_new_entry = line.contains("hardn[") || 
                          line.contains("legion[") || 
                          line.contains("hardn-monitor[") ||
                          line.starts_with("2025-") || // Year prefix for timestamps
                          line.starts_with("2024-");
        
        if is_new_entry {
            // Process previous entry if exists
            if !current_entry.is_empty() {
                formatted_entries.push(format_log_entry(&current_entry));
            }
            current_entry = line.to_string();
        } else {
            // Continuation of previous entry
            if !current_entry.is_empty() {
                current_entry.push(' ');
                current_entry.push_str(line.trim());
            }
        }
    }
    
    // Process the last entry
    if !current_entry.is_empty() {
        formatted_entries.push(format_log_entry(&current_entry));
    }
    
    // Display formatted entries
    if formatted_entries.is_empty() {
        println!("  No recent activity to display");
    } else {
        // Limit to 5 most recent entries for cleaner display
        let display_count = formatted_entries.len().min(5);
        let start_index = formatted_entries.len().saturating_sub(5);
        
        for entry in &formatted_entries[start_index..] {
            println!("  {}", entry);
        }
        
        if formatted_entries.len() > 5 {
            println!("  ... ({} more entries)", formatted_entries.len() - 5);
        }
    }
}

/// Format a single log entry for display
fn format_log_entry(entry: &str) -> String {
    let mut formatted = String::new();
    
    // Extract timestamp (looking for ISO format: YYYY-MM-DDTHH:MM:SS)
    if let Some(t_start) = entry.find("202") {
        if let Some(t_end) = entry[t_start..].find(' ').or_else(|| entry[t_start..].find('.')).or_else(|| entry[t_start..].find('-')) {
            let timestamp = &entry[t_start..t_start + t_end];
            if let Some(t_idx) = timestamp.find('T') {
                let time = &timestamp[t_idx+1..timestamp.len().min(t_idx+9)];
                formatted.push_str(&format!("[{}] ", time));
            }
        }
    }
    
    // Extract service name
    for service in &["hardn", "legion", "hardn-monitor"] {
        if let Some(idx) = entry.find(&format!("{}[", service)) {
            formatted.push_str(&format!("{}: ", service.to_uppercase()));
            break;
        }
    }
    
    // Handle different types of log entries
    if entry.contains("{\"timestamp\"") || entry.contains("{\"event") {
        // JSON log entry - summarize it
        if entry.contains("suricata") && entry.contains("stats") {
            formatted.push_str("Suricata statistics update");
        } else if entry.contains("\"event_type\":\"stats\"") {
            formatted.push_str("Network statistics logged");
        } else if entry.contains("NETWORK ALERT") {
            formatted.push_str("🌐 Network monitoring alert");
        } else if entry.contains("event_type") {
            // Try to extract event type
            if let Some(et_idx) = entry.find("\"event_type\":") {
                let after_et = &entry[et_idx + 14..];
                if let Some(quote_idx) = after_et.find('\"') {
                    if let Some(end_quote) = after_et[quote_idx+1..].find('\"') {
                        let event_type = &after_et[quote_idx+1..quote_idx+1+end_quote];
                        formatted.push_str(&format!("Event: {}", event_type));
                    }
                }
            } else {
                formatted.push_str("System event logged");
            }
        } else {
            formatted.push_str("System monitoring data");
        }
    } else {
        // Regular log entry - extract the message
        let message = if let Some(colon_idx) = entry.rfind(": ") {
            &entry[colon_idx + 2..]
        } else if let Some(bracket_idx) = entry.rfind("] ") {
            &entry[bracket_idx + 2..]
        } else {
            entry
        };
        
        // Clean up emojis and format
        let clean_message = message
            .replace("🌐", "[NET]")
            .replace("⚠️", "[WARN]")
            .replace("🔒", "[SEC]")
            .replace("🚨", "[ALERT]")
            .replace("✓", "[OK]")
            .replace("✗", "[FAIL]")
            .replace("📊", "[STATS]")
            .replace("🛡️", "[SHIELD]");
        
        // Truncate very long messages
        if clean_message.len() > 80 {
            formatted.push_str(&format!("{}...", &clean_message[..77]));
        } else {
            formatted.push_str(&clean_message);
        }
    }
    
    // If we couldn't format it nicely, just truncate the original
    if formatted.trim().is_empty() || formatted.len() < 10 {
        if entry.len() > 100 {
            format!("{}...", &entry[..97])
        } else {
            entry.to_string()
        }
    } else {
        formatted
    }
}

/// Display comprehensive status of HARDN
fn show_status() {
    println!("\n═══════════════════════════════════════════════════════════════════════════════");
    println!("                          HARDN SYSTEM STATUS");
    println!("═════════════════════════════════════════════════════════════════════════════════\n");
    
    // System Information
    let (version, codename) = detect_debian_version();
    println!("SYSTEM INFORMATION:");
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
    println!("HARDN SERVICES:");
    let hardn_services = vec!["hardn", "legion-daemon"];
    let mut any_active = false;
    
    for service_name in &hardn_services {
        let status = check_service_status(service_name);
        let status_icon = if status.active { "[OK]" } else { "[DOWN]" };
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
        println!("  [WARNING] No HARDN services are currently active");
    }
    println!();
    
    // Check Security Tools
    println!("SECURITY TOOLS STATUS:");
    let tools = get_security_tools();
    let mut active_tools = 0;
    
    for tool in &tools {
        let status = check_service_status(tool.service_name);
        if status.active {
            active_tools += 1;
            print!("  \x1b[32m[OK] {:<12}\x1b[0m", tool.name);
            if let Some(pid) = status.pid {
                print!(" [PID: {}]", pid);
            }
            println!(" - {}", tool.description);
        }
    }
    
    if active_tools == 0 {
        println!("  [WARNING] No security tools are currently active");
    } else {
        println!("\n  Total active security tools: {}/{}", active_tools, tools.len());
    }
    println!();
    
    // Check Running HARDN Processes
    println!("RUNNING HARDN PROCESSES:");
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
    println!("RECENT ACTIVITY:");
    if Path::new(DEFAULT_LOG_DIR).exists() {
        let log_output = Command::new("journalctl")
            .args(&[
                "-u", "hardn.service",
                "-u", "legion-daemon.service",
                "-u", "hardn-monitor.service",
                "-n", "10",
                "--no-pager",
                "-o", "short-iso",
            ])
            .output();
        
        match log_output {
            Ok(output) if output.status.success() => {
                let logs = String::from_utf8_lossy(&output.stdout);
                if logs.trim().is_empty() {
                    println!("  No recent log entries");
                } else {
                    display_formatted_logs(&logs);
                }
            }
            _ => {
                // Fallback to file-based logs if journalctl fails
                let file_output = Command::new("tail")
                    .args(&["-n", "10", &format!("{}/hardn.log", DEFAULT_LOG_DIR)])
                    .output();
                
                match file_output {
                    Ok(output) if output.status.success() => {
                        let logs = String::from_utf8_lossy(&output.stdout);
                        if logs.trim().is_empty() {
                            println!("  No recent log entries");
                        } else {
                            display_formatted_logs(&logs);
                        }
                    }
                    _ => {
                        println!("  Log file not accessible or empty");
                    }
                }
            }
        }
    } else {
        println!("  Log directory not found");
    }
    
    println!("\n═══════════════════════════════════════════════════════════════════════════════\n");
}

fn print_help() {
    println!(
        r#"
{} - Linux Security Hardening and Extended Detection & Response Toolkit

═══════════════════════════════════════════════════════════════════════════════

QUICK START:
  sudo hardn-service-manager  Launch the interactive service manager (recommended)
  sudo make hardn             Alternative: Build and launch service manager
  sudo hardn services          Launch service monitoring interface

NAVIGATION:
  • Use arrow keys or numbers to navigate menus
  • Press 'q' to quit from any menu
  • Press Ctrl+C in log views to return to menus (doesn't exit app)

GETTING HELP:
  sudo hardn --help        Show this help menu
  sudo hardn --about       Show detailed information about HARDN
  sudo hardn --status      Show current service status

TROUBLESHOOTING ERRORS:
  • Check service status: sudo hardn --status
  • View service logs: sudo journalctl -u hardn.service -f
  • Reinstall if needed: sudo make build && sudo make hardn
  • Check permissions: ensure running with sudo

AVAILABLE COMMANDS:
  status                   Show service status
  service <action>         Manage services (enable/disable/start/stop/restart)
  run-module <name>        Run specific hardening module
  run-tool <name>          Run specific security tool
  legion <options>         LEGION security monitoring
  --security-report        Generate comprehensive security assessment

═══════════════════════════════════════════════════════════════════════════════
"#,
        APP_NAME
    );
}

/* ---------- Utility Functions ---------- */

// Utility functions are now in the utils module

/* ---------- Path Helpers ---------- */

// Path helper functions are now in utils::paths module

/* ---------- Script Runner ---------- */

// run_script is now in execution::runner module

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

/* ---------- Main Entry Point ---------- */

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
                    "services" => {
                        interactive_service_monitor()
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
        }
    };    process::exit(exit_code);
}
