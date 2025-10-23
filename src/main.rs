// Refactored main.rs - now using modular architecture

mod cli;
mod core;
mod display;
mod execution;
mod legion;
mod services;
mod utils;

use crate::core::config::*;
use crate::core::types::*;
use crate::display::banner::print_banner;
use crate::execution::run_script;
use crate::utils::{detect_debian_version, log_message, LogLevel};
use crate::utils::{env_or_defaults, find_script, join_paths, list_modules};
use chrono::{DateTime, Utc};
use comfy_table::{presets::UTF8_FULL, Table};
use glob::glob;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap};
use std::env;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{self, Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

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

/// Tool status types for enhanced checking
#[derive(Debug, PartialEq, Clone)]
enum ToolStatusType {
    Active,       // Tool is running/active
    Enabled,      // Tool is enabled but not running
    Installed,    // Tool is installed but not enabled
    NotInstalled, // Tool is not installed
}

#[derive(Debug, Clone)]
struct ToolStatusDetail {
    state: ToolStatusType,
    enabled: bool,
    installed: bool,
}

fn tool_detail(state: ToolStatusType, enabled: bool, installed: bool) -> ToolStatusDetail {
    ToolStatusDetail {
        state,
        enabled,
        installed,
    }
}

/// Check tool status with enhanced methods for different tool types
fn get_tool_status_detail(tool_name: &str) -> ToolStatusDetail {
    match tool_name {
        "AIDE" => {
            // AIDE runs via timer, not as a service
            if Command::new("systemctl")
                .args(["is-active", "dailyaidecheck.timer"])
                .output()
                .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "active")
                .unwrap_or(false)
            {
                tool_detail(ToolStatusType::Active, true, true)
            } else if Command::new("systemctl")
                .args(["is-enabled", "dailyaidecheck.timer"])
                .output()
                .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "enabled")
                .unwrap_or(false)
            {
                tool_detail(ToolStatusType::Enabled, true, true)
            } else if Path::new("/usr/bin/aide").exists() || Path::new("/usr/sbin/aide").exists() {
                tool_detail(ToolStatusType::Installed, false, true)
            } else {
                tool_detail(ToolStatusType::NotInstalled, false, false)
            }
        }
        "Lynis" => {
            // Lynis may run via timer or on-demand
            if Command::new("systemctl")
                .args(["is-active", "lynis.timer"])
                .output()
                .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "active")
                .unwrap_or(false)
            {
                tool_detail(ToolStatusType::Active, true, true)
            } else if Command::new("systemctl")
                .args(["is-enabled", "lynis.timer"])
                .output()
                .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "enabled")
                .unwrap_or(false)
            {
                tool_detail(ToolStatusType::Enabled, true, true)
            } else if Command::new("which")
                .arg("lynis")
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false)
            {
                tool_detail(ToolStatusType::Installed, false, true)
            } else {
                tool_detail(ToolStatusType::NotInstalled, false, false)
            }
        }
        "UFW" => {
            // UFW is a firewall, check if it's active
            let output = Command::new("ufw").arg("status").output();

            match output {
                Ok(o) => {
                    let status = String::from_utf8_lossy(&o.stdout);
                    if status.contains("Status: active") {
                        tool_detail(ToolStatusType::Active, true, true)
                    } else if status.contains("Status: inactive") {
                        tool_detail(ToolStatusType::Installed, false, true)
                    } else {
                        tool_detail(ToolStatusType::NotInstalled, false, false)
                    }
                }
                Err(_) => tool_detail(ToolStatusType::NotInstalled, false, false),
            }
        }
        "RKHunter" => {
            // RKHunter is typically run on-demand or via cron
            if Command::new("which")
                .arg("rkhunter")
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false)
            {
                // Check if database is initialized
                if Path::new("/var/lib/rkhunter/db/rkhunter.dat").exists() {
                    tool_detail(ToolStatusType::Active, true, true)
                } else {
                    // If installed, treat as enabled when cron job exists
                    let cron_enabled = Path::new("/etc/cron.daily/rkhunter").exists()
                        || Path::new("/etc/cron.d/rkhunter").exists();
                    if cron_enabled {
                        tool_detail(ToolStatusType::Enabled, true, true)
                    } else {
                        tool_detail(ToolStatusType::Installed, false, true)
                    }
                }
            } else {
                tool_detail(ToolStatusType::NotInstalled, false, false)
            }
        }
        "OSSEC" => {
            // OSSEC may not use systemd
            if Command::new("pgrep")
                .args(["-f", "ossec-analysisd"])
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false)
            {
                tool_detail(ToolStatusType::Active, true, true)
            } else if Path::new("/var/ossec").exists() {
                let enabled = Command::new("systemctl")
                    .args(["is-enabled", "ossec"])
                    .output()
                    .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "enabled")
                    .unwrap_or(false);
                if enabled {
                    tool_detail(ToolStatusType::Enabled, true, true)
                } else {
                    tool_detail(ToolStatusType::Installed, false, true)
                }
            } else {
                tool_detail(ToolStatusType::NotInstalled, false, false)
            }
        }
        "Firejail" => {
            // Firejail is a sandboxing tool, check if installed and profiles exist
            if Command::new("which")
                .arg("firejail")
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false)
            {
                // Check if HARDN profiles exist
                if Path::new("/etc/firejail/hardn-service-manager.profile").exists() {
                    tool_detail(ToolStatusType::Active, true, true)
                } else {
                    tool_detail(ToolStatusType::Installed, false, true)
                }
            } else {
                tool_detail(ToolStatusType::NotInstalled, false, false)
            }
        }
        "SELinux" => {
            // SELinux is a kernel security module
            let output = Command::new("sestatus").output();
            match output {
                Ok(o) => {
                    let status = String::from_utf8_lossy(&o.stdout);
                    if status.contains("SELinux status:\tenabled")
                        && status.contains("Current mode:\tenforcing")
                    {
                        tool_detail(ToolStatusType::Active, true, true)
                    } else if status.contains("SELinux status:\tenabled") {
                        tool_detail(ToolStatusType::Enabled, true, true)
                    } else {
                        tool_detail(ToolStatusType::NotInstalled, false, false)
                    }
                }
                Err(_) => tool_detail(ToolStatusType::NotInstalled, false, false),
            }
        }
        "AppArmor" | "Fail2Ban" | "Auditd" | "ClamAV" | "Grafana" | "Legion" | "Suricata" => {
            // These are standard systemd services
            let service_name = match tool_name {
                "AppArmor" => "apparmor",
                "Fail2Ban" => "fail2ban",
                "Auditd" => "auditd",
                "ClamAV" => "clamav-daemon",
                "Grafana" => "grafana-server",
                "Legion" => "legion-daemon",
                "Suricata" => "suricata",
                _ => return tool_detail(ToolStatusType::NotInstalled, false, false),
            };

            let status = check_service_status(service_name);
            let is_enabled = status.enabled || status.active;
            let mut is_installed = status.active || status.enabled;
            if !is_installed {
                is_installed = Command::new("dpkg")
                    .args(["-l", service_name])
                    .output()
                    .map(|o| {
                        String::from_utf8_lossy(&o.stdout)
                            .lines()
                            .any(|line| line.starts_with("ii") && line.contains(service_name))
                    })
                    .unwrap_or(false);
            }

            let state = if status.active {
                ToolStatusType::Active
            } else if is_enabled {
                ToolStatusType::Enabled
            } else if is_installed {
                ToolStatusType::Installed
            } else {
                ToolStatusType::NotInstalled
            };

            tool_detail(state, is_enabled, is_installed)
        }
        _ => tool_detail(ToolStatusType::NotInstalled, false, false),
    }
}

/// Display HARDN audit report
fn display_hardn_audit_report(report_path_hint: Option<String>) {
    println!("\n\x1b[1;36m▶ HARDN AUDIT REPORT:\x1b[0m\n");

    let default_path = "/var/log/hardn/hardn_audit_report.json";
    let resolved_path = report_path_hint
        .filter(|path| Path::new(path).exists())
        .unwrap_or_else(|| default_path.to_string());

    if !Path::new(&resolved_path).exists() {
        println!(
            "  \x1b[33m⚠\x1b[0m No hardn-audit report found at {}.",
            resolved_path
        );
        println!("  Run 'sudo hardn audit' or rerun the compliance report to generate one.");
        println!("\nPress Enter to continue...");
        let mut input = String::new();
        let _ = std::io::stdin().read_line(&mut input);
        return;
    }

    let viewer = Command::new("less")
        .arg(&resolved_path)
        .status()
        .or_else(|_| Command::new("cat").arg(&resolved_path).status());

    match viewer {
        Ok(_) => {
            println!("\n\x1b[1;32m✓\x1b[0m Report displayed successfully.");
        }
        Err(e) => {
            println!("  \x1b[31m✗\x1b[0m Error displaying report: {}", e);
            println!("  You can manually view the report at: {}", resolved_path);
        }
    }

    println!("\nPress Enter to continue...");
    let mut input = String::new();
    let _ = std::io::stdin().read_line(&mut input);
}

const HARDN_MONITOR_STATE_PATH: &str = "/var/lib/hardn/monitor/hardn_summary.json";

#[derive(Serialize)]
struct HardnMonitorSnapshot {
    timestamp: DateTime<Utc>,
    total_score: f64,
    grade: String,
    component_scores: HardnScoreBreakdown,
    tool_summary: HardnToolSummary,
    module_logs: Vec<String>,
    services: Vec<HardnServiceStatusEntry>,
    hardn_processes: Vec<String>,
    recommendations: Vec<String>,
    status_note: Option<String>,
    audit: Option<HardnAuditSummary>,
}

#[derive(Serialize)]
struct HardnScoreBreakdown {
    tools: f64,
    modules: f64,
    audit: f64,
}

#[derive(Serialize)]
struct HardnToolSummary {
    active: u32,
    enabled: u32,
    installed: u32,
    missing: u32,
    total: u32,
    statuses: Vec<HardnToolStatusEntry>,
}

#[derive(Serialize)]
struct HardnToolStatusEntry {
    name: String,
    state: String,
}

#[derive(Serialize)]
struct HardnServiceStatusEntry {
    name: String,
    active: bool,
    enabled: bool,
    pid: Option<u32>,
}

#[derive(Serialize, Clone)]
struct HardnAuditRuleResult {
    id: String,
    title: String,
    category: String,
    severity: String,
    status: String,
    evidence: String,
}

#[derive(Serialize, Clone)]
struct HardnAuditSummary {
    report_version: String,
    generated_at: String,
    counts: HashMap<String, u32>,
    rules: Vec<HardnAuditRuleResult>,
    report_path: Option<String>,
    stderr: Option<String>,
}

#[derive(Deserialize)]
struct HardnAuditRaw {
    report_version: String,
    generated_at: String,
    rules: Vec<HardnAuditRawRule>,
}

#[derive(Deserialize)]
struct HardnAuditRawRule {
    id: String,
    title: String,
    category: String,
    severity: String,
    status: String,
    evidence: String,
}

impl HardnMonitorSnapshot {
    fn new(
        scores: HardnScoreBreakdown,
        total_score: f64,
        grade: &str,
        context: HardnSnapshotContext,
    ) -> Self {
        let sanitized_scores = HardnScoreBreakdown {
            tools: sanitize_score(scores.tools),
            modules: sanitize_score(scores.modules),
            audit: sanitize_score(scores.audit),
        };

        Self {
            timestamp: Utc::now(),
            total_score: sanitize_score(total_score),
            grade: grade.to_string(),
            component_scores: sanitized_scores,
            tool_summary: context.tool_summary,
            module_logs: context.module_logs,
            services: context.services,
            hardn_processes: context.hardn_processes,
            recommendations: context.recommendations,
            status_note: context.status_note,
            audit: context.audit,
        }
    }
}

struct HardnSnapshotContext {
    tool_summary: HardnToolSummary,
    module_logs: Vec<String>,
    services: Vec<HardnServiceStatusEntry>,
    hardn_processes: Vec<String>,
    recommendations: Vec<String>,
    status_note: Option<String>,
    audit: Option<HardnAuditSummary>,
}

fn sanitize_score(value: f64) -> f64 {
    if value.is_finite() {
        value
    } else {
        0.0
    }
}

fn persist_hardn_monitor_snapshot(
    snapshot: &HardnMonitorSnapshot,
) -> Result<(), Box<dyn std::error::Error>> {
    let path = Path::new(HARDN_MONITOR_STATE_PATH);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let temp_path = path
        .parent()
        .map(|dir| dir.join("hardn_summary.json.tmp"))
        .unwrap_or_else(|| Path::new("hardn_summary.json.tmp").to_path_buf());

    let data = serde_json::to_vec_pretty(snapshot)?;
    fs::write(&temp_path, &data)?;
    let _ = fs::set_permissions(&temp_path, fs::Permissions::from_mode(0o640));
    fs::rename(&temp_path, path)?;

    Ok(())
}

/// Generate and display comprehensive security report
fn generate_security_report() {
    println!("\n╔═══════════════════════════════════════════════════════════════════════════════╗");
    println!("║                     HARDN COMPREHENSIVE SECURITY REPORT                     ║");
    println!(
        "╚═════════════════════════════════════════════════════════════════════════════════╝\n"
    );

    // Track scoring components
    let mut audit_score: f64 = 0.0;
    let mut recommendations: Vec<String> = Vec::new();
    let mut status_note: Option<String> = None;
    let mut tool_status_entries: Vec<HardnToolStatusEntry> = Vec::new();
    let mut audit_summary: Option<HardnAuditSummary> = None;
    let mut has_recommendations = false;

    // 1. Check active security tools (40% of total score)
    println!("\x1b[1;36m▶ SECURITY TOOLS ASSESSMENT (40% weight):\x1b[0m");
    let mut active_tools: u32 = 0;
    let mut enabled_tools: u32 = 0;
    let mut installed_tools: u32 = 0;
    let mut tool_points: f64 = 0.0;
    let total_tools: u32 = 13;

    // Check each tool with appropriate method
    let tool_statuses = vec![
        ("AIDE", get_tool_status_detail("AIDE")),
        ("AppArmor", get_tool_status_detail("AppArmor")),
        ("Fail2Ban", get_tool_status_detail("Fail2Ban")),
        ("UFW", get_tool_status_detail("UFW")),
        ("Auditd", get_tool_status_detail("Auditd")),
        ("ClamAV", get_tool_status_detail("ClamAV")),
        ("Firejail", get_tool_status_detail("Firejail")),
        ("Grafana", get_tool_status_detail("Grafana")),
        ("Legion", get_tool_status_detail("Legion")),
        ("OSSEC", get_tool_status_detail("OSSEC")),
        ("SELinux", get_tool_status_detail("SELinux")),
        ("Suricata", get_tool_status_detail("Suricata")),
        ("Lynis", get_tool_status_detail("Lynis")),
    ];

    for (tool_name, detail) in &tool_statuses {
        match detail.state {
            ToolStatusType::Active => {
                active_tools += 1;
                tool_points += 1.0;
                print!("  \x1b[32m✓\x1b[0m {:<12}", tool_name);
                println!(" [ACTIVE]");
                tool_status_entries.push(HardnToolStatusEntry {
                    name: (*tool_name).to_string(),
                    state: "active".to_string(),
                });
            }
            ToolStatusType::Enabled => {
                tool_points += 0.5;
                print!("  \x1b[33m●\x1b[0m {:<12}", tool_name);
                println!(" [ENABLED]");
                tool_status_entries.push(HardnToolStatusEntry {
                    name: (*tool_name).to_string(),
                    state: "enabled".to_string(),
                });
            }
            ToolStatusType::Installed => {
                tool_points += 0.25;
                print!("  \x1b[34m○\x1b[0m {:<12}", tool_name);
                println!(" [INSTALLED]");
                tool_status_entries.push(HardnToolStatusEntry {
                    name: (*tool_name).to_string(),
                    state: "installed".to_string(),
                });
            }
            ToolStatusType::NotInstalled => {
                print!("  \x1b[31m✗\x1b[0m {:<12}", tool_name);
                println!(" [DISABLED]");
                tool_status_entries.push(HardnToolStatusEntry {
                    name: (*tool_name).to_string(),
                    state: "missing".to_string(),
                });
            }
        }

        if detail.enabled {
            enabled_tools += 1;
        }
        if detail.installed {
            installed_tools += 1;
        }
    }

    // Calculate tool score: active tools get full points, enabled get half, installed get quarter
    if installed_tools > total_tools {
        installed_tools = total_tools;
    }
    let missing_tools = total_tools.saturating_sub(installed_tools);
    let max_tool_points = total_tools as f64;
    let tool_score = (tool_points / max_tool_points * 40.0).min(40.0);

    println!(
        "\n  Active: {}/{}, Enabled: {}/{}, Installed: {}/{}",
        active_tools, total_tools, enabled_tools, total_tools, installed_tools, total_tools
    );
    println!("  \x1b[1;33mTool Score: {:.1}/40\x1b[0m\n", tool_score);

    // 2. Check executed modules (20% of total score)
    println!("\x1b[1;36m▶ MODULE EXECUTION STATUS (20% weight):\x1b[0m");

    // Check if log directory exists and analyze module execution
    let mut module_log_set: BTreeSet<String> = BTreeSet::new();
    if Path::new(DEFAULT_LOG_DIR).exists() {
        let log_root = Path::new(DEFAULT_LOG_DIR);
        let patterns = vec![
            format!("{}/**/*.log", DEFAULT_LOG_DIR),
            format!("{}/**/*.out", DEFAULT_LOG_DIR),
        ];

        for pattern in patterns {
            if let Ok(entries) = glob(&pattern) {
                for entry in entries.flatten() {
                    if entry.is_file() {
                        let relative = entry
                            .strip_prefix(log_root)
                            .map(|p| p.display().to_string())
                            .unwrap_or_else(|_| entry.display().to_string());
                        module_log_set.insert(relative.trim_start_matches('/').to_string());
                    }
                }
            }
        }

        if module_log_set.is_empty() {
            let expected_logs = vec![
                "hardn.log",
                "hardn-tools.log",
                "hardn-modules.log",
                "hardening.log",
                "audit.log",
            ];

            for log_file in &expected_logs {
                let log_path = log_root.join(log_file);
                if log_path.exists() {
                    module_log_set.insert(log_file.to_string());
                }
            }
        }
    }

    let executed_modules: Vec<String> = module_log_set.into_iter().collect();

    if executed_modules.is_empty() {
        println!(
            "  \x1b[33m⚠\x1b[0m No module logs found in {}",
            DEFAULT_LOG_DIR
        );
    } else {
        for log in &executed_modules {
            println!("  \x1b[32m✓\x1b[0m {}", log);
        }
    }

    // Check HARDN services
    let hardn_services = vec![
        "hardn.service",
        "legion-daemon.service",
        "hardn-monitor.service",
    ];
    let mut active_services = 0;
    let mut service_status_entries: Vec<HardnServiceStatusEntry> = Vec::new();
    for service in &hardn_services {
        let status = check_service_status(service);
        if status.active || status.enabled {
            active_services += 1;
        }
        service_status_entries.push(HardnServiceStatusEntry {
            name: service.to_string(),
            active: status.active,
            enabled: status.enabled,
            pid: status.pid,
        });
    }

    // Calculate module score based on logs and services
    let expected_modules = 5; // Expected number of module logs
    let module_points = (executed_modules.len() as f64 / expected_modules as f64 * 10.0)
        + (active_services as f64 / hardn_services.len() as f64 * 10.0);
    let module_score = module_points.min(20.0);

    println!(
        "\n  Module logs found: {}/{}",
        executed_modules.len(),
        expected_modules
    );
    println!(
        "  HARDN services active: {}/{}",
        active_services,
        hardn_services.len()
    );
    println!("  \x1b[1;33mModule Score: {:.1}/20\x1b[0m\n", module_score);

    // 3. Run HARDN audit and get score (40% of total score)
    println!("\x1b[1;36m▶ HARDN AUDIT (40% weight):\x1b[0m");

    match run_hardn_audit() {
        Ok(summary) => {
            let total_rules = summary.rules.len();
            println!("  Rules evaluated: {}", total_rules);

            if !summary.counts.is_empty() {
                let mut status_counts: Vec<_> = summary.counts.iter().collect();
                status_counts.sort_by(|a, b| a.0.cmp(b.0));
                let counts_line = status_counts
                    .into_iter()
                    .map(|(status, count)| format!("{}: {}", status.to_uppercase(), count))
                    .collect::<Vec<_>>()
                    .join(", ");
                println!("  Status counts: {}", counts_line);
            }

            if let Some(path) = summary.report_path.as_deref() {
                println!("  Report saved to: {}", path);
            }

            if let Some(stderr) = summary.stderr.as_ref() {
                if !stderr.is_empty() {
                    println!("  \x1b[33m⚠ hardn-audit warnings:\x1b[0m {}", stderr);
                }
            }

            let mut weighted_sum = 0.0;
            let mut failing_rules: Vec<HardnAuditRuleResult> = Vec::new();
            let pass_rules: Vec<&HardnAuditRuleResult> = summary
                .rules
                .iter()
                .filter(|rule| rule.status == "pass")
                .collect();

            for rule in &summary.rules {
                let status = rule.status.as_str();
                let weight = match status {
                    "pass" => 1.0,
                    "not_applicable" => 1.0,
                    "not_implemented" => 0.4,
                    "fail" | "error" => 0.0,
                    _ => 0.5,
                };
                weighted_sum += weight;
                if matches!(status, "fail" | "error") {
                    failing_rules.push(rule.clone());
                }
            }

            if total_rules > 0 {
                audit_score = (weighted_sum / total_rules as f64 * 40.0).min(40.0);
            } else {
                println!("  \x1b[33m⚠\x1b[0m Audit returned no rules");
            }

            println!("  \x1b[1;33mAudit Score: {:.1}/40\x1b[0m", audit_score);

            if !pass_rules.is_empty() {
                println!(
                    "\n  Passing rules logged: {} (showing first 10)",
                    pass_rules.len()
                );
                for rule in pass_rules.iter().take(10) {
                    println!("    • {} [{}]", rule.title, rule.severity);
                }
                if pass_rules.len() > 10 {
                    println!("    ... {} additional passing rules", pass_rules.len() - 10);
                }
                println!();
            }

            if failing_rules.is_empty() {
                println!("  \x1b[32m✓ All audit checks passed\x1b[0m\n");
            } else {
                println!(
                    "  \x1b[33m⚠ Issues detected in {} rule(s)\x1b[0m",
                    failing_rules.len()
                );

                let mut table = Table::new();
                table.load_preset(UTF8_FULL);
                table.set_header(vec!["Rule", "Severity", "Status", "Evidence"]);
                for rule in &failing_rules {
                    let mut evidence = rule.evidence.clone();
                    if evidence.len() > 96 {
                        evidence.truncate(93);
                        evidence.push_str("...");
                    }
                    table.add_row(vec![
                        rule.title.clone(),
                        rule.severity.clone(),
                        rule.status.to_uppercase(),
                        evidence,
                    ]);
                }
                println!("{}\n", table);

                for rule in failing_rules.iter().take(5) {
                    let rec = format!(
                        "Address audit finding for '{}' (status: {})",
                        rule.title, rule.status
                    );
                    recommendations.push(rec);
                    has_recommendations = true;
                }
                if failing_rules.len() > 5 {
                    let rec = format!(
                        "Review remaining {} audit findings in the detailed report",
                        failing_rules.len() - 5
                    );
                    recommendations.push(rec);
                    has_recommendations = true;
                }
                if let Some(path) = summary.report_path.as_deref() {
                    let rec = format!("Review detailed audit report at {}", path);
                    recommendations.push(rec);
                    has_recommendations = true;
                }
            }
            audit_summary = Some(summary.clone());
        }
        Err(err) => {
            println!("  \x1b[31m✗ Failed to run hardn-audit:\x1b[0m {}", err);
            recommendations.push(
                "Install and configure the hardn-audit binary to enable compliance evaluation"
                    .to_string(),
            );
            has_recommendations = true;
        }
    }

    // Calculate total score
    let total_score = tool_score + module_score + audit_score;

    // Display final report
    println!("╔════════════════════════════════════════════════════════════════════════════════╗");
    println!("║                              SECURITY SCORE SUMMARY                            ║");
    println!("╠════════════════════════════════════════════════════════════════════════════════╣");
    println!("║  Component                │    Score    │ Weight │         Status              ║");
    println!("╠───────────────────────────┼─────────────┼────────┼─────────────────────────────╣");

    let tool_status = if tool_score >= 30.0 {
        "✓"
    } else if tool_score >= 20.0 {
        "●"
    } else {
        "✗"
    };
    let module_status = if module_score >= 15.0 {
        "✓"
    } else if module_score >= 10.0 {
        "●"
    } else {
        "✗"
    };
    let audit_status = if audit_score >= 30.0 {
        "✓"
    } else if audit_score >= 20.0 {
        "●"
    } else {
        "✗"
    };

    println!(
        "║  Security Tools           │  {:>6.1}/40  │  40%   │             {}               ║",
        tool_score, tool_status
    );
    println!(
        "║  Module Execution         │  {:>6.1}/20  │  20%   │             {}               ║",
        module_score, module_status
    );
    println!(
        "║  HARDN Audit              │  {:>6.1}/40  │  40%   │             {}               ║",
        audit_score, audit_status
    );
    println!("╠═══════════════════════════╧═════════════╧════════╧═════════════════════════════╣");

    // Determine overall grade and color
    let (grade, grade_color) = match total_score as i32 {
        0..=49 => ("F", "\x1b[1;31m"),  // Red
        50..=59 => ("D", "\x1b[1;31m"), // Red
        60..=69 => ("C", "\x1b[1;33m"), // Yellow
        70..=79 => ("B", "\x1b[1;33m"), // Yellow
        80..=89 => ("A", "\x1b[1;32m"), // Green
        _ => ("A+", "\x1b[1;32m"),      // Green
    };

    // Format the total score line with proper padding
    let score_text = format!("TOTAL SCORE: {:.1}/100  Grade: {}", total_score, grade);
    // Calculate padding - total width is 80 characters inside the box borders
    // Subtracting 2 for initial spaces leaves 78 characters for content
    let padding = 78 - score_text.len();

    println!(
        "║  {}{}\x1b[0m{:width$}║",
        grade_color,
        score_text,
        " ",
        width = padding
    );
    println!("╚════════════════════════════════════════════════════════════════════════════════╝");

    // Recommendations
    println!("\n\x1b[1;36m▶ RECOMMENDATIONS:\x1b[0m\n");

    if tool_score < 30.0 {
        let rec = "Enable more security tools to improve protection (Run: sudo hardn run-tool <tool-name>)";
        recommendations.push(rec.to_string());
        println!("  • Enable more security tools to improve protection");
        println!("    Run: sudo hardn run-tool <tool-name>\n");
        has_recommendations = true;
    }

    if module_score < 15.0 {
        let rec =
            "Execute HARDN modules for system hardening (Run: sudo hardn run-module hardening)";
        recommendations.push(rec.to_string());
        println!("  • Execute HARDN modules for system hardening");
        println!("    Run: sudo hardn run-module hardening\n");
        has_recommendations = true;
    }

    if audit_score < 30.0 {
        let report_hint = audit_summary
            .as_ref()
            .and_then(|summary| summary.report_path.clone())
            .unwrap_or_else(|| "/var/log/hardn/hardn_audit_report.json".to_string());
        let rec = format!(
            "Review hardn-audit findings and apply recommendations (View: {})",
            report_hint
        );
        recommendations.push(rec.clone());
        println!("  • Review hardn-audit findings and apply recommendations");
        println!("    View: {}\n", report_hint);
        has_recommendations = true;
    }

    if total_score >= 80.0 {
        let note = "System security posture is strong. Maintain regular audits.".to_string();
        status_note = Some(note.clone());
        println!("  \x1b[1;32m✓ {}\x1b[0m\n", note);
    }

    let tool_summary_snapshot = HardnToolSummary {
        active: active_tools,
        enabled: enabled_tools,
        installed: installed_tools,
        missing: missing_tools,
        total: total_tools,
        statuses: tool_status_entries,
    };

    let module_logs_snapshot = executed_modules.clone();
    let hardn_processes_snapshot = check_hardn_processes();
    let recommendations_snapshot = recommendations.clone();
    let status_note_snapshot = status_note.clone();

    let component_scores = HardnScoreBreakdown {
        tools: tool_score,
        modules: module_score,
        audit: audit_score,
    };

    let snapshot_context = HardnSnapshotContext {
        tool_summary: tool_summary_snapshot,
        module_logs: module_logs_snapshot,
        services: service_status_entries,
        hardn_processes: hardn_processes_snapshot,
        recommendations: recommendations_snapshot,
        status_note: status_note_snapshot,
        audit: audit_summary.clone(),
    };

    let snapshot = HardnMonitorSnapshot::new(
        component_scores,
        total_score,
        grade,
        snapshot_context,
    );

    if let Err(e) = persist_hardn_monitor_snapshot(&snapshot) {
        eprintln!("Failed to persist HARDN monitor snapshot: {}", e);
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
        if audit_score < 30.0 {
            println!("  c) Review hardn-audit findings and apply recommendations?");
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
            }
            "b" if module_score < 15.0 => {
                println!("\n═══════════════════════════════════════════════════════════════════════════════\n");
                // Run module selection menu
                select_and_run_module();
            }
            "c" if audit_score < 30.0 => {
                println!("\n═══════════════════════════════════════════════════════════════════════════════\n");
                // Display HARDN audit report
                display_hardn_audit_report(
                    audit_summary
                        .as_ref()
                        .and_then(|summary| summary.report_path.clone()),
                );
            }
            "d" => {
                println!("\n═══════════════════════════════════════════════════════════════════════════════\n");
                // Return to main menu
            }
            _ => {
                println!("\nInvalid selection. Returning to main menu.");
                println!("\n═══════════════════════════════════════════════════════════════════════════════\n");
            }
        }
    } else {
        println!(
            "\n═══════════════════════════════════════════════════════════════════════════════\n"
        );
    }
}

fn run_hardn_audit() -> Result<HardnAuditSummary, String> {
    let binary_path = find_hardn_audit_binary()
        .ok_or_else(|| "hardn-audit binary not found in PATH or HARDN directories".to_string())?;

    let output = Command::new(&binary_path)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .map_err(|e| format!("failed to execute {}: {}", binary_path.display(), e))?;

    if !output.status.success() {
        return Err(format!(
            "{} exited with status {}",
            binary_path.display(),
            output.status
        ));
    }

    let stdout_str = String::from_utf8(output.stdout.clone())
        .map_err(|e| format!("invalid UTF-8 from hardn-audit: {}", e))?;

    let raw: HardnAuditRaw = serde_json::from_str(&stdout_str)
        .map_err(|e| format!("failed to parse hardn-audit JSON: {}", e))?;

    let HardnAuditRaw {
        report_version,
        generated_at,
        rules: raw_rules,
    } = raw;

    let mut counts: HashMap<String, u32> = HashMap::new();
    let mut rules: Vec<HardnAuditRuleResult> = Vec::with_capacity(raw_rules.len());

    for raw_rule in raw_rules {
        let status = raw_rule.status.to_lowercase();
        *counts.entry(status.clone()).or_insert(0) += 1;
        rules.push(HardnAuditRuleResult {
            id: raw_rule.id,
            title: raw_rule.title,
            category: raw_rule.category,
            severity: raw_rule.severity,
            status,
            evidence: raw_rule.evidence,
        });
    }

    let report_path = persist_hardn_audit_report(stdout_str.as_bytes());

    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    let stderr = if stderr.is_empty() {
        None
    } else {
        Some(stderr)
    };

    Ok(HardnAuditSummary {
        report_version,
        generated_at,
        counts,
        rules,
        report_path,
        stderr,
    })
}

fn persist_hardn_audit_report(contents: &[u8]) -> Option<String> {
    let report_dir = Path::new(DEFAULT_LOG_DIR);
    if fs::create_dir_all(report_dir).is_err() {
        return None;
    }

    let report_path = report_dir.join("hardn_audit_report.json");
    if fs::write(&report_path, contents).is_ok() {
        let _ = fs::set_permissions(&report_path, fs::Permissions::from_mode(0o640));
        Some(report_path.display().to_string())
    } else {
        None
    }
}

fn find_hardn_audit_binary() -> Option<PathBuf> {
    if let Some(path) = env::var_os("HARDN_AUDIT_BIN") {
        let candidate = PathBuf::from(path);
        if is_executable(&candidate) {
            return Some(candidate);
        }
    }

    for dir in env_or_defaults("HARDN_TOOL_PATH", DEFAULT_TOOL_DIRS) {
        for name in ["hardn-audit", "hardn_audit"] {
            let candidate = Path::new(&dir).join(name);
            if is_executable(&candidate) {
                return Some(candidate);
            }
        }
    }

    let mut known_dirs: Vec<PathBuf> = vec![
        PathBuf::from("/usr/lib/hardn"),
        PathBuf::from("/usr/libexec/hardn"),
        PathBuf::from("/usr/local/lib/hardn"),
        PathBuf::from("/usr/local/libexec/hardn"),
        PathBuf::from(DEFAULT_LIB_DIR).join("bin"),
    ];

    if let Ok(cwd) = env::current_dir() {
        known_dirs.push(cwd.join("debian/hardn/usr/lib/hardn"));
        known_dirs.push(cwd.join("target/release"));
    }

    known_dirs.push(PathBuf::from(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/debian/hardn/usr/lib/hardn"
    )));

    for dir in known_dirs {
        for name in ["hardn-audit", "hardn_audit"] {
            let candidate = dir.join(name);
            if is_executable(&candidate) {
                return Some(candidate);
            }
        }
    }

    if let Some(path_var) = env::var_os("PATH") {
        for dir in env::split_paths(&path_var) {
            for name in ["hardn-audit", "hardn_audit"] {
                let candidate = dir.join(name);
                if is_executable(&candidate) {
                    return Some(candidate);
                }
            }
        }
    }

    None
}

fn is_executable(path: &Path) -> bool {
    if !path.is_file() {
        return false;
    }

    path.metadata()
        .map(|metadata| metadata.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

/// Run all available modules
/// NOTE: This function ONLY runs .sh scripts found in module directories
/// It does NOT include sandbox commands which are independent safety features
fn run_all_modules() -> i32 {
    let module_dirs = env_or_defaults("HARDN_MODULE_PATH", DEFAULT_MODULE_DIRS);

    println!("\n═══ RUNNING ALL MODULES ═══\n");
    log_message(
        LogLevel::Info,
        "Starting execution of all available modules...",
    );
    log_message(
        LogLevel::Info,
        "Note: Sandbox commands are NOT included in batch operations",
    );

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
                    log_message(
                        LogLevel::Pass,
                        &format!("Module {} completed successfully", module_name),
                    );
                    succeeded += 1;
                }
                Ok(_) => {
                    log_message(LogLevel::Error, &format!("Module {} failed", module_name));
                    failed += 1;
                }
                Err(e) => {
                    log_message(
                        LogLevel::Error,
                        &format!("Failed to run {}: {}", module_name, e),
                    );
                    failed += 1;
                }
            }
        }
    }

    println!("\n═══════════════════════════════════════");
    log_message(
        LogLevel::Info,
        &format!(
            "Module execution complete: {} succeeded, {} failed out of {} total",
            succeeded,
            failed,
            modules.len()
        ),
    );

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
    log_message(
        LogLevel::Info,
        "Starting execution of all available tools...",
    );
    log_message(
        LogLevel::Info,
        "Note: Sandbox commands are NOT included in batch operations",
    );

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
                    log_message(
                        LogLevel::Pass,
                        &format!("Tool {} completed successfully", tool_name),
                    );
                    succeeded += 1;
                }
                Ok(_) => {
                    log_message(LogLevel::Error, &format!("Tool {} failed", tool_name));
                    failed += 1;
                }
                Err(e) => {
                    log_message(
                        LogLevel::Error,
                        &format!("Failed to run {}: {}", tool_name, e),
                    );
                    failed += 1;
                }
            }
        }
    }

    println!("\n═══════════════════════════════════════");
    log_message(
        LogLevel::Info,
        &format!(
            "Tool execution complete: {} succeeded, {} failed out of {} total",
            succeeded,
            failed,
            tools.len()
        ),
    );

    if failed > 0 {
        EXIT_FAILURE
    } else {
        EXIT_SUCCESS
    }
}

/// Run all modules and tools with comprehensive hardening
/// IMPORTANT: This function now includes the comprehensive Lynis hardening process
/// Sandbox commands (--sandbox-on/--sandbox-off) are NEVER included in this batch operation
fn run_everything() -> i32 {
    println!("\n╔═══════════════════════════════════════╗");
    println!("║   COMPREHENSIVE SYSTEM HARDENING        ║");
    println!("╚═════════════════════════════════════════╝\n");

    log_message(
        LogLevel::Warning,
        "WARNING: Sandbox mode is NOT included in batch operations",
    );
    log_message(
        LogLevel::Info,
        "Starting comprehensive system hardening with Lynis optimization...",
    );

    // Check if comprehensive hardening script exists
    let comprehensive_script_paths = vec![
        "/usr/share/hardn/scripts/hardn-lynis-comprehensive.sh",
        "./scripts/hardn-lynis-comprehensive.sh",
        "/opt/hardn/scripts/hardn-lynis-comprehensive.sh",
    ];

    let mut comprehensive_script_found = false;
    let mut comprehensive_result = EXIT_SUCCESS;

    // PHASE 1: Run comprehensive Lynis hardening if available
    for script_path in &comprehensive_script_paths {
        if Path::new(script_path).exists() {
            println!("\n▶ PHASE 1: COMPREHENSIVE LYNIS HARDENING");
            println!("═══════════════════════════════════════");
            log_message(
                LogLevel::Info,
                &format!("Found comprehensive hardening script: {}", script_path),
            );

            match Command::new("bash")
                .arg(script_path)
                .env("HARDN_LOG_DIR", DEFAULT_LOG_DIR)
                .env("HARDN_LIB_DIR", DEFAULT_LIB_DIR)
                .env("HARDN_VERSION", VERSION)
                .stdout(Stdio::inherit())
                .stderr(Stdio::inherit())
                .status()
            {
                Ok(status) => {
                    if status.success() {
                        log_message(
                            LogLevel::Pass,
                            "✓ Comprehensive Lynis hardening completed successfully",
                        );
                    } else {
                        log_message(
                            LogLevel::Warning,
                            "Comprehensive hardening completed with warnings",
                        );
                        comprehensive_result = EXIT_FAILURE;
                    }
                    comprehensive_script_found = true;
                    break;
                }
                Err(e) => {
                    log_message(
                        LogLevel::Error,
                        &format!("✗ Failed to run comprehensive hardening: {}", e),
                    );
                    comprehensive_result = EXIT_FAILURE;
                }
            }
        }
    }

    if !comprehensive_script_found {
        log_message(
            LogLevel::Info,
            "Comprehensive hardening script not found, using standard approach",
        );
    }

    // PHASE 2: Run all standard modules
    println!("\n▶ PHASE 2: STANDARD SECURITY MODULES");
    println!("═══════════════════════════════════");
    let module_result = run_all_modules();

    // PHASE 3: Run all security tools
    println!("\n▶ PHASE 3: SECURITY TOOLS");
    println!("═════════════════════════");
    let tool_result = run_all_tools();

    // Report overall status
    println!("\n╔═══════════════════════════════════════╗");
    println!("║       HARDENING EXECUTION SUMMARY       ║");
    println!("╚═════════════════════════════════════════╝\n");

    // Determine final status based on all phases
    let all_success = comprehensive_result == EXIT_SUCCESS
        && module_result == EXIT_SUCCESS
        && tool_result == EXIT_SUCCESS;

    if all_success {
        log_message(LogLevel::Pass, "✓ ALL PHASES COMPLETED SUCCESSFULLY");
        println!("\n[COMPLETE] System hardening finished successfully!");
        println!(
            "   - Comprehensive Lynis hardening: {}",
            if comprehensive_script_found {
                "Applied"
            } else {
                "Skipped (script not found)"
            }
        );
        println!("   - Standard modules: Success");
        println!("   - Security tools: Success");
        println!("\n[NEXT STEPS]");
        println!("   1. Review logs in /var/log/hardn/");
        println!("   2. Run 'sudo lynis audit system' to check your security score");
        println!("   3. Reboot if kernel parameters were modified");
        EXIT_SUCCESS
    } else {
        log_message(LogLevel::Warning, "WARNING: Some phases had issues");

        if comprehensive_result != EXIT_SUCCESS && comprehensive_script_found {
            log_message(
                LogLevel::Warning,
                "   - Comprehensive hardening had warnings",
            );
        }
        if module_result != EXIT_SUCCESS {
            log_message(LogLevel::Warning, "   - Some modules failed");
        }
        if tool_result != EXIT_SUCCESS {
            log_message(LogLevel::Warning, "   - Some tools failed");
        }

        println!("\n[WARNING] System hardening completed with warnings.");
        println!("   Review the logs for details: /var/log/hardn/");

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

    log_message(
        LogLevel::Warning,
        "⚠️  SANDBOX MODE - Manual activation only",
    );
    log_message(LogLevel::Warning, "This command must be run independently");
    log_message(LogLevel::Warning, "Activating network isolation...");

    // Save current network configuration
    let backup_dir = "/var/lib/hardn/sandbox-backup";
    let _ = fs::create_dir_all(backup_dir);

    // Backup current iptables rules
    let iptables_backup = Command::new("iptables-save").output();

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
            fs::write(
                format!("{}/network-interfaces.txt", backup_dir),
                output.stdout,
            )
        });

    // Drop all network traffic
    let mut success = true;

    // Set default policies to DROP
    let policies = vec![("INPUT", "DROP"), ("OUTPUT", "DROP"), ("FORWARD", "DROP")];

    for (chain, policy) in policies {
        match Command::new("iptables")
            .args(["-P", chain, policy])
            .status()
        {
            Ok(status) if status.success() => {
                log_message(
                    LogLevel::Pass,
                    &format!("Set {} policy to {}", chain, policy),
                );
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
        let _ = Command::new("iptables").args(rule).status();
    }

    // Disable all network interfaces except loopback
    let interfaces_output = Command::new("ip").args(["link", "show"]).output();

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
                            log_message(
                                LogLevel::Warning,
                                &format!("Could not disable interface: {}", iface),
                            );
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
    println!("║            ⚠️ Advanced ⚠️             ║");
    println!("║          SELINUX ACTIVATION            ║");
    println!("╚════════════════════════════════════════╝\n");

    log_message(
        LogLevel::Error,
        "⚠️  CRITICAL WARNING: SELinux activation will:",
    );
    log_message(LogLevel::Error, "   1. DISABLE AppArmor (if active)");
    log_message(
        LogLevel::Error,
        "   2. Modify GRUB bootloader configuration",
    );
    log_message(LogLevel::Error, "   3. REQUIRE a system reboot");
    log_message(LogLevel::Error, "   4. May break existing applications");
    println!();
    log_message(
        LogLevel::Warning,
        "This is a MAJOR system change that cannot be easily reversed.",
    );
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
        log_message(
            LogLevel::Error,
            "SELinux script not found. This is intentional for safety.",
        );
        log_message(
            LogLevel::Info,
            "SELinux must be configured manually or the script restored.",
        );
        return EXIT_FAILURE;
    }

    // Run the dangerous SELinux script
    log_message(LogLevel::Warning, "Proceeding with SELinux activation...");

    match Command::new("bash").arg(selinux_script).status() {
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
            .stdin(Stdio::from(
                fs::File::open(&iptables_backup).unwrap_or_else(|_| {
                    log_message(LogLevel::Error, "Could not open iptables backup file");
                    process::exit(EXIT_FAILURE);
                }),
            ))
            .status()
        {
            Ok(status) if status.success() => {
                log_message(LogLevel::Pass, "Firewall rules restored");
            }
            _ => {
                log_message(LogLevel::Error, "Failed to restore firewall rules");
                success = false;

                // Fallback: set default ACCEPT policies
                let _ = Command::new("iptables")
                    .args(["-P", "INPUT", "ACCEPT"])
                    .status();
                let _ = Command::new("iptables")
                    .args(["-P", "OUTPUT", "ACCEPT"])
                    .status();
                let _ = Command::new("iptables")
                    .args(["-P", "FORWARD", "ACCEPT"])
                    .status();
                let _ = Command::new("iptables").args(["-F"]).status();
            }
        }
    } else {
        // No backup found, set permissive defaults
        log_message(
            LogLevel::Warning,
            "No firewall backup found, setting default policies",
        );
        let _ = Command::new("iptables")
            .args(["-P", "INPUT", "ACCEPT"])
            .status();
        let _ = Command::new("iptables")
            .args(["-P", "OUTPUT", "ACCEPT"])
            .status();
        let _ = Command::new("iptables")
            .args(["-P", "FORWARD", "DROP"])
            .status();
        let _ = Command::new("iptables").args(["-F"]).status();
    }

    // Re-enable network interfaces
    let interfaces_output = Command::new("ip").args(["link", "show"]).output();

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
                            log_message(
                                LogLevel::Warning,
                                &format!("Could not enable interface: {}", iface),
                            );
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
        log_message(
            LogLevel::Warning,
            "Sandbox deactivation completed with some warnings",
        );
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
            vec![
                "lynis",
                "rkhunter",
                "aide",
                "debsums",
                "yara",
                "legion",
                "chkrootkit",
            ],
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
            vec![
                "audit",
                "prometheus_monitoring",
                "centralized_logging",
                "auditd",
            ],
        ),
        ToolCategory::new(
            "System Management",
            vec![
                "auto_update",
                "update_system_packages",
                "cron",
                "ntp",
                "cleanup",
                "firmware",
                "enable_apparmor",
                "systemd",
            ],
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
    // Terminal width (assuming standard 80 chars, but can be adjusted)
    const TERM_WIDTH: usize = 80;

    // Helper function to center text
    let center_text = |text: &str| -> String {
        let padding = TERM_WIDTH.saturating_sub(text.len()) / 2;
        format!("{:width$}{}", "", text, width = padding)
    };

    // Print centered header
    println!();
    println!(
        "{}",
        center_text(&format!(
            "{} - Linux Security Hardening and Extended Detection & Response Toolkit",
            APP_NAME
        ))
    );
    println!("{}", center_text(&format!("Version: {}", VERSION)));
    println!();
    println!(
        "{}",
        center_text("Developed by: Security International Group (SIG) Team")
    );
    println!("{}", center_text("License: MIT"));
    println!();

    // Print the rest with normal formatting
    println!(
        r#"HARDN is a comprehensive security hardening and threat detection system
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
"#
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
            service_name: "clamv-daemon",
            process_name: "clamd",
            description: "Antivirus engine for detecting trojans and malware",
        },
        SecurityToolInfo {
            name: "Legion",
            service_name: "legion-daemon",
            process_name: "legion",
            description: "Continuous anomaly detection and network telemetry",
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
        .args(["is-active", service_name])
        .output()
    {
        Ok(output) => output,
        Err(_) => {
            return ServiceStatus {
                name: service_name.to_string(),
                active: false,
                enabled: false,
                description: String::new(),
                pid: None,
            }
        }
    };

    let active = String::from_utf8_lossy(&active_output.stdout).trim() == "active";

    // Check if service is enabled
    let enabled_output = match Command::new("systemctl")
        .args(["is-enabled", service_name])
        .output()
    {
        Ok(output) => output,
        Err(_) => {
            return ServiceStatus {
                name: service_name.to_string(),
                active,
                enabled: false,
                description: String::new(),
                pid: None,
            }
        }
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
    let output = match Command::new("ps").args(["aux"]).output() {
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
                let cmd = parts[10..].join(" ").chars().take(50).collect::<String>();

                processes.push(format!(
                    "  PID: {} | CPU: {}% | MEM: {}% | CMD: {}...",
                    pid, cpu, mem, cmd
                ));
            }
        }
    }

    processes
}

/// Get simple service status (active/inactive/failed)
fn get_service_status_simple(service: &str) -> String {
    let output = Command::new("systemctl")
        .args(["is-active", service])
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
        Err(_) => "unknown".to_string(),
    }
}

/// Get detailed service status information
fn get_service_status_detailed(service: &str) -> String {
    let output = Command::new("systemctl")
        .args(["status", service, "--no-pager", "-l"])
        .output();

    match output {
        Ok(result) => {
            if result.status.success() {
                String::from_utf8_lossy(&result.stdout).to_string()
            } else {
                format!(
                    "{}: Failed to get status - {}",
                    service,
                    String::from_utf8_lossy(&result.stderr)
                )
            }
        }
        Err(e) => format!("{}: Error - {}", service, e),
    }
}

/// Manage HARDN services (enable, disable, start, stop, restart)
fn manage_service(action: &str) -> i32 {
    // List of manageable HARDN services (in dependency order)
    // Note: hardn-monitor is optional and may not be present
    let services = vec!["hardn", "hardn-api", "legion-daemon"];
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
            log_message(
                LogLevel::Error,
                &format!("Unknown service action: {}", action),
            );
            println!("\nValid actions: enable, disable, start, stop, restart");
            println!("Example: sudo hardn service enable");
            EXIT_USAGE
        }
    }
}

/// Enable a systemd service
fn enable_systemd_service(service_name: &str, optional: bool) {
    print!("  Enabling {}... ", service_name);

    let unit = format!("{}.service", service_name);
    let output = Command::new("systemctl")
        .args(["enable", unit.as_str()])
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
                    println!(
                        "    Error: {}",
                        String::from_utf8_lossy(&result.stderr).trim()
                    );
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

    let unit = format!("{}.service", service_name);
    let output = Command::new("systemctl")
        .args(["disable", unit.as_str()])
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
                    println!(
                        "    Error: {}",
                        String::from_utf8_lossy(&result.stderr).trim()
                    );
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

    let unit = format!("{}.service", service_name);
    let output = Command::new("systemctl")
        .args(["start", unit.as_str()])
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
                    println!(
                        "    Error: {}",
                        String::from_utf8_lossy(&result.stderr).trim()
                    );
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

    let unit = format!("{}.service", service_name);
    let output = Command::new("systemctl")
        .args(["stop", unit.as_str()])
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
                    println!(
                        "    Error: {}",
                        String::from_utf8_lossy(&result.stderr).trim()
                    );
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

    let unit = format!("{}.service", service_name);
    let output = Command::new("systemctl")
        .args(["restart", unit.as_str()])
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
                    println!(
                        "    Error: {}",
                        String::from_utf8_lossy(&result.stderr).trim()
                    );
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
    })
    .expect("Error setting Ctrl+C handler");

    let services = vec![
        "hardn.service",
        "hardn-api.service",
        "legion-daemon.service",
        "hardn-monitor.service",
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
                _ => "\x1b[33m",
            };
            println!(
                "  {}. {} - {}{} \x1b[0m",
                i + 1,
                service,
                status_color,
                status
            );
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
                        .args(["restart", service])
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
                        .args([
                            "-f",
                            "-u",
                            "hardn",
                            "-u",
                            "hardn-api",
                            "-u",
                            "legion-daemon",
                            "-u",
                            "hardn-monitor",
                            "--since",
                            "today",
                        ])
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

                    let _ = child.wait();
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
                                .args([
                                    "-f",
                                    "-u",
                                    service_name.as_str(),
                                    "--since",
                                    "today",
                                ])
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

                            let _ = child.wait();
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
        let start_index = formatted_entries.len().saturating_sub(display_count);

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
        if let Some(t_end) = entry[t_start..]
            .find(' ')
            .or_else(|| entry[t_start..].find('.'))
            .or_else(|| entry[t_start..].find('-'))
        {
            let timestamp = &entry[t_start..t_start + t_end];
            if let Some(t_idx) = timestamp.find('T') {
                let time = &timestamp[t_idx + 1..timestamp.len().min(t_idx + 9)];
                formatted.push_str(&format!("[{}] ", time));
            }
        }
    }

    // Extract service name
    for service in &["hardn", "legion", "hardn-monitor"] {
        let needle = format!("{}[", service);
        if entry.contains(&needle) {
            formatted.push_str(&format!("{}: ", service.to_uppercase()));
            break;
        }
    }

    // Handle different types of log entries
    if entry.contains("{\"timestamp\"") || entry.contains("{\"event") {
        // JSON log entry - summarize it
        if entry.contains("legion-network-sensor") {
            formatted.push_str("Legion network sensor alert");
        } else if entry.contains("\"event_type\":\"stats\"") {
            formatted.push_str("Network statistics logged");
        } else if entry.contains("NETWORK ALERT") {
            formatted.push_str("🌐 Network monitoring alert");
        } else if entry.contains("event_type") {
            // Try to extract event type
            if let Some(et_idx) = entry.find("\"event_type\":") {
                let after_et = &entry[et_idx + 14..];
                if let Some(quote_idx) = after_et.find('\"') {
                    if let Some(end_quote) = after_et[quote_idx + 1..].find('\"') {
                        let event_type = &after_et[quote_idx + 1..quote_idx + 1 + end_quote];
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
            .replace("\u{1F310}", "[NET]")
            .replace("\u{26A0}\u{FE0F}", "[WARN]")
            .replace("\u{1F512}", "[SEC]")
            .replace("\u{1F6A8}", "[ALERT]")
            .replace("\u{2713}", "[OK]")
            .replace("\u{2717}", "[FAIL]")
            .replace("\u{1F4CA}", "[STATS]")
            .replace("\u{1F6E1}\u{FE0F}", "[SHIELD]");

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
    let hardn_services = vec!["hardn", "hardn-api", "legion-daemon"];
    let mut any_active = false;

    for service_name in &hardn_services {
        let status = check_service_status(service_name);
        let status_icon = if status.active { "[OK]" } else { "[DOWN]" };
        let status_color = if status.active {
            "\x1b[32m"
        } else {
            "\x1b[31m"
        };
        let enabled_text = if status.enabled {
            "enabled"
        } else {
            "disabled"
        };

        print!(
            "  {} {}{:<15}\x1b[0m",
            status_icon, status_color, service_name
        );

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
        println!(
            "\n  Total active security tools: {}/{}",
            active_tools,
            tools.len()
        );
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
            .args([
                "-u",
                "hardn.service",
                "-u",
                "legion-daemon.service",
                "-u",
                "hardn-monitor.service",
                "-n",
                "10",
                "--no-pager",
                "-o",
                "short-iso",
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
                let log_path = format!("{}/hardn.log", DEFAULT_LOG_DIR);
                let file_output = Command::new("tail")
                    .args(["-n", "10", log_path.as_str()])
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
    sudo hardn --banner      Display the ASCII art banner
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
        Some(path) => match run_script(&path, "module", module_dirs) {
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
        },
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
        Some(path) => match run_script(&path, "tool", module_dirs) {
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
        },
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

    // Ensure LEGION banner and colorized output are ready before checks begin
    crate::legion::functions::enable_color(
        atty::is(atty::Stream::Stdout) && std::env::var_os("NO_COLOR").is_none(),
    );
    crate::legion::banner::display_banner();

    // Create a tokio runtime for async legion execution
    let rt = tokio::runtime::Runtime::new().unwrap();

    // Call the legion module
    rt.block_on(async {
        match crate::legion::core::legion::run_with_args(&legion_args).await {
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
        2 => matches!(
            args[1].as_str(),
            "-h" | "--help" | "help" | "-a" | "--about" | "about"
        ),
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
            2 => match args[1].as_str() {
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
                "-b" | "--banner" | "banner" => {
                    print_banner();
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
                "services" => interactive_service_monitor(),
                "--run-all-modules" | "run-all-modules" => run_all_modules(),
                "--run-all-tools" | "run-all-tools" => run_all_tools(),
                "--run-everything" | "run-everything" => run_everything(),
                "--sandbox-on" | "sandbox-on" => sandbox_on(),
                "--sandbox-off" | "sandbox-off" => sandbox_off(),
                "--service-enable" | "service-enable" => manage_service("enable"),
                "--service-start" | "service-start" => manage_service("start"),
                "--service-status" | "service-status" => {
                    show_status();
                    EXIT_SUCCESS
                }
                "--enable-selinux" | "enable-selinux" => enable_selinux(),
                _ => {
                    log_message(LogLevel::Error, &format!("Unknown option: {}", args[1]));
                    print_help();
                    EXIT_USAGE
                }
            },
            3 => match args[1].as_str() {
                "service" => manage_service(&args[2]),
                "run-module" => handle_run_module(&module_dirs, &args[2]),
                "run-tool" => handle_run_tool(&tool_dirs, &args[2], &module_dirs),
                _ => {
                    log_message(LogLevel::Error, &format!("Unknown command: {}", args[1]));
                    print_help();
                    EXIT_USAGE
                }
            },
            _ => {
                log_message(LogLevel::Error, "Invalid number of arguments");
                print_help();
                EXIT_USAGE
            }
        }
    };
    process::exit(exit_code);
}
