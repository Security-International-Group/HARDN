// security_tool_manager.rs - Enhanced security tool detection and management
use std::process::Command;
use std::path::Path;
use std::fs;

#[derive(Debug, Clone)]
pub struct SecurityTool {
    pub name: &'static str,
    pub check_method: CheckMethod,
    pub activation_method: ActivationMethod,
    pub description: &'static str,
}

#[derive(Debug, Clone)]
pub enum CheckMethod {
    SystemdService(String),           // Check via systemctl
    SystemdTimer(String),             // Check systemd timer
    ProcessName(String),              // Check if process is running
    BinaryExists(String),             // Check if binary exists
    ConfigExists(String),             // Check if config file exists
    FirewallStatus,                   // Special check for UFW
    Custom(fn() -> bool),             // Custom check function
}

#[derive(Debug, Clone)]
pub enum ActivationMethod {
    SystemdService(String),           // Start via systemctl
    SystemdTimer(String),             // Enable/start systemd timer
    RunCommand(String),               // Run a command
    EnableFirewall,                   // Special activation for UFW
    InstallPackage(String),           // Install via apt
    Custom(fn() -> Result<(), String>), // Custom activation
}

#[derive(Debug)]
pub struct ToolStatus {
    pub name: String,
    pub active: bool,
    pub installed: bool,
    pub configured: bool,
    pub details: String,
}

impl SecurityTool {
    pub fn check_status(&self) -> ToolStatus {
        let (active, details) = match &self.check_method {
            CheckMethod::SystemdService(service) => {
                check_systemd_service(service)
            },
            CheckMethod::SystemdTimer(timer) => {
                check_systemd_timer(timer)
            },
            CheckMethod::ProcessName(process) => {
                check_process_running(process)
            },
            CheckMethod::BinaryExists(binary) => {
                check_binary_exists(binary)
            },
            CheckMethod::ConfigExists(config) => {
                check_config_exists(config)
            },
            CheckMethod::FirewallStatus => {
                check_ufw_status()
            },
            CheckMethod::Custom(check_fn) => {
                let active = check_fn();
                (active, if active { "Active (custom check)" } else { "Inactive" }.to_string())
            }
        };

        // Check if tool is installed
        let installed = self.is_installed();
        let configured = self.is_configured();

        ToolStatus {
            name: self.name.to_string(),
            active,
            installed,
            configured,
            details,
        }
    }

    pub fn activate(&self) -> Result<(), String> {
        // First ensure the tool is installed
        if !self.is_installed() {
            return Err(format!("{} is not installed. Please install it first.", self.name));
        }

        match &self.activation_method {
            ActivationMethod::SystemdService(service) => {
                start_systemd_service(service)
            },
            ActivationMethod::SystemdTimer(timer) => {
                enable_systemd_timer(timer)
            },
            ActivationMethod::RunCommand(cmd) => {
                run_activation_command(cmd)
            },
            ActivationMethod::EnableFirewall => {
                enable_ufw()
            },
            ActivationMethod::InstallPackage(package) => {
                install_package(package)
            },
            ActivationMethod::Custom(activate_fn) => {
                activate_fn()
            }
        }
    }

    fn is_installed(&self) -> bool {
        // Check if the tool's package is installed
        let package_name = match self.name {
            "AIDE" => "aide",
            "AppArmor" => "apparmor",
            "Fail2Ban" => "fail2ban",
            "UFW" => "ufw",
            "Auditd" => "auditd",
            "RKHunter" => "rkhunter",
            "ClamAV" => "clamav-daemon",
            "Suricata" => "suricata",
            "OSSEC" => "ossec-hids",
            "Lynis" => "lynis",
            _ => return false,
        };

        check_package_installed(package_name)
    }

    fn is_configured(&self) -> bool {
        // Check if the tool has basic configuration
        match self.name {
            "AIDE" => Path::new("/etc/aide/aide.conf").exists(),
            "AppArmor" => Path::new("/etc/apparmor.d").exists(),
            "Fail2Ban" => Path::new("/etc/fail2ban/jail.conf").exists(),
            "UFW" => Path::new("/etc/ufw/ufw.conf").exists(),
            "Auditd" => Path::new("/etc/audit/auditd.conf").exists(),
            "RKHunter" => Path::new("/etc/rkhunter.conf").exists(),
            "ClamAV" => Path::new("/etc/clamav/clamd.conf").exists(),
            "Suricata" => Path::new("/etc/suricata/suricata.yaml").exists(),
            "OSSEC" => Path::new("/var/ossec/etc/ossec.conf").exists(),
            "Lynis" => Path::new("/etc/lynis").exists() || which_binary("lynis").is_some(),
            _ => false,
        }
    }
}

// Helper functions
fn check_systemd_service(service: &str) -> (bool, String) {
    let output = Command::new("systemctl")
        .args(&["is-active", service])
        .output();
    
    match output {
        Ok(result) => {
            let status = String::from_utf8_lossy(&result.stdout).trim().to_string();
            let active = status == "active";
            (active, format!("Service {}: {}", service, status))
        },
        Err(_) => (false, format!("Service {} not found", service))
    }
}

fn check_systemd_timer(timer: &str) -> (bool, String) {
    let output = Command::new("systemctl")
        .args(&["is-active", timer])
        .output();
    
    match output {
        Ok(result) => {
            let status = String::from_utf8_lossy(&result.stdout).trim().to_string();
            let active = status == "active";
            
            // Also check if timer is enabled
            let enabled_output = Command::new("systemctl")
                .args(&["is-enabled", timer])
                .output();
            
            let enabled = enabled_output
                .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "enabled")
                .unwrap_or(false);
            
            let details = format!("Timer {}: {} ({})", 
                timer, 
                status,
                if enabled { "enabled" } else { "disabled" }
            );
            
            (active || enabled, details)
        },
        Err(_) => (false, format!("Timer {} not found", timer))
    }
}

fn check_process_running(process: &str) -> (bool, String) {
    let output = Command::new("pgrep")
        .arg(process)
        .output();
    
    match output {
        Ok(result) => {
            let active = result.status.success();
            if active {
                let pids = String::from_utf8_lossy(&result.stdout).trim().to_string();
                (true, format!("Process {} running (PIDs: {})", process, pids.replace('\n', ", ")))
            } else {
                (false, format!("Process {} not running", process))
            }
        },
        Err(_) => (false, format!("Unable to check process {}", process))
    }
}

fn check_binary_exists(binary: &str) -> (bool, String) {
    if let Some(path) = which_binary(binary) {
        (true, format!("Binary found: {}", path))
    } else {
        (false, format!("Binary {} not found in PATH", binary))
    }
}

fn check_config_exists(config: &str) -> (bool, String) {
    if Path::new(config).exists() {
        (true, format!("Config found: {}", config))
    } else {
        (false, format!("Config {} not found", config))
    }
}

fn check_ufw_status() -> (bool, String) {
    let output = Command::new("ufw")
        .arg("status")
        .output();
    
    match output {
        Ok(result) => {
            let status = String::from_utf8_lossy(&result.stdout);
            let active = status.contains("Status: active");
            if active {
                (true, "UFW firewall is active".to_string())
            } else {
                (false, "UFW firewall is inactive".to_string())
            }
        },
        Err(_) => (false, "UFW not installed or accessible".to_string())
    }
}

fn check_package_installed(package: &str) -> bool {
    let output = Command::new("dpkg")
        .args(&["-l", package])
        .output();
    
    match output {
        Ok(result) => {
            let stdout = String::from_utf8_lossy(&result.stdout);
            stdout.lines().any(|line| {
                line.starts_with("ii") && line.contains(package)
            })
        },
        Err(_) => false
    }
}

fn which_binary(binary: &str) -> Option<String> {
    let output = Command::new("which")
        .arg(binary)
        .output()
        .ok()?;
    
    if output.status.success() {
        Some(String::from_utf8_lossy(&output.stdout).trim().to_string())
    } else {
        None
    }
}

fn start_systemd_service(service: &str) -> Result<(), String> {
    // First enable the service
    let enable_output = Command::new("systemctl")
        .args(&["enable", service])
        .output()
        .map_err(|e| format!("Failed to enable {}: {}", service, e))?;
    
    if !enable_output.status.success() {
        let stderr = String::from_utf8_lossy(&enable_output.stderr);
        if !stderr.contains("already") {
            return Err(format!("Failed to enable {}: {}", service, stderr));
        }
    }
    
    // Then start the service
    let start_output = Command::new("systemctl")
        .args(&["start", service])
        .output()
        .map_err(|e| format!("Failed to start {}: {}", service, e))?;
    
    if !start_output.status.success() {
        let stderr = String::from_utf8_lossy(&start_output.stderr);
        return Err(format!("Failed to start {}: {}", service, stderr));
    }
    
    Ok(())
}

fn enable_systemd_timer(timer: &str) -> Result<(), String> {
    // Enable and start the timer
    let enable_output = Command::new("systemctl")
        .args(&["enable", "--now", timer])
        .output()
        .map_err(|e| format!("Failed to enable timer {}: {}", timer, e))?;
    
    if !enable_output.status.success() {
        let stderr = String::from_utf8_lossy(&enable_output.stderr);
        return Err(format!("Failed to enable timer {}: {}", timer, stderr));
    }
    
    Ok(())
}

fn run_activation_command(cmd: &str) -> Result<(), String> {
    let output = Command::new("sh")
        .arg("-c")
        .arg(cmd)
        .output()
        .map_err(|e| format!("Failed to run command: {}", e))?;
    
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("Command failed: {}", stderr));
    }
    
    Ok(())
}

fn enable_ufw() -> Result<(), String> {
    // Enable UFW with default settings
    let output = Command::new("ufw")
        .args(&["--force", "enable"])
        .output()
        .map_err(|e| format!("Failed to enable UFW: {}", e))?;
    
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("Failed to enable UFW: {}", stderr));
    }
    
    Ok(())
}

fn install_package(package: &str) -> Result<(), String> {
    let output = Command::new("apt-get")
        .args(&["install", "-y", package])
        .output()
        .map_err(|e| format!("Failed to install {}: {}", package, e))?;
    
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("Failed to install {}: {}", package, stderr));
    }
    
    Ok(())
}

// Get the comprehensive list of security tools with proper detection methods
pub fn get_security_tools_enhanced() -> Vec<SecurityTool> {
    vec![
        SecurityTool {
            name: "AIDE",
            check_method: CheckMethod::SystemdTimer("dailyaidecheck.timer"),
            activation_method: ActivationMethod::SystemdTimer("dailyaidecheck.timer"),
            description: "Advanced Intrusion Detection Environment - File integrity monitoring",
        },
        SecurityTool {
            name: "AppArmor",
            check_method: CheckMethod::SystemdService("apparmor.service"),
            activation_method: ActivationMethod::SystemdService("apparmor.service"),
            description: "Mandatory Access Control system for applications",
        },
        SecurityTool {
            name: "Fail2Ban",
            check_method: CheckMethod::SystemdService("fail2ban.service"),
            activation_method: ActivationMethod::SystemdService("fail2ban.service"),
            description: "Intrusion prevention - Bans IPs with multiple auth failures",
        },
        SecurityTool {
            name: "UFW",
            check_method: CheckMethod::FirewallStatus,
            activation_method: ActivationMethod::EnableFirewall,
            description: "Uncomplicated Firewall - Network traffic filtering",
        },
        SecurityTool {
            name: "Auditd",
            check_method: CheckMethod::SystemdService("auditd.service"),
            activation_method: ActivationMethod::SystemdService("auditd.service"),
            description: "Linux Audit Framework - Security event logging",
        },
        SecurityTool {
            name: "RKHunter",
            check_method: CheckMethod::BinaryExists("rkhunter"),
            activation_method: ActivationMethod::RunCommand("rkhunter --propupd && rkhunter --update"),
            description: "Rootkit Hunter - Scans for rootkits and exploits",
        },
        SecurityTool {
            name: "ClamAV",
            check_method: CheckMethod::SystemdService("clamav-daemon.service"),
            activation_method: ActivationMethod::SystemdService("clamav-daemon.service"),
            description: "Antivirus engine for detecting trojans and malware",
        },
        SecurityTool {
            name: "Suricata",
            check_method: CheckMethod::SystemdService("suricata.service"),
            activation_method: ActivationMethod::SystemdService("suricata.service"),
            description: "Network IDS/IPS and security monitoring",
        },
        SecurityTool {
            name: "OSSEC",
            check_method: CheckMethod::ProcessName("ossec-analysisd"),
            activation_method: ActivationMethod::RunCommand("/var/ossec/bin/ossec-control start"),
            description: "Host-based Intrusion Detection System",
        },
        SecurityTool {
            name: "Lynis",
            check_method: CheckMethod::SystemdTimer("lynis.timer"),
            activation_method: ActivationMethod::SystemdTimer("lynis.timer"),
            description: "Security auditing and compliance testing",
        },
    ]
}