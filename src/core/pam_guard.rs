// PAM Guard Module for HARDN
// Purpose: Prevent PAM misconfigurations that could break sudo access

use std::fs;
use std::path::Path;
use std::process::Command;
use crate::utils::{LogLevel, log_message};

/// Critical PAM files that should never be removed or corrupted
const CRITICAL_PAM_FILES: &[&str] = &[
    "/etc/pam.d/sudo",
    "/etc/pam.d/common-auth",
    "/etc/pam.d/common-account",
    "/etc/pam.d/common-password",
    "/etc/pam.d/common-session",
    "/etc/pam.d/common-session-noninteractive",
];

/// Check if PAM configuration is valid
pub fn check_pam_health() -> bool {
    log_message(LogLevel::Info, "Checking PAM configuration health...");
    
    // Check if PAM directory exists
    if !Path::new("/etc/pam.d").exists() {
        log_message(LogLevel::Error, "PAM directory /etc/pam.d does not exist!");
        return false;
    }
    
    // Check critical PAM files
    let mut all_good = true;
    for file in CRITICAL_PAM_FILES {
        if !Path::new(file).exists() {
            log_message(LogLevel::Error, &format!("Critical PAM file missing: {}", file));
            all_good = false;
        } else {
            // Check if file is not empty
            match fs::read_to_string(file) {
                Ok(content) => {
                    if content.trim().is_empty() {
                        log_message(LogLevel::Warning, &format!("PAM file is empty: {}", file));
                        all_good = false;
                    }
                    // Check for obvious errors
                    if content.contains("Module is unknown") {
                        log_message(LogLevel::Error, &format!("PAM file has errors: {}", file));
                        all_good = false;
                    }
                }
                Err(e) => {
                    log_message(LogLevel::Error, &format!("Cannot read PAM file {}: {}", file, e));
                    all_good = false;
                }
            }
        }
    }
    
    if all_good {
        log_message(LogLevel::Pass, "PAM configuration appears healthy");
    }
    
    all_good
}

/// Create backup of PAM configuration
pub fn backup_pam_config() -> Result<String, std::io::Error> {
    let timestamp = chrono::Local::now().format("%Y%m%d-%H%M%S");
    let backup_dir = format!("/var/lib/hardn/pam-backup-{}", timestamp);
    
    log_message(LogLevel::Info, &format!("Creating PAM backup to {}", backup_dir));
    
    // Create backup directory
    fs::create_dir_all(&backup_dir)?;
    
    // Copy PAM configuration
    let pam_dir = Path::new("/etc/pam.d");
    if pam_dir.exists() {
        // Use cp command for simplicity
        Command::new("cp")
            .args(&["-r", "/etc/pam.d", &backup_dir])
            .status()?;
    }
    
    // Copy security directory
    let security_dir = Path::new("/etc/security");
    if security_dir.exists() {
        Command::new("cp")
            .args(&["-r", "/etc/security", &backup_dir])
            .status()?;
    }
    
    log_message(LogLevel::Pass, &format!("PAM configuration backed up to {}", backup_dir));
    Ok(backup_dir)
}

/// Verify sudo is working
pub fn test_sudo() -> bool {
    log_message(LogLevel::Info, "Testing sudo functionality...");
    
    // Create a simple test
    match Command::new("sudo")
        .args(&["-n", "true"])  // -n = non-interactive
        .status()
    {
        Ok(status) => {
            if status.success() {
                log_message(LogLevel::Pass, "Sudo test passed");
                true
            } else {
                // This might be normal if password is required
                log_message(LogLevel::Warning, "Sudo requires password or has issues");
                // Try to check if it's just a password requirement
                match Command::new("sudo")
                    .args(&["-l"])  // List sudo privileges
                    .output()
                {
                    Ok(output) => {
                        let stdout = String::from_utf8_lossy(&output.stdout);
                        if stdout.contains("may run the following") {
                            log_message(LogLevel::Pass, "Sudo is functional (password required)");
                            true
                        } else {
                            log_message(LogLevel::Error, "Sudo appears broken");
                            false
                        }
                    }
                    Err(_) => {
                        log_message(LogLevel::Error, "Cannot test sudo functionality");
                        false
                    }
                }
            }
        }
        Err(e) => {
            log_message(LogLevel::Error, &format!("Failed to test sudo: {}", e));
            false
        }
    }
}

/// Main PAM guard function to be called before any system modifications
pub fn guard_pam_configuration() -> bool {
    log_message(LogLevel::Info, "========================================");
    log_message(LogLevel::Info, "PAM Configuration Guard Active");
    log_message(LogLevel::Info, "========================================");
    
    // First, check current PAM health
    if !check_pam_health() {
        log_message(LogLevel::Error, "PAM configuration issues detected!");
        log_message(LogLevel::Warning, "Run scripts/fix-pam-sudo.sh to repair");
        return false;
    }
    
    // Create backup
    match backup_pam_config() {
        Ok(backup_path) => {
            log_message(LogLevel::Pass, &format!("Backup created: {}", backup_path));
        }
        Err(e) => {
            log_message(LogLevel::Error, &format!("Failed to backup PAM config: {}", e));
            return false;
        }
    }
    
    // Test sudo
    if !test_sudo() {
        log_message(LogLevel::Error, "Sudo functionality check failed!");
        log_message(LogLevel::Warning, "System modifications may be unsafe");
        return false;
    }
    
    log_message(LogLevel::Pass, "PAM guard checks passed - safe to proceed");
    true
}

/// Restore PAM configuration from backup
pub fn restore_pam_from_backup(backup_dir: &str) -> Result<(), std::io::Error> {
    log_message(LogLevel::Warning, &format!("Restoring PAM from backup: {}", backup_dir));
    
    let backup_pam = format!("{}/pam.d", backup_dir);
    let backup_security = format!("{}/security", backup_dir);
    
    // Restore pam.d
    if Path::new(&backup_pam).exists() {
        Command::new("cp")
            .args(&["-r", &backup_pam, "/etc/"])
            .status()?;
        log_message(LogLevel::Pass, "Restored /etc/pam.d");
    }
    
    // Restore security
    if Path::new(&backup_security).exists() {
        Command::new("cp")
            .args(&["-r", &backup_security, "/etc/"])
            .status()?;
        log_message(LogLevel::Pass, "Restored /etc/security");
    }
    
    Ok(())
}