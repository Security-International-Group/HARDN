use std::fs;
use std::process::Command;

/// Authentication and account security checks
#[allow(clippy::module_inception)]
pub mod auth {
    use super::*;

    #[allow(dead_code)]
    pub fn check_auth_failures() -> Result<(), Box<dyn std::error::Error>> {
        eprintln!("  Checking authentication failures...");

        // Check recent failed login attempts
        if let Ok(output) = Command::new("journalctl")
            .args(["-u", "sshd", "--since", "1 hour ago", "-g", "Failed"])
            .output()
        {
            let output_str = String::from_utf8_lossy(&output.stdout);
            let failure_count = output_str.lines().count();

            if failure_count > 0 {
                eprintln!(
                    "    Found {} SSH authentication failures in last hour",
                    failure_count
                );
            } else {
                eprintln!("    No recent SSH authentication failures");
            }
        }

        // Check faillock status
        if let Ok(output) = Command::new("faillock").output() {
            let output_str = String::from_utf8_lossy(&output.stdout);
            let lockout_count = output_str.lines().count();
            if lockout_count > 0 {
                eprintln!("    Active account lockouts detected");
            }
        }

        Ok(())
    }

    #[allow(dead_code)]
    pub fn check_sudoers_changes() -> Result<(), Box<dyn std::error::Error>> {
        eprintln!("  Checking sudoers configuration...");

        // Check for passwordless sudo entries
        if let Ok(content) = fs::read_to_string("/etc/sudoers") {
            let mut suspicious_lines = Vec::new();

            for (line_num, line) in content.lines().enumerate() {
                let line = line.trim();
                if line.contains("NOPASSWD") && !line.starts_with('#') {
                    suspicious_lines.push(format!("Line {}: {}", line_num + 1, line));
                }
            }

            if !suspicious_lines.is_empty() {
                eprintln!("    Found passwordless sudo entries:");
                for entry in suspicious_lines {
                    eprintln!("       {}", entry);
                }
            } else {
                eprintln!("    No passwordless sudo entries found");
            }
        }

        Ok(())
    }

    #[allow(dead_code)]
    pub fn check_ssh_config() -> Result<(), Box<dyn std::error::Error>> {
        eprintln!("  Checking SSH configuration...");

        if let Ok(content) = fs::read_to_string("/etc/ssh/sshd_config") {
            let mut issues = Vec::new();

            for line in content.lines() {
                let line = line.trim();
                if line.starts_with("PermitRootLogin") && line.contains("yes") {
                    issues.push("Root login permitted via SSH");
                }
                if line.starts_with("PasswordAuthentication") && line.contains("yes") {
                    issues.push("Password authentication enabled");
                }
                if line.starts_with("PermitEmptyPasswords") && line.contains("yes") {
                    issues.push("Empty passwords permitted");
                }
            }

            if issues.is_empty() {
                eprintln!("    SSH configuration appears secure");
            } else {
                eprintln!("    SSH security issues found:");
                for issue in issues {
                    eprintln!("       - {}", issue);
                }
            }
        }

        Ok(())
    }
}
