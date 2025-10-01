use std::os::unix::fs::PermissionsExt;
use std::process::Command;

/// File permissions and access control monitoring
pub mod permissions {
    use super::*;

    #[allow(dead_code)]
    pub fn check_world_writable_files() -> Result<(), Box<dyn std::error::Error>> {
        safe_println!("  Checking for world-writable files...");

        // Find world-writable files in system directories
        if let Ok(output) = Command::new("find")
            .args(&["/etc", "/usr", "/var", "-type", "f", "-perm", "-002", "-ls"])
            .output()
        {
            let output_str = String::from_utf8_lossy(&output.stdout);
            let world_writable: Vec<&str> = output_str.lines().collect();

            if !world_writable.is_empty() {
                safe_println!(
                    "    WARNING: {} world-writable files found in system directories",
                    world_writable.len(),
                );
                for file in world_writable.iter().take(5) {
                    safe_println!("      {}", file);
                }
                if world_writable.len() > 5 {
                    safe_println!("      ... and {} more", world_writable.len() - 5);
                }
            } else {
                safe_println!("    No world-writable files found in system directories");
            }
        }

        Ok(())
    }

    #[allow(dead_code)]
    pub fn check_suid_sgid_permissions() -> Result<(), Box<dyn std::error::Error>> {
        safe_println!("  Analyzing SUID/SGID file permissions...");

        // Get detailed SUID/SGID file information
        if let Ok(output) = Command::new("find")
            .args(&[
                "/", "-type", "f", "-perm", "/6000", "-exec", "ls", "-la", "{}", ";",
            ])
            .output()
        {
            let output_str = String::from_utf8_lossy(&output.stdout);
            let suid_files: Vec<&str> = output_str.lines().collect();

            if !suid_files.is_empty() {
                safe_println!("    Detailed SUID/SGID file analysis:");
                let mut suid_count = 0;
                let mut sgid_count = 0;

                for file in suid_files {
                    if file.contains("-rws") {
                        suid_count += 1;
                    }
                    if file.contains("-rwx") && file.contains("s") {
                        sgid_count += 1;
                    }
                }

                safe_println!("      SUID files: {}", suid_count);
                safe_println!("      SGID files: {}", sgid_count);
            }
        }

        Ok(())
    }

    #[allow(dead_code)]
    pub fn check_file_ownership() -> Result<(), Box<dyn std::error::Error>> {
        safe_println!("  Checking file ownership consistency...");

        // Check for files owned by non-existent users
        if let Ok(output) = Command::new("find")
            .args(&["/etc", "/home", "-nouser", "-o", "-nogroup", "-type", "f"])
            .output()
        {
            let output_str = String::from_utf8_lossy(&output.stdout);
            let orphan_files: Vec<&str> = output_str.lines().collect();

            if !orphan_files.is_empty() {
                safe_println!(
                    "    WARNING: {} files with invalid ownership found",
                    orphan_files.len(),
                );
                for file in orphan_files.iter().take(3) {
                    safe_println!("      {}", file);
                }
            } else {
                safe_println!("    All files have valid ownership");
            }
        }

        Ok(())
    }

    #[allow(dead_code)]
    pub fn check_directory_permissions() -> Result<(), Box<dyn std::error::Error>> {
        safe_println!("  Checking critical directory permissions...");

        let critical_dirs = vec!["/etc", "/usr", "/var", "/home", "/root", "/boot"];

        for dir in critical_dirs {
            if let Ok(metadata) = std::fs::metadata(dir) {
                let permissions = metadata.permissions();
                let mode = permissions.mode();
                safe_println!("    {}: {:o}", dir, mode & 0o777);
            }
        }

        Ok(())
    }

    #[allow(dead_code)]
    pub fn detect_permission_anomalies() -> Result<(), Box<dyn std::error::Error>> {
        safe_println!("  Detecting permission-related security anomalies...");

        // Check for unusual permission patterns
        if let Ok(output) = Command::new("find")
            .args(&["/etc", "-type", "f", "-perm", "-777"])
            .output()
        {
            let output_str = String::from_utf8_lossy(&output.stdout);
            let world_rw_files: Vec<&str> = output_str.lines().collect();

            if !world_rw_files.is_empty() {
                safe_println!(
                    "    CRITICAL: {} files with 777 permissions in /etc",
                    world_rw_files.len(),
                );
                for file in world_rw_files.iter().take(3) {
                    safe_println!("      {}", file);
                }
            }
        }

        // Check for executable files in unusual locations
        if let Ok(output) = Command::new("find")
            .args(&["/etc", "-type", "f", "-executable"])
            .output()
        {
            let output_str = String::from_utf8_lossy(&output.stdout);
            let executable_configs: Vec<&str> = output_str.lines().collect();

            if !executable_configs.is_empty() {
                safe_println!(
                    "    WARNING: {} executable files in /etc directory",
                    executable_configs.len(),
                );
            }
        }

        Ok(())
    }
}
