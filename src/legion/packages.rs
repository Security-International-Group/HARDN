use std::process::Command;

/// Package and binary integrity checks
pub mod packages {
    use super::*;

    #[allow(dead_code)]
    pub fn check_package_drift() -> Result<(), Box<dyn std::error::Error>> {
        println!("  Checking package integrity...");

        // Check for modified packages using debsums
        if let Ok(output) = Command::new("debsums").arg("-c").output() {
            let output_str = String::from_utf8_lossy(&output.stderr);
            let modified_count = output_str.lines().count();

            if modified_count > 0 {
                println!("    Found {} packages with modified files", modified_count);
                // Show first few modified packages
                for line in output_str.lines().take(3) {
                    println!("       {}", line);
                }
            } else {
                println!("    Package integrity verified");
            }
        } else {
            println!("    debsums not available for package integrity check");
        }

        Ok(())
    }

    #[allow(dead_code)]
    pub fn check_binary_integrity() -> Result<(), Box<dyn std::error::Error>> {
        println!("  Checking binary integrity...");

        // Check critical system binaries
        let critical_binaries = vec![
            "/bin/bash",
            "/bin/sh",
            "/usr/bin/sudo",
            "/usr/bin/su",
            "/usr/sbin/sshd",
        ];

        let mut suspicious = Vec::new();

        for binary in critical_binaries {
            if let Ok(metadata) = std::fs::metadata(binary) {
                use std::os::unix::fs::PermissionsExt;
                let mode = metadata.permissions().mode();

                // Check for SUID/SGID bits
                if mode & 0o4000 != 0 || mode & 0o2000 != 0 {
                    suspicious.push(format!("{} has SUID/SGID bits", binary));
                }
            }
        }

        if suspicious.is_empty() {
            println!("    Critical binaries appear normal");
        } else {
            println!("    Suspicious binary permissions:");
            for item in suspicious {
                println!("       {}", item);
            }
        }

        Ok(())
    }
}