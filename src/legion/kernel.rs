use std::process::Command;

/// Kernel and low-level monitoring
pub mod kernel {
    use super::*;

    #[allow(dead_code)]
    pub fn check_kernel_modules() -> Result<(), Box<dyn std::error::Error>> {
        println!("  Checking kernel modules...");

        // Check loaded kernel modules
        if let Ok(output) = Command::new("lsmod").output() {
            let output_str = String::from_utf8_lossy(&output.stdout);
            let module_count = output_str.lines().count().saturating_sub(1); // Subtract header

            println!("    {} kernel modules loaded", module_count);

            // Check for suspicious modules
            let suspicious_modules = vec!["cramfs", "freevxfs", "jffs2", "hfs", "hfsplus", "squashfs", "udf"];
            let mut found_suspicious = Vec::new();

            for line in output_str.lines().skip(1) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if !parts.is_empty() {
                    let module_name = parts[0];
                    if suspicious_modules.contains(&module_name) {
                        found_suspicious.push(module_name.to_string());
                    }
                }
            }

            if !found_suspicious.is_empty() {
                println!("    Suspicious kernel modules loaded:");
                for module in found_suspicious {
                    println!("       {}", module);
                }
            }
        }

        Ok(())
    }

    #[allow(dead_code)]
    pub fn check_sysctl_params() -> Result<(), Box<dyn std::error::Error>> {
        println!("  Checking sysctl parameters...");

        // Check important security-related sysctl parameters
        let security_params = vec![
            ("kernel.kptr_restrict", "2"),
            ("kernel.dmesg_restrict", "1"),
            ("net.ipv4.ip_forward", "0"),
            ("net.ipv4.conf.all.accept_redirects", "0"),
        ];

        let mut issues = Vec::new();

        for (param, expected) in security_params {
            if let Ok(output) = Command::new("sysctl").arg("-n").arg(param).output() {
                if let Ok(value) = String::from_utf8(output.stdout) {
                    let value = value.trim();
                    if value != expected {
                        issues.push(format!("{} = {} (expected {})", param, value, expected));
                    }
                }
            }
        }

        if issues.is_empty() {
            println!("    Sysctl security parameters are properly configured");
        } else {
            println!("    Sysctl security issues:");
            for issue in issues {
                println!("       {}", issue);
            }
        }

        Ok(())
    }
}