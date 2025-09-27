use std::fs;
use std::process::Command;

/// System inventory and information collection
pub mod inventory {
    use super::*;

    #[allow(dead_code)]
    pub fn check_system_info() -> Result<(), Box<dyn std::error::Error>> {
        eprintln!("  System Information:");

        // OS Information
        if let Ok(content) = fs::read_to_string("/etc/os-release") {
            for line in content.lines() {
                if line.starts_with("PRETTY_NAME=") {
                    let name = line.split_once('=').unwrap().1.trim_matches('"');
                    eprintln!("    OS: {}", name);
                    break;
                }
            }
        }

        // Kernel version
        if let Ok(output) = Command::new("uname").arg("-r").output() {
            if let Ok(version) = String::from_utf8(output.stdout) {
                eprintln!("    Kernel: {}", version.trim());
            }
        }

        // Architecture
        if let Ok(output) = Command::new("uname").arg("-m").output() {
            if let Ok(arch) = String::from_utf8(output.stdout) {
                eprintln!("     Architecture: {}", arch.trim());
            }
        }

        // Hostname
        if let Ok(output) = Command::new("hostname").output() {
            if let Ok(hostname) = String::from_utf8(output.stdout) {
                eprintln!("      Hostname: {}", hostname.trim());
            }
        }

        Ok(())
    }

    #[allow(dead_code)]
    pub fn check_hardware_info() -> Result<(), Box<dyn std::error::Error>> {
        eprintln!("  Hardware Information:");

        // CPU info
        if let Ok(content) = fs::read_to_string("/proc/cpuinfo") {
            let mut model_name = String::new();
            let mut cpu_count = 0;

            for line in content.lines() {
                if line.starts_with("model name") {
                    if let Some(name) = line.split_once(':').map(|(_, n)| n.trim()) {
                        model_name = name.to_string();
                    }
                }
                if line.starts_with("processor") {
                    cpu_count += 1;
                }
            }

            if !model_name.is_empty() {
                eprintln!("    CPU: {} ({} cores)", model_name, cpu_count);
            }
        }

        // Memory info
        if let Ok(content) = fs::read_to_string("/proc/meminfo") {
            for line in content.lines() {
                if line.starts_with("MemTotal:") {
                    if let Some(mem_str) = line.split_once(':').map(|(_, m)| m.trim()) {
                        let mem_kb: u64 = mem_str.split_whitespace()
                            .next()
                            .and_then(|s| s.parse().ok())
                            .unwrap_or(0);
                        let mem_gb = mem_kb / 1024 / 1024;
                        eprintln!("    Memory: {} GB", mem_gb);
                    }
                    break;
                }
            }
        }

        // Virtualization check
        if let Ok(output) = Command::new("systemd-detect-virt").output() {
            if let Ok(virt) = String::from_utf8(output.stdout) {
                let virt = virt.trim();
                if virt != "none" {
                    eprintln!("    Virtualization: {}", virt);
                }
            }
        }

        Ok(())
    }
}