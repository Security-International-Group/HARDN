use std::process::Command;

/// Network and communications monitoring
#[allow(clippy::module_inception)]
pub mod network {
    use super::*;

    #[allow(dead_code)]
    pub fn check_listening_sockets() -> Result<(), Box<dyn std::error::Error>> {
        eprintln!("  Checking listening network sockets...");

        // Check listening ports
    if let Ok(output) = Command::new("ss").args(["-lntup", "--no-header"]).output() {
            let output_str = String::from_utf8_lossy(&output.stdout);
            let listening_count = output_str.lines().count();

            eprintln!("    {} listening sockets found", listening_count);

            // Check for suspicious ports
            let suspicious_ports = [23, 21, 25, 53, 139, 445]; // telnet, ftp, smtp, dns, samba
            let mut found_suspicious = Vec::new();

            for line in output_str.lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 5 {
                    if let Some(port_part) = parts[4].split(':').next_back() {
                        if let Ok(port) = port_part.parse::<u16>() {
                            if suspicious_ports.contains(&port) {
                                found_suspicious.push(format!("Port {} ({})", port, parts[0]));
                            }
                        }
                    }
                }
            }

            if !found_suspicious.is_empty() {
                eprintln!("    Suspicious listening ports:");
                for port in found_suspicious {
                    eprintln!("       {}", port);
                }
            }
        }

        Ok(())
    }

    #[allow(dead_code)]
    pub fn check_firewall_rules() -> Result<(), Box<dyn std::error::Error>> {
        eprintln!("  Checking firewall configuration...");

        // Check ufw status
        if let Ok(output) = Command::new("ufw").arg("status").output() {
            let output_str = String::from_utf8_lossy(&output.stdout);
            if output_str.contains("inactive") {
                eprintln!("    UFW firewall is inactive");
            } else {
                eprintln!("    UFW firewall is active");
            }
        } else {
            eprintln!("    UFW not available");
        }

        // Check iptables rules
    if let Ok(output) = Command::new("iptables").args(["-L", "-n"]).output() {
            let output_str = String::from_utf8_lossy(&output.stdout);
            let rule_count = output_str
                .lines()
                .filter(|line| line.contains("ACCEPT") || line.contains("DROP"))
                .count();

            eprintln!("    {} iptables rules configured", rule_count);
        }

        Ok(())
    }
}
