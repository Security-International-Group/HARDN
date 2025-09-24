use std::process::Command;

/// Network and communications monitoring
pub mod network {
    use super::*;

    #[allow(dead_code)]
    pub fn check_listening_sockets() -> Result<(), Box<dyn std::error::Error>> {
        println!("  Checking listening network sockets...");

        // Check listening ports
        if let Ok(output) = Command::new("ss")
            .args(&["-lntup", "--no-header"])
            .output()
        {
            let output_str = String::from_utf8_lossy(&output.stdout);
            let listening_count = output_str.lines().count();

            println!("    {} listening sockets found", listening_count);

            // Check for suspicious ports
            let suspicious_ports = vec![23, 21, 25, 53, 139, 445]; // telnet, ftp, smtp, dns, samba
            let mut found_suspicious = Vec::new();

            for line in output_str.lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 5 {
                    if let Some(port_part) = parts[4].split(':').last() {
                        if let Ok(port) = port_part.parse::<u16>() {
                            if suspicious_ports.contains(&port) {
                                found_suspicious.push(format!("Port {} ({})", port, parts[0]));
                            }
                        }
                    }
                }
            }

            if !found_suspicious.is_empty() {
                println!("    Suspicious listening ports:");
                for port in found_suspicious {
                    println!("       {}", port);
                }
            }
        }

        Ok(())
    }

    #[allow(dead_code)]
    pub fn check_firewall_rules() -> Result<(), Box<dyn std::error::Error>> {
        println!("  Checking firewall configuration...");

        // Check ufw status
        if let Ok(output) = Command::new("ufw").arg("status").output() {
            let output_str = String::from_utf8_lossy(&output.stdout);
            if output_str.contains("inactive") {
                println!("    UFW firewall is inactive");
            } else {
                println!("    UFW firewall is active");
            }
        } else {
            println!("    UFW not available");
        }

        // Check iptables rules
        if let Ok(output) = Command::new("iptables").args(&["-L", "-n"]).output() {
            let output_str = String::from_utf8_lossy(&output.stdout);
            let rule_count = output_str.lines()
                .filter(|line| line.contains("ACCEPT") || line.contains("DROP"))
                .count();

            println!("    {} iptables rules configured", rule_count);
        }

        Ok(())
    }
}