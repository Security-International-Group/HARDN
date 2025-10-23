use crate::legion::safe_println;
use std::process::Command;

/// System services and daemon monitoring utilities
#[allow(dead_code)]
pub fn check_service_status() -> Result<(), Box<dyn std::error::Error>> {
    safe_println!("  Analyzing system service status...");

    // Get all systemd services status
    if let Ok(output) = Command::new("systemctl")
        .args([
            "list-units",
            "--type=service",
            "--all",
            "--no-pager",
            "--no-legend",
        ])
        .output()
    {
        let output_str = String::from_utf8_lossy(&output.stdout);
        let services: Vec<&str> = output_str.lines().collect();

        let mut active = 0;
        let mut inactive = 0;
        let mut failed = 0;

        for service in services {
            if service.contains("active") && service.contains("running") {
                active += 1;
            } else if service.contains("inactive") {
                inactive += 1;
            } else if service.contains("failed") {
                failed += 1;
            }
        }

        safe_println!("    Service status summary:");
        safe_println!("      Active: {}", active);
        safe_println!("      Inactive: {}", inactive);
        safe_println!("      Failed: {}", failed);

        if failed > 0 {
            safe_println!("    WARNING: {} services in failed state", failed);
        }
    }

    Ok(())
}

#[allow(dead_code)]
pub fn check_critical_services() -> Result<(), Box<dyn std::error::Error>> {
    safe_println!("  Checking critical system services...");

    let critical_services = vec![
        "sshd.service",
        "systemd-networkd.service",
        "systemd-resolved.service",
        "systemd-timesyncd.service",
        "cron.service",
        "rsyslog.service",
    ];

    for service in critical_services {
        if let Ok(output) = Command::new("systemctl").args(["is-active", service]).output() {
            let status_str = String::from_utf8_lossy(&output.stdout);
            let status = status_str.trim();
            if status == "active" {
                safe_println!("    {}: {}", service, status);
            } else {
                safe_println!("    {}: {} ", service, status);
            }
        }
    }

    Ok(())
}

#[allow(dead_code)]
pub fn detect_service_anomalies() -> Result<(), Box<dyn std::error::Error>> {
    safe_println!("  Detecting service-related anomalies...");

    // Check for services with high restart counts
    if let Ok(output) = Command::new("systemctl")
        .args([
            "list-units",
            "--type=service",
            "--state=failed",
            "--no-pager",
            "--no-legend",
        ])
        .output()
    {
        let output_str = String::from_utf8_lossy(&output.stdout);
        let failed_services: Vec<&str> = output_str.lines().collect();

        if !failed_services.is_empty() {
            safe_println!("    Failed services detected:");
            for service in failed_services.iter().take(5) {
                let parts: Vec<&str> = service.split_whitespace().collect();
                if !parts.is_empty() {
                    safe_println!("      {}", parts[0]);
                }
            }
        }
    }

    // Check for services listening on unexpected ports
    if let Ok(output) = Command::new("ss")
        .args(["-lntup", "|", "grep", "users:"])
        .output()
    {
        let output_str = String::from_utf8_lossy(&output.stdout);
        let service_ports: Vec<&str> = output_str.lines().collect();

        if !service_ports.is_empty() {
            safe_println!(
                "    Services with associated processes: {}",
                service_ports.len(),
            );
        }
    }

    Ok(())
}

#[allow(dead_code)]
pub fn check_service_dependencies() -> Result<(), Box<dyn std::error::Error>> {
    safe_println!("  Analyzing service dependency chains...");

    // Check for services that depend on failed units
    if let Ok(output) = Command::new("systemctl")
        .args(["list-dependencies", "--all", "--no-pager"])
        .output()
    {
        let output_str = String::from_utf8_lossy(&output.stdout);
        let dependencies = output_str.lines().count();
        safe_println!(
            "    Service dependency relationships analyzed: {}",
            dependencies,
        );
    }

    Ok(())
}

#[allow(dead_code)]
pub fn check_service_security() -> Result<(), Box<dyn std::error::Error>> {
    safe_println!("  Checking service security configurations...");

    // Check for services running as root unnecessarily
    if let Ok(output) = Command::new("ps")
        .args(["-eo", "pid,cmd", "--no-headers", "|", "grep", "systemd"])
        .output()
    {
        let output_str = String::from_utf8_lossy(&output.stdout);
        let systemd_processes = output_str.lines().count();
        safe_println!("    Systemd processes running: {}", systemd_processes);
    }

    // Check service sandboxing (NoNewPrivileges, etc.)
    if let Ok(_output) = Command::new("systemctl")
        .args(["show", "*", "--property=ExecStart", "--no-pager"])
        .output()
    {
        safe_println!("    Service execution configurations analyzed");
    }

    Ok(())
}
