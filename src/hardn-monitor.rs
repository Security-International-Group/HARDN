use std::fs;
use std::process::Command;
use std::thread;
use std::time::Duration;
use std::io::Write;
use chrono::Utc;

fn log_message(level: &str, message: &str) {
    let timestamp = Utc::now().format("%Y-%m-%d %H:%M:%S");
    let log_entry = format!("[{}] [{}] {}\n", timestamp, level, message);

    // Log to file
    if let Ok(mut file) = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open("/var/log/hardn/hardn-monitor.log") {
        let _ = file.write_all(log_entry.as_bytes());
    }

    // Also log to stderr for systemd
    eprintln!("{}", log_entry.trim());
}

fn check_service_status(service: &str) -> Result<String, std::io::Error> {
    let output = Command::new("systemctl")
        .args(&["is-active", "--quiet", service])
        .output()?;

    if output.status.success() {
        Ok("running".to_string())
    } else {
        Ok("stopped".to_string())
    }
}

fn restart_service(service: &str) -> Result<(), std::io::Error> {
    log_message("WARN", &format!("{} is stopped - attempting restart", service));

    let output = Command::new("systemctl")
        .args(&["restart", service])
        .output()?;

    if output.status.success() {
        log_message("INFO", &format!("Successfully restarted {}", service));
    } else {
        log_message("ERROR", &format!("Failed to restart {}", service));
    }

    Ok(())
}

fn monitor_services() {
    let services = vec![
        "hardn.service",
        "hardn-api.service",
        "legion-daemon.service"
    ];

    let mut status_messages = Vec::new();

    for service in &services {
        match check_service_status(service) {
            Ok(status) => {
                status_messages.push(format!("{}:{}", service.replace(".service", ""), status));

                if status == "stopped" {
                    let _ = restart_service(service);
                }
            }
            Err(e) => {
                log_message("ERROR", &format!("Failed to check status of {}: {}", service, e));
            }
        }
    }

    log_message("INFO", &format!("Service Status - {}", status_messages.join(", ")));
}

fn check_api_health() -> Result<(), std::io::Error> {
    // Simple health check for the API
    let output = Command::new("curl")
        .args(&["-s", "--max-time", "5", "http://localhost:8000/health"])
        .output();

    match output {
        Ok(result) if result.status.success() => {
            log_message("INFO", "API health check passed");
        }
        _ => {
            log_message("WARN", "API health check failed");
        }
    }

    Ok(())
}

fn main() {
    log_message("INFO", "HARDN Centralized Monitor starting");

    // Create necessary directories
    let _ = fs::create_dir_all("/var/log/hardn");
    let _ = fs::create_dir_all("/var/run");

    // Write PID file
    if let Ok(pid) = std::process::id().to_string().parse::<u32>() {
        let _ = fs::write("/var/run/hardn-monitor.pid", pid.to_string());
    }

    // Initial service check
    monitor_services();

    log_message("INFO", "Entering monitoring loop");

    loop {
        // Check services every 30 seconds
        monitor_services();

        // Check API health
        let _ = check_api_health();

        // Check for inter-service communication (placeholder)
        log_message("DEBUG", "Monitoring inter-service communication channels");

        // Sleep for 30 seconds
        thread::sleep(Duration::from_secs(30));
    }
}