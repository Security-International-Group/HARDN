use std::fs;
use std::process::Command;
use std::thread;
use std::time::Duration;
use std::io::Write;
use chrono::Utc;
use serde_json::Value;
use std::env;

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

fn log_metrics_from_api() {
    // Query HARDN API for system metrics; keep it lightweight and resilient
    let api = "http://localhost:8000/overwatch/system";
    let mut args: Vec<String> = vec!["-s".into()];
    if let Ok(key_raw) = env::var("HARDN_API_KEY") {
        let key = key_raw.trim();
        if !key.is_empty() {
            args.push("-H".into());
            args.push(format!("Authorization: Bearer {}", key));
        }
    }
    args.push(api.into());
    let output = Command::new("curl").args(&args).output();

    if let Ok(result) = output {
        if result.status.success() {
            if let Ok(text) = String::from_utf8(result.stdout) {
                if let Ok(json) = serde_json::from_str::<Value>(&text) {
                    let cpu = json.get("system_health").and_then(|h| h.get("cpu_percent")).and_then(|v| v.as_f64()).unwrap_or(0.0);
                    let mem = json.get("system_health").and_then(|h| h.get("memory")).and_then(|m| m.get("percent")).and_then(|v| v.as_f64()).unwrap_or(0.0);
                    let load = json.get("system_health").and_then(|h| h.get("load_average"));
                    let (l1, l5, l15) = if let Some(arr) = load.and_then(|v| v.as_array()) {
                        let l1 = arr.get(0).and_then(|v| v.as_f64()).unwrap_or(0.0);
                        let l5 = arr.get(1).and_then(|v| v.as_f64()).unwrap_or(0.0);
                        let l15 = arr.get(2).and_then(|v| v.as_f64()).unwrap_or(0.0);
                        (l1, l5, l15)
                    } else { (0.0, 0.0, 0.0) };
                    log_message("INFO", &format!("Metrics - cpu={:.1}% mem={:.1}% load={:.2},{:.2},{:.2}", cpu, mem, l1, l5, l15));
                }
            }
        }
    }
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

        // Log metrics summary for GUI consumption
        log_metrics_from_api();

        // Check for inter-service communication (placeholder)
        log_message("DEBUG", "Monitoring inter-service communication channels");

        // Sleep for 30 seconds
        thread::sleep(Duration::from_secs(30));
    }
}