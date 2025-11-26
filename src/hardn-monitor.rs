use chrono::Utc;
use serde_json::Value;
use std::env;
use std::fs;
use std::io::Write;
use std::process::{Command, Stdio};
use std::sync::{Mutex, OnceLock};
use std::thread;
use std::time::Duration;

fn log_message(level: &str, message: &str) {
    let timestamp = Utc::now().format("%Y-%m-%d %H:%M:%S");
    let log_entry = format!("[{}] [{}] {}\n", timestamp, level, message);

    // Ensure log directory exists so the first log line doesn't fail
    let _ = fs::create_dir_all("/var/log/hardn");

    // Log to file
    if let Ok(mut file) = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open("/var/log/hardn/hardn-monitor.log")
    {
        let _ = file.write_all(log_entry.as_bytes());
    }

    // Also log to stderr for systemd
    eprintln!("{}", log_entry.trim());
}

fn check_service_status(service: &str) -> Result<String, std::io::Error> {
    let output = Command::new("systemctl")
        .args(["is-active", "--quiet", service])
        .output()?;

    if output.status.success() {
        Ok("running".to_string())
    } else {
        Ok("stopped".to_string())
    }
}

fn restart_service(service: &str) -> Result<(), std::io::Error> {
    log_message(
        "WARN",
        &format!("{} is stopped - attempting restart", service),
    );

    let output = Command::new("systemctl")
        .args(["restart", service])
        .output()?;

    if output.status.success() {
        log_message("INFO", &format!("Successfully restarted {}", service));
    } else {
        log_message("ERROR", &format!("Failed to restart {}", service));
    }

    Ok(())
}

fn service_exists(service: &str) -> bool {
    match Command::new("systemctl")
        .args(["status", service])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
    {
        Ok(status) => {
            if let Some(code) = status.code() {
                matches!(code, 0 | 3)
            } else {
                status.success()
            }
        }
        Err(_) => false,
    }
}

fn systemd_running_state() -> String {
    match Command::new("systemctl")
        .args(["is-system-running"])
        .output()
    {
        Ok(result) => {
            let value = String::from_utf8_lossy(&result.stdout).trim().to_string();
            if value.is_empty() {
                if result.status.success() {
                    "running".to_string()
                } else {
                    "unknown".to_string()
                }
            } else {
                value
            }
        }
        Err(_) => "unknown".to_string(),
    }
}

fn service_active_state(service: &str) -> String {
    match Command::new("systemctl")
        .args(["show", service, "--property=ActiveState", "--value"])
        .output()
    {
        Ok(result) if result.status.success() => {
            let value = String::from_utf8_lossy(&result.stdout).trim().to_string();
            if value.is_empty() {
                "unknown".to_string()
            } else {
                value
            }
        }
        _ => "unknown".to_string(),
    }
}

fn count_failed_units() -> Option<usize> {
    let output = Command::new("systemctl")
        .args([
            "list-units",
            "--type=service",
            "--state=failed",
            "--no-legend",
            "--plain",
        ])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let count = text.lines().filter(|line| !line.trim().is_empty()).count();
    Some(count)
}

fn count_systemd_jobs() -> Option<usize> {
    let output = Command::new("systemctl")
        .args(["list-jobs", "--no-legend"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let count = text.lines().filter(|line| !line.trim().is_empty()).count();
    Some(count)
}

fn parse_size_to_mb(token: &str) -> Option<f64> {
    let cleaned = token
        .trim()
        .trim_start_matches('(')
        .trim_end_matches(&[')', '.', ','][..]);
    if cleaned.is_empty() {
        return None;
    }

    let split_index = cleaned
        .char_indices()
        .find(|(_, c)| c.is_ascii_alphabetic())
        .map(|(i, _)| i);

    let (number_part, unit_part) = if let Some(idx) = split_index {
        cleaned.split_at(idx)
    } else {
        (cleaned, "")
    };

    let number = number_part.trim().parse::<f64>().ok()?;
    let unit = unit_part.trim().to_ascii_uppercase();

    let multiplier = match unit.as_str() {
        "" | "B" => 1.0 / (1024.0 * 1024.0),
        "K" | "KB" | "KIB" => 1.0 / 1024.0,
        "M" | "MB" | "MIB" => 1.0,
        "G" | "GB" | "GIB" => 1024.0,
        "T" | "TB" | "TIB" => 1024.0 * 1024.0,
        _ => return None,
    };

    Some(number * multiplier)
}

fn journal_disk_usage_mb() -> Option<f64> {
    let output = Command::new("journalctl")
        .args(["--disk-usage"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout);
    for token in text.split_whitespace() {
        if let Some(value) = parse_size_to_mb(token) {
            return Some(value);
        }
    }
    None
}

fn networkd_summary() -> Option<(usize, usize, usize)> {
    let output = Command::new("networkctl")
        .args(["list", "--no-legend"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let mut total = 0usize;
    let mut online = 0usize;
    let mut degraded = 0usize;

    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        total += 1;
        let cols: Vec<&str> = trimmed.split_whitespace().collect();
        if cols.len() >= 4 {
            let operational = cols[3].to_lowercase();
            if !matches!(
                operational.as_str(),
                "off" | "down" | "no-carrier" | "failed" | "unknown" | "dormant"
            ) {
                online += 1;
            }
            if operational == "degraded" {
                degraded += 1;
            }
        }
    }

    Some((total, online, degraded))
}

fn log_core_services() {
    let systemd_state = systemd_running_state();
    let networkd_state = service_active_state("systemd-networkd.service");
    let journald_state = service_active_state("systemd-journald.service");

    log_message(
        "INFO",
        &format!(
            "Core Services - systemd={} networkd={} journald={}",
            systemd_state, networkd_state, journald_state
        ),
    );
}

fn log_systemd_metrics() {
    let failed_units = count_failed_units();
    let jobs = count_systemd_jobs();

    if failed_units.is_some() || jobs.is_some() {
        log_message(
            "INFO",
            &format!(
                "Systemd Metrics - failed_units={} queued_jobs={}",
                failed_units.unwrap_or(0),
                jobs.unwrap_or(0)
            ),
        );
    }
}

fn log_journal_metrics() {
    if let Some(usage_mb) = journal_disk_usage_mb() {
        log_message(
            "INFO",
            &format!("Journal Metrics - disk_usage_mb={:.1}", usage_mb),
        );
    }
}

fn log_networkd_metrics() {
    if let Some((total, online, degraded)) = networkd_summary() {
        log_message(
            "INFO",
            &format!(
                "Networkd Metrics - links={} online={} degraded={}",
                total, online, degraded
            ),
        );
    }
}

fn monitor_services() {
    // Services that HARDN monitor should track and auto-heal
    let services = vec![
        ("hardn.service", "hardn"),
        ("hardn-api.service", "hardn-api"),
        ("legion-daemon.service", "legion"),
    ];

    let mut status_messages = Vec::new();

    for (service, alias) in &services {
        if !service_exists(service) {
            log_message(
                "WARN",
                &format!(
                    "Service {} not present on this host; skipping health check",
                    service
                ),
            );
            continue;
        }
        match check_service_status(service) {
            Ok(status) => {
                status_messages.push(format!("{}:{}", alias, status));

                if status == "stopped" {
                    let _ = restart_service(service);
                }
            }
            Err(e) => {
                log_message(
                    "WARN",
                    &format!("Unable to determine status of {}: {}", service, e),
                );
            }
        }
    }

    // Also report the monitor daemon itself for GUI badges.
    // This process *is* hardn-monitor, so if we're running, it's "running".
    status_messages.push("hardn-monitor:running".to_string());

    if !status_messages.is_empty() {
        log_message(
            "INFO",
            &format!("Service Status - {}", status_messages.join(", ")),
        );
    }
}

fn check_api_health() -> Result<(), std::io::Error> {
    // Simple health check for the API
    let output = Command::new("curl")
        .args(["-s", "--max-time", "5", "http://localhost:8000/health"])
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

fn read_cpu_times() -> Option<(u64, u64)> {
    let contents = fs::read_to_string("/proc/stat").ok()?;
    let first_line = contents.lines().next()?;
    if !first_line.starts_with("cpu ") {
        return None;
    }

    let mut values = first_line
        .split_whitespace()
        .skip(1)
        .filter_map(|v| v.parse::<u64>().ok());
    let user = values.next()?;
    let nice = values.next()?;
    let system = values.next()?;
    let idle = values.next()?;
    let iowait = values.next().unwrap_or(0);
    let irq = values.next().unwrap_or(0);
    let softirq = values.next().unwrap_or(0);
    let steal = values.next().unwrap_or(0);
    let guest = values.next().unwrap_or(0);
    let guest_nice = values.next().unwrap_or(0);

    let idle_total = idle + iowait;
    let total = user
        .saturating_add(nice)
        .saturating_add(system)
        .saturating_add(idle)
        .saturating_add(iowait)
        .saturating_add(irq)
        .saturating_add(softirq)
        .saturating_add(steal)
        .saturating_add(guest)
        .saturating_add(guest_nice);

    Some((total, idle_total))
}

fn calculate_cpu_usage() -> Option<f64> {
    static PREV_SNAPSHOT: OnceLock<Mutex<Option<(u64, u64)>>> = OnceLock::new();
    let (current_total, current_idle) = read_cpu_times()?;
    let state = PREV_SNAPSHOT.get_or_init(|| Mutex::new(None));

    let mut guard = state.lock().ok()?;
    if let Some((prev_total, prev_idle)) = *guard {
        let total_delta = current_total.saturating_sub(prev_total);
        let idle_delta = current_idle.saturating_sub(prev_idle);
        *guard = Some((current_total, current_idle));
        if total_delta == 0 {
            return None;
        }
        Some(((total_delta - idle_delta) as f64 / total_delta as f64) * 100.0)
    } else {
        *guard = Some((current_total, current_idle));
        None
    }
}

fn read_memory_percent() -> Option<f64> {
    let contents = fs::read_to_string("/proc/meminfo").ok()?;
    let mut total_kb = None;
    let mut available_kb = None;

    for line in contents.lines() {
        if line.starts_with("MemTotal:") {
            total_kb = line
                .split_whitespace()
                .nth(1)
                .and_then(|v| v.parse::<u64>().ok());
        } else if line.starts_with("MemAvailable:") {
            available_kb = line
                .split_whitespace()
                .nth(1)
                .and_then(|v| v.parse::<u64>().ok());
        }

        if total_kb.is_some() && available_kb.is_some() {
            break;
        }
    }

    let total = total_kb? as f64;
    let available = available_kb? as f64;
    if total <= 0.0 {
        return None;
    }

    Some((1.0 - (available / total)) * 100.0)
}

fn read_load_average() -> Option<(f64, f64, f64)> {
    let contents = fs::read_to_string("/proc/loadavg").ok()?;
    let mut parts = contents.split_whitespace();
    let l1 = parts.next()?.parse::<f64>().ok()?;
    let l5 = parts.next()?.parse::<f64>().ok()?;
    let l15 = parts.next()?.parse::<f64>().ok()?;
    Some((l1, l5, l15))
}

fn capture_local_metrics() -> Option<(f64, f64, (f64, f64, f64))> {
    let cpu = calculate_cpu_usage();
    let mem = read_memory_percent();
    let load = read_load_average();

    if cpu.is_none() && mem.is_none() && load.is_none() {
        return None;
    }

    Some((
        cpu.unwrap_or(0.0),
        mem.unwrap_or(0.0),
        load.unwrap_or((0.0, 0.0, 0.0)),
    ))
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
    let output = Command::new("curl").args(args).output();

    let mut logged = false;

    if let Ok(result) = output {
        if result.status.success() {
            if let Ok(text) = String::from_utf8(result.stdout) {
                if let Ok(json) = serde_json::from_str::<Value>(&text) {
                    let cpu = json
                        .get("system_health")
                        .and_then(|h| h.get("cpu_percent"))
                        .and_then(|v| v.as_f64());
                    let mem = json
                        .get("system_health")
                        .and_then(|h| h.get("memory"))
                        .and_then(|m| m.get("percent"))
                        .and_then(|v| v.as_f64());
                    let load = json
                        .get("system_health")
                        .and_then(|h| h.get("load_average"))
                        .and_then(|v| v.as_array())
                        .map(|arr| {
                            let l1 = arr.first().and_then(|v| v.as_f64()).unwrap_or(0.0);
                            let l5 = arr.get(1).and_then(|v| v.as_f64()).unwrap_or(0.0);
                            let l15 = arr.get(2).and_then(|v| v.as_f64()).unwrap_or(0.0);
                            (l1, l5, l15)
                        });

                    if cpu.is_some() || mem.is_some() || load.is_some() {
                        let (l1, l5, l15) = load.unwrap_or((0.0, 0.0, 0.0));
                        log_message(
                            "INFO",
                            &format!(
                                "Metrics - cpu={:.1}% mem={:.1}% load={:.2},{:.2},{:.2}",
                                cpu.unwrap_or(0.0),
                                mem.unwrap_or(0.0),
                                l1,
                                l5,
                                l15
                            ),
                        );
                        logged = true;
                    }
                }
            }
        }
    }

    if !logged {
        if let Some((cpu, mem, (l1, l5, l15))) = capture_local_metrics() {
            log_message(
                "INFO",
                &format!(
                    "Metrics - cpu={:.1}% mem={:.1}% load={:.2},{:.2},{:.2}",
                    cpu, mem, l1, l5, l15
                ),
            );
        } else {
            log_message(
                "DEBUG",
                "Local metrics unavailable; skipping GUI metrics update this cycle",
            );
        }
    }
}

fn log_database_metrics() {
    // Query journalctl for recent LEGION SUMMARY lines to extract database metrics
    let output = Command::new("journalctl")
        .args(["-u", "legion-daemon", "-n", "10", "-o", "cat", "--no-pager"])
        .output();

    if let Ok(result) = output {
        if result.status.success() {
            if let Ok(logs) = String::from_utf8(result.stdout) {
                // Look for the most recent LEGION SUMMARY line
                for line in logs.lines().rev() {
                    if line.contains("LEGION SUMMARY:") && line.contains(" db=[") {
                        if let Some(db_part) = line.split(" db=[").nth(1) {
                            if let Some(db_info) = db_part.split(']').next() {
                                if db_info == "not_initialized" {
                                    log_message("INFO", "Database - status=not_initialized (waiting for first baseline)");
                                } else {
                                    // Parse database info: baselines=X,anomalies=Y,latest_age=Z,size=W
                                    let mut baselines = 0i64;
                                    let mut anomalies = 0i64;
                                    let mut db_size_mb = 0.0f64;

                                    for part in db_info.split(',') {
                                        if let Some((key, value)) = part.split_once('=') {
                                            match key {
                                                "baselines" => {
                                                    if let Ok(val) = value.parse::<i64>() {
                                                        baselines = val;
                                                    }
                                                }
                                                "anomalies" => {
                                                    if let Ok(val) = value.parse::<i64>() {
                                                        anomalies = val;
                                                    }
                                                }
                                                "size" => {
                                                    if let Some(size_str) = value.strip_suffix("MB")
                                                    {
                                                        if let Ok(val) = size_str.parse::<f64>() {
                                                            db_size_mb = val;
                                                        }
                                                    }
                                                }
                                                _ => {}
                                            }
                                        }
                                    }

                                    log_message(
                                        "INFO",
                                        &format!(
                                            "Database - status=healthy baselines={} anomalies={} size={:.1}MB",
                                            baselines, anomalies, db_size_mb
                                        ),
                                    );
                                }
                                return; // Found and processed the most recent summary
                            }
                        }
                    }
                }
                // If we get here, no database info was found in recent logs
                log_message(
                    "DEBUG",
                    "Database - no recent summary found in legion-daemon logs",
                );
            }
        } else {
            log_message("WARN", "Failed to query legion-daemon journal logs");
        }
    } else {
        log_message(
            "WARN",
            "Failed to execute journalctl for legion-daemon logs",
        );
    }
}

fn main() {
    log_message("INFO", "HARDN Centralized Monitor starting");


    let _ = fs::create_dir_all("/var/log/hardn");
    let _ = fs::create_dir_all("/var/run");
    if let Ok(pid) = std::process::id().to_string().parse::<u32>() {
        let _ = fs::write("/var/run/hardn-monitor.pid", pid.to_string());
    }

    monitor_services();

    log_message("INFO", "Entering monitoring loop");

    loop {
        // Check services every 30 seconds
        monitor_services();

        // Core 
        log_core_services();
        log_systemd_metrics();
        log_journal_metrics();
        log_networkd_metrics();
        let _ = check_api_health();
        log_metrics_from_api();
        log_database_metrics();
        log_message("DEBUG", "Monitoring inter-service communication channels");


        thread::sleep(Duration::from_secs(30));
    }
}