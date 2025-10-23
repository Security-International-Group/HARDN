use std::process::Command;

/// Memory and resource monitoring
#[allow(clippy::module_inception)]
pub mod memory {
    use super::*;

    #[allow(dead_code)]
    pub fn check_memory_usage() -> Result<(), Box<dyn std::error::Error>> {
        safe_println!("  Analyzing memory usage patterns...");

        // Check overall memory usage
        if let Ok(output) = Command::new("free").arg("-h").output() {
            let output_str = String::from_utf8_lossy(&output.stdout);
            safe_println!("    Memory usage:");
            for line in output_str.lines().skip(1) {
                safe_println!("      {}", line);
            }
        }

        // Check for memory-intensive processes
        if let Ok(output) = Command::new("ps")
            .args(["aux", "--sort", "-%mem", "-h", "-n", "10"])
            .output()
        {
            let output_str = String::from_utf8_lossy(&output.stdout);
            let lines: Vec<&str> = output_str.lines().collect();
            if lines.len() > 5 {
                safe_println!("    Top memory-consuming processes:");
                for (i, line) in lines.iter().enumerate().take(5) {
                    if i > 0 {
                        // Skip header
                        let parts: Vec<&str> = line.split_whitespace().collect();
                        if parts.len() >= 4 {
                            let mem_usage = parts[3];
                            let cmd = parts[10..].join(" ");
                            safe_println!("      {}% - {}", mem_usage, cmd);
                        }
                    }
                }
            }
        }

        Ok(())
    }

    #[allow(dead_code)]
    pub fn check_swap_usage() -> Result<(), Box<dyn std::error::Error>> {
        safe_println!("  Checking swap space usage...");

        if let Ok(output) = Command::new("swapon").arg("--show").output() {
            let output_str = String::from_utf8_lossy(&output.stdout);
            let lines: Vec<&str> = output_str.lines().collect();
            if lines.len() > 1 {
                safe_println!("    Swap devices:");
                for line in lines.iter().skip(1) {
                    safe_println!("      {}", line);
                }
            } else {
                safe_println!("    No swap devices configured");
            }
        }

        Ok(())
    }

    #[allow(dead_code)]
    pub fn detect_memory_anomalies() -> Result<(), Box<dyn std::error::Error>> {
        safe_println!("  Detecting memory-related anomalies...");

        // Check for OOM killer activity
        if let Ok(output) = Command::new("journalctl")
            .args([
                "--since",
                "1 hour ago",
                "--grep",
                "Out of memory",
                "--no-pager",
            ])
            .output()
        {
            let output_str = String::from_utf8_lossy(&output.stdout);
            let oom_events = output_str.lines().count();
            if oom_events > 0 {
                safe_println!(
                    "    WARNING: {} Out of Memory events detected in last hour",
                    oom_events
                );
            }
        }

        // Check for memory leaks (processes with growing memory usage)
        if let Ok(output) = Command::new("ps")
            .args(["-eo", "pid,cmd,rss,vsz", "--no-headers"])
            .output()
        {
            let output_str = String::from_utf8_lossy(&output.stdout);
            let mut high_memory_processes = Vec::new();

            for line in output_str.lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 4 {
                    if let Ok(rss_kb) = parts[2].parse::<u64>() {
                        let rss_mb = rss_kb / 1024;
                        if rss_mb > 500 {
                            // Processes using more than 500MB
                            let cmd = parts[1..].join(" ");
                            high_memory_processes.push((rss_mb, cmd));
                        }
                    }
                }
            }

            if !high_memory_processes.is_empty() {
                safe_println!("    High memory usage processes (>500MB):");
                for (mem, cmd) in high_memory_processes.iter().take(5) {
                    safe_println!("      {}MB - {}", mem, cmd);
                }
            }
        }

        Ok(())
    }
}
