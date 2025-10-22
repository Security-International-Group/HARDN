use crate::legion::safe_println;
use std::process::Command;

/// USB device and peripheral monitoring utilities
#[allow(dead_code)]
pub fn check_usb_devices() -> Result<(), Box<dyn std::error::Error>> {
    safe_println!("  Checking USB devices and peripherals...");

    // Check connected USB devices
    if let Ok(output) = Command::new("lsusb").output() {
        let output_str = String::from_utf8_lossy(&output.stdout);
        let device_count = output_str.lines().count();
        safe_println!("    {} USB devices detected", device_count);

        // Look for suspicious device types
        let suspicious_keywords = vec!["keyboard", "mouse", "storage", "wireless", "bluetooth"];
        let mut suspicious_devices = Vec::new();

        for line in output_str.lines() {
            let line_lower = line.to_lowercase();
            for keyword in &suspicious_keywords {
                if line_lower.contains(keyword) {
                    suspicious_devices.push(line.to_string());
                    break;
                }
            }
        }

        if !suspicious_devices.is_empty() {
            safe_println!("    Human interface devices detected:");
            for device in suspicious_devices.iter().take(5) {
                safe_println!("      {}", device);
            }
        }
    }

    Ok(())
}

#[allow(dead_code)]
pub fn check_usb_storage() -> Result<(), Box<dyn std::error::Error>> {
    safe_println!("  Checking USB storage devices...");

    // Check for mounted USB devices
    if let Ok(output) = Command::new("mount").args(["|", "grep", "/dev/sd"]).output() {
        let output_str = String::from_utf8_lossy(&output.stdout);
        let mounted_devices: Vec<&str> = output_str.lines().collect();

        if !mounted_devices.is_empty() {
            safe_println!("    Mounted storage devices:");
            for device in mounted_devices {
                safe_println!("      {}", device);
            }
        } else {
            safe_println!("    No external storage devices mounted");
        }
    }

    // Check for USB device permissions
    if let Ok(output) = Command::new("ls").args(["-la", "/dev/bus/usb/"]).output() {
        let _output_str = String::from_utf8_lossy(&output.stdout);
        safe_println!("    USB device permissions checked");
    }

    Ok(())
}

#[allow(dead_code)]
pub fn detect_usb_anomalies() -> Result<(), Box<dyn std::error::Error>> {
    safe_println!("  Detecting USB-related security anomalies...");

    // Check for unauthorized USB device access
    if let Ok(output) = Command::new("lsof").args(["/dev/bus/usb/", "-F", "p"]).output() {
        let output_str = String::from_utf8_lossy(&output.stdout);
        let usb_access_processes: Vec<&str> = output_str
            .lines()
            .filter(|line| line.starts_with('p'))
            .collect();

        if !usb_access_processes.is_empty() {
            safe_println!(
                "    Processes accessing USB devices: {}",
                usb_access_processes.len(),
            );
        }
    }

    // Check USB kernel modules
    if let Ok(output) = Command::new("lsmod").args(["|", "grep", "usb"]).output() {
        let output_str = String::from_utf8_lossy(&output.stdout);
        let usb_modules: Vec<&str> = output_str.lines().collect();

        if !usb_modules.is_empty() {
            safe_println!("    Loaded USB kernel modules: {}", usb_modules.len());
        }
    }

    Ok(())
}

#[allow(dead_code)]
pub fn check_usb_history() -> Result<(), Box<dyn std::error::Error>> {
    safe_println!("  Checking USB device connection history...");

    // Check system logs for USB events
    if let Ok(output) = Command::new("journalctl")
        .args(["--since", "1 day ago", "--grep", "usb", "--no-pager"])
        .output()
    {
        let output_str = String::from_utf8_lossy(&output.stdout);
        let usb_events = output_str.lines().count();

        if usb_events > 0 {
            safe_println!(
                "    {} USB-related events in system logs (last 24h)",
                usb_events,
            );
        }
    }

    Ok(())
}
