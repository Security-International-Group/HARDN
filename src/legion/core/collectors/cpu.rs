use std::fs;
use std::thread;
use std::time::Duration;

use crate::legion::core::framework::{
    CollectionContext, FrameworkError, TelemetryCategory, TelemetryPayload, TelemetryRecord,
    TelemetrySource,
};

#[derive(Debug, Clone)]
pub struct CpuTelemetrySource {
    sample_interval: Duration,
}

impl CpuTelemetrySource {
    #[allow(dead_code)]
    pub fn new(sample_interval: Duration) -> Self {
        Self { sample_interval }
    }
}

impl Default for CpuTelemetrySource {
    fn default() -> Self {
        Self {
            sample_interval: Duration::from_millis(100),
        }
    }
}

impl TelemetrySource for CpuTelemetrySource {
    fn id(&self) -> &'static str {
        "cpu"
    }

    fn collect(
        &mut self,
        _context: &CollectionContext<'_>,
    ) -> Result<Vec<TelemetryRecord>, FrameworkError> {
        read_cpu_usage(self.sample_interval)
            .map(|usage| {
                vec![TelemetryRecord::new(
                    "cpu",
                    TelemetryCategory::Resource,
                    TelemetryPayload::Metric {
                        name: "cpu_usage".to_string(),
                        value: usage,
                        unit: Some("ratio".to_string()),
                    },
                )]
            })
            .map_err(|e| FrameworkError::collection(self.id(), e))
    }
}

pub fn read_cpu_usage(sample_interval: Duration) -> Result<f64, String> {
    let stat1 = fs::read_to_string("/proc/stat").map_err(|e| e.to_string())?;
    thread::sleep(sample_interval);
    let stat2 = fs::read_to_string("/proc/stat").map_err(|e| e.to_string())?;
    parse_cpu_usage(&stat1, &stat2)
}

pub fn parse_cpu_usage(stat1: &str, stat2: &str) -> Result<f64, String> {
    let first = stat1
        .lines()
        .next()
        .ok_or_else(|| "missing cpu line".to_string())?;
    let second = stat2
        .lines()
        .next()
        .ok_or_else(|| "missing cpu line".to_string())?;

    let parts1: Vec<&str> = first.split_whitespace().collect();
    let parts2: Vec<&str> = second.split_whitespace().collect();

    if parts1.len() < 8 || parts2.len() < 8 || parts1[0] != "cpu" || parts2[0] != "cpu" {
        return Err("invalid /proc/stat format".to_string());
    }

    let user1: u64 = parts1[1].parse::<u64>().map_err(|e| e.to_string())?;
    let nice1: u64 = parts1[2].parse::<u64>().map_err(|e| e.to_string())?;
    let system1: u64 = parts1[3].parse::<u64>().map_err(|e| e.to_string())?;
    let idle1: u64 = parts1[4].parse::<u64>().map_err(|e| e.to_string())?;
    let iowait1: u64 = parts1[5].parse::<u64>().map_err(|e| e.to_string())?;
    let irq1: u64 = parts1[6].parse::<u64>().map_err(|e| e.to_string())?;
    let softirq1: u64 = parts1[7].parse::<u64>().map_err(|e| e.to_string())?;

    let user2: u64 = parts2[1].parse::<u64>().map_err(|e| e.to_string())?;
    let nice2: u64 = parts2[2].parse::<u64>().map_err(|e| e.to_string())?;
    let system2: u64 = parts2[3].parse::<u64>().map_err(|e| e.to_string())?;
    let idle2: u64 = parts2[4].parse::<u64>().map_err(|e| e.to_string())?;
    let iowait2: u64 = parts2[5].parse::<u64>().map_err(|e| e.to_string())?;
    let irq2: u64 = parts2[6].parse::<u64>().map_err(|e| e.to_string())?;
    let softirq2: u64 = parts2[7].parse::<u64>().map_err(|e| e.to_string())?;

    let total1 = user1 + nice1 + system1 + idle1 + iowait1 + irq1 + softirq1;
    let total2 = user2 + nice2 + system2 + idle2 + iowait2 + irq2 + softirq2;

    if total2 <= total1 {
        return Err("non-monotonic cpu counters".to_string());
    }

    let total_diff = total2 - total1;
    let idle_diff = idle2 - idle1;

    if total_diff == 0 {
        return Ok(0.0);
    }

    let usage = (total_diff - idle_diff) as f64 / total_diff as f64;
    Ok(usage.clamp(0.0, 1.0))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_cpu_usage_from_samples() {
        let before = "cpu  100 200 300 400 500 600 700 0";
        let after = "cpu  200 300 400 500 600 700 800 0";
        let usage = parse_cpu_usage(before, after).expect("parse succeeds");
        assert!(usage > 0.0 && usage <= 1.0);
    }
}
