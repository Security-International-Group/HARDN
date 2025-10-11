use std::fs;

use crate::legion::core::framework::{
    CollectionContext, FrameworkError, TelemetryCategory, TelemetryPayload, TelemetryRecord,
    TelemetrySource,
};

#[derive(Debug, Default, Clone)]
pub struct MemoryTelemetrySource;

impl TelemetrySource for MemoryTelemetrySource {
    fn id(&self) -> &'static str {
        "memory"
    }

    fn collect(
        &mut self,
        _context: &CollectionContext<'_>,
    ) -> Result<Vec<TelemetryRecord>, FrameworkError> {
        read_memory_usage()
            .map(|usage| {
                vec![TelemetryRecord::new(
                    "memory",
                    TelemetryCategory::Resource,
                    TelemetryPayload::Metric {
                        name: "memory_usage".to_string(),
                        value: usage,
                        unit: Some("ratio".to_string()),
                    },
                )]
            })
            .map_err(|e| FrameworkError::collection(self.id(), e))
    }
}

pub fn read_memory_usage() -> Result<f64, String> {
    let meminfo = fs::read_to_string("/proc/meminfo").map_err(|e| e.to_string())?;
    parse_memory_usage(&meminfo)
}

pub fn parse_memory_usage(meminfo: &str) -> Result<f64, String> {
    let mut total = None;
    let mut available = None;

    for line in meminfo.lines() {
        if line.starts_with("MemTotal:") {
            total = line
                .split_whitespace()
                .nth(1)
                .and_then(|val| val.parse::<u64>().ok());
        } else if line.starts_with("MemAvailable:") {
            available = line
                .split_whitespace()
                .nth(1)
                .and_then(|val| val.parse::<u64>().ok());
        }

        if total.is_some() && available.is_some() {
            break;
        }
    }

    let total = total.ok_or_else(|| "meminfo missing MemTotal".to_string())?;
    let available = available.ok_or_else(|| "meminfo missing MemAvailable".to_string())?;

    if total == 0 {
        return Ok(0.0);
    }

    let used = total.saturating_sub(available);
    Ok((used as f64 / total as f64).clamp(0.0, 1.0))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_memory_usage_from_samples() {
        let sample = "MemTotal:       100000 kB\nMemAvailable:   25000 kB\n";
        let usage = parse_memory_usage(sample).expect("parse succeeds");
        assert!((usage - 0.75).abs() < f64::EPSILON);
    }
}
