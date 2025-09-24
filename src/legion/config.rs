use std::env;
use std::fs;
use std::path::Path;

/// LEGION Configuration
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct Config {
    pub config_file: String,
    pub baseline_dir: String,
    pub log_file: String,
    pub create_baseline: bool,
    pub verbose: bool,
    pub json_output: bool,
    pub timeout: u64,
    pub rate_limit: u32,
}

#[allow(dead_code)]
impl Config {
    /// Load configuration from file and environment variables
    pub fn load() -> Result<Self, Box<dyn std::error::Error>> {
        let config_file = env::var("LEGION_CONFIG")
            .unwrap_or_else(|_| "/etc/hardn/legion.conf".to_string());

        let mut config = Self::default();

        // Load from config file if it exists
        if Path::new(&config_file).exists() {
            config.load_from_file(&config_file)?;
        }

        // Override with environment variables
        config.load_from_env();

        Ok(config)
    }

    fn load_from_file(&mut self, path: &str) -> Result<(), Box<dyn std::error::Error>> {
        match fs::read_to_string(path) {
            Ok(content) => {
                for line in content.lines() {
                    let line = line.trim();
                    if line.is_empty() || line.starts_with('#') {
                        continue;
                    }

                    if let Some((key, value)) = line.split_once('=') {
                        let key = key.trim();
                        let value = value.trim().trim_matches('"');

                        match key {
                            "BASELINE_DIR" => self.baseline_dir = value.to_string(),
                            "LOG_FILE" => self.log_file = value.to_string(),
                            "TIMEOUT" => self.timeout = value.parse()?,
                            "RATE_LIMIT" => self.rate_limit = value.parse()?,
                            "VERBOSE" => self.verbose = value.parse().unwrap_or(false),
                            "JSON_OUTPUT" => self.json_output = value.parse().unwrap_or(false),
                            _ => {} // Ignore unknown keys
                        }
                    }
                }
                Ok(())
            }
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                // Config file exists but we can't read it - use defaults
                Ok(())
            }
            Err(e) => Err(e.into()),
        }
    }

    fn load_from_env(&mut self) {
        if let Ok(val) = env::var("LEGION_BASELINE_DIR") {
            self.baseline_dir = val;
        }
        if let Ok(val) = env::var("LEGION_LOG_FILE") {
            self.log_file = val;
        }
        if let Ok(val) = env::var("LEGION_TIMEOUT") {
            if let Ok(timeout) = val.parse() {
                self.timeout = timeout;
            }
        }
        if let Ok(val) = env::var("LEGION_RATE_LIMIT") {
            if let Ok(rate_limit) = val.parse() {
                self.rate_limit = rate_limit;
            }
        }
        if let Ok(val) = env::var("LEGION_VERBOSE") {
            if let Ok(verbose) = val.parse() {
                self.verbose = verbose;
            }
        }
        if let Ok(val) = env::var("LEGION_JSON_OUTPUT") {
            if let Ok(json_output) = val.parse() {
                self.json_output = json_output;
            }
        }
        if let Ok(val) = env::var("LEGION_CREATE_BASELINE") {
            if let Ok(create_baseline) = val.parse() {
                self.create_baseline = create_baseline;
            }
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            config_file: "/etc/hardn/legion.conf".to_string(),
            baseline_dir: "/var/lib/hardn/legion".to_string(),
            log_file: "/var/log/hardn/legion.log".to_string(),
            create_baseline: false,
            verbose: false,
            json_output: false,
            timeout: 300, // 5 minutes
            rate_limit: 100, // operations per minute
        }
    }
}