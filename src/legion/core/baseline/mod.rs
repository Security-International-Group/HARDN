use rusqlite::{params, Connection, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// System baseline data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Baseline {
    pub timestamp: u64,
    pub version: String,
    pub system_fingerprint: SystemFingerprint,
    pub packages: HashMap<String, PackageInfo>,
    pub files: HashMap<String, FileInfo>,
    pub processes: Vec<ProcessInfo>,
    pub network: NetworkInfo,
    pub kernel: KernelInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemFingerprint {
    pub hostname: String,
    pub os_release: String,
    pub kernel_version: String,
    pub architecture: String,
    pub uuid: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageInfo {
    pub name: String,
    pub version: String,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileInfo {
    pub path: String,
    pub size: u64,
    pub modified: u64,
    pub permissions: u32,
    pub hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessInfo {
    pub pid: u32,
    pub name: String,
    pub cmdline: String,
    pub parent_pid: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkInfo {
    pub interfaces: Vec<NetworkInterface>,
    pub listening_ports: Vec<PortInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkInterface {
    pub name: String,
    pub addresses: Vec<String>,
    pub mac: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortInfo {
    pub port: u16,
    pub protocol: String,
    pub process: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KernelInfo {
    pub modules: Vec<String>,
    pub sysctl: HashMap<String, String>,
}

/// Baseline manager for handling baseline operations
#[derive(Debug)]
pub struct BaselineManager {
    config: std::sync::Arc<super::config::Config>,
    current_baseline: Option<Baseline>,
    database: Option<BaselineDatabase>,
}

impl BaselineManager {
    pub fn new(config: &super::config::Config) -> Result<Self, Box<dyn std::error::Error>> {
        fs::create_dir_all(&config.baseline_dir)?;

        // Initialize database if possible
        let database = match BaselineDatabase::new("/var/lib/hardn/baselines/legion_baselines.db") {
            Ok(db) => Some(db),
            Err(e) => {
                eprintln!("Warning: Could not initialize baseline database: {}", e);
                None
            }
        };

        Ok(Self {
            config: std::sync::Arc::new(config.clone()),
            current_baseline: None,
            database,
        })
    }

    pub fn save(&self, baseline: &Baseline) -> Result<(), Box<dyn std::error::Error>> {
        let timestamp = baseline.timestamp;
        let filename = format!("{}/baseline_{}.json", self.config.baseline_dir, timestamp);
        let json = serde_json::to_string_pretty(baseline)?;
        fs::write(&filename, &json)?;
        eprintln!(" Baseline saved to: {}", filename);

        // Store in database if available
        if let Some(ref db) = self.database {
            let json_value: Value =
                serde_json::from_str(&json).map_err(|e| format!("JSON parse error: {}", e))?;
            if let Err(e) = db.store_baseline(timestamp, &json_value) {
                eprintln!("Warning: Failed to store baseline in database: {}", e);
            } else {
                eprintln!(" Baseline stored in database");
            }
        }

        // Clean up old baselines, keeping only the last 30 days
        self.cleanup_old_baselines()?;

        Ok(())
    }

    /// Clean up baseline files older than 30 days
    fn cleanup_old_baselines(&self) -> Result<(), Box<dyn std::error::Error>> {
        // Clean up database baselines
        if let Some(ref db) = self.database {
            if let Err(e) = db.cleanup_old_baselines(30) {
                eprintln!("Warning: Failed to cleanup old database baselines: {}", e);
            }
        }

        // Clean up file baselines
        let pattern = format!("{}/baseline_*.json", self.config.baseline_dir);
        let paths = glob::glob(&pattern)?;

        let now = SystemTime::now();
        let thirty_days_ago = now - Duration::from_secs(30 * 24 * 60 * 60);

        for path in paths.filter_map(Result::ok) {
            if let Some(filename) = path.file_name().and_then(|n| n.to_str()) {
                if let Some(timestamp_str) = filename
                    .strip_prefix("baseline_")
                    .and_then(|s| s.strip_suffix(".json"))
                {
                    if let Ok(timestamp) = timestamp_str.parse::<u64>() {
                        let file_time = UNIX_EPOCH + Duration::from_secs(timestamp);
                        if file_time < thirty_days_ago {
                            if let Err(e) = fs::remove_file(&path) {
                                eprintln!(
                                    "Failed to remove old baseline {}: {}",
                                    path.display(),
                                    e
                                );
                            } else {
                                eprintln!("Removed old baseline: {}", path.display());
                            }
                        }
                    }
                }
            }
        }

        Ok(())
    }

    pub fn load(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let pattern = format!("{}/baseline_*.json", self.config.baseline_dir);
        let paths = glob::glob(&pattern)?;

        let latest_path = paths.filter_map(Result::ok).max_by_key(|path| {
            path.file_stem()
                .and_then(|s| s.to_str())
                .and_then(|s| s.strip_prefix("baseline_"))
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or(0)
        });

        if let Some(path) = latest_path {
            let content = fs::read_to_string(&path)?;
            let baseline: Baseline = serde_json::from_str(&content)?;
            self.current_baseline = Some(baseline);
            eprintln!("Loaded baseline from: {}", path.display());
        } else {
            return Err("No baseline found. Run with --create-baseline to create one.".into());
        }

        Ok(())
    }

    #[allow(dead_code)]
    pub fn get_current(&self) -> Option<&Baseline> {
        self.current_baseline.as_ref()
    }

    pub fn snapshot(&self) -> Option<super::framework::BaselineSnapshot> {
        self.current_baseline.as_ref().map(|baseline| {
            let created_at = UNIX_EPOCH + Duration::from_secs(baseline.timestamp);
            let version = baseline
                .version
                .split('.')
                .next()
                .and_then(|major| major.parse::<u64>().ok())
                .unwrap_or(0);

            let mut tags = Vec::new();
            tags.push(format!("hostname:{}", baseline.system_fingerprint.hostname));
            tags.push(format!(
                "kernel:{}",
                baseline.system_fingerprint.kernel_version.trim()
            ));

            super::framework::BaselineSnapshot {
                created_at,
                version,
                tags,
            }
        })
    }

    /// Detect anomalies by comparing current state with historical baselines
    #[allow(dead_code)]
    pub fn detect_anomalies(
        &self,
        current: &Value,
    ) -> Result<Vec<String>, Box<dyn std::error::Error>> {
        if let Some(ref db) = self.database {
            Ok(db.detect_anomalies(current)?)
        } else {
            Ok(Vec::new())
        }
    }

    pub fn get_database_stats(&self) -> Result<Option<(i64, i64, Option<i64>, u64)>> {
        if let Some(ref db) = self.database {
            let baseline_count = db.get_baseline_count()?;
            let anomaly_count = db.get_anomaly_count()?;
            let latest_timestamp = db.get_latest_baseline_timestamp()?;
            let db_size = db.get_database_size()?;
            Ok(Some((
                baseline_count,
                anomaly_count,
                latest_timestamp,
                db_size,
            )))
        } else {
            Ok(None)
        }
    }
}

impl Baseline {
    /// Capture current system state as baseline
    pub fn capture() -> Result<Self, Box<dyn std::error::Error>> {
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

        let system_fingerprint = Self::capture_system_fingerprint()?;
        let packages = Self::capture_packages()?;
        let files = Self::capture_critical_files()?;
        let processes = Self::capture_processes()?;
        let network = Self::capture_network()?;
        let kernel = Self::capture_kernel()?; // updated kernel info

        Ok(Self {
            timestamp,
            version: env!("CARGO_PKG_VERSION").to_string(),
            system_fingerprint,
            packages,
            files,
            processes,
            network,
            kernel,
        })
    }

    fn capture_system_fingerprint() -> Result<SystemFingerprint, Box<dyn std::error::Error>> {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();

        let hostname = fs::read_to_string("/proc/sys/kernel/hostname")?
            .trim()
            .to_string();
        let os_release = fs::read_to_string("/etc/os-release")?;
        let kernel_version = fs::read_to_string("/proc/version")?;
        let architecture = std::env::consts::ARCH.to_string();

        // Generate a simple UUID-like identifier
        let uuid = format!(
            "{:x}-{:x}-{:x}",
            timestamp,
            hostname.len() as u64,
            kernel_version.len() as u64
        );

        Ok(SystemFingerprint {
            hostname,
            os_release,
            kernel_version,
            architecture,
            uuid,
        })
    }

    fn capture_packages() -> Result<HashMap<String, PackageInfo>, Box<dyn std::error::Error>> {
        // Try to use dpkg-query to get installed packages on Debian-based systems
        let output = std::process::Command::new("dpkg-query")
            .args(["-W", "-f=${Package}\t${Version}\t${Status}\n"])
            .output()?;

        if !output.status.success() {
            return Err("Failed to run dpkg-query".into());
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut packages = HashMap::new();

        for line in stdout.lines() {
            let parts: Vec<&str> = line.split('\t').collect();
            if parts.len() >= 3 {
                let name = parts[0].to_string();
                let version = parts[1].to_string();
                let status = parts[2].to_string();
                packages.insert(
                    name.clone(),
                    PackageInfo {
                        name,
                        version,
                        status,
                    },
                );
            }
        }

        Ok(packages)
    }

    fn capture_critical_files() -> Result<HashMap<String, FileInfo>, Box<dyn std::error::Error>> {
        // List of critical files to check
        let critical_files = vec![
            "/etc/passwd",
            "/etc/shadow",
            "/etc/group",
            "/etc/hosts",
            "/etc/hostname",
            "/etc/resolv.conf",
        ];

        let mut files = HashMap::new();

        for path in critical_files {
            if let Ok(metadata) = fs::metadata(path) {
                let size = metadata.len();
                let modified = metadata.modified()?.duration_since(UNIX_EPOCH)?.as_secs();
                let permissions = metadata.permissions().mode();
                let mut file = fs::File::open(path)?;
                let mut hasher = Sha256::new();
                let mut buffer = Vec::new();
                file.read_to_end(&mut buffer)?;
                hasher.update(&buffer);
                let hash = format!("{:x}", hasher.finalize());

                files.insert(
                    path.to_string(),
                    FileInfo {
                        path: path.to_string(),
                        size,
                        modified,
                        permissions,
                        hash,
                    },
                );
            }
        }

        Ok(files)
    }

    fn capture_processes() -> Result<Vec<ProcessInfo>, Box<dyn std::error::Error>> {
        let mut processes = Vec::new();

        for entry in fs::read_dir("/proc")? {
            let entry = entry?;
            let file_name = entry.file_name();
            if let Ok(pid) = file_name.to_string_lossy().parse::<u32>() {
                let cmdline_path = format!("/proc/{}/cmdline", pid);
                let status_path = format!("/proc/{}/status", pid);

                if let Ok(cmdline) = fs::read_to_string(&cmdline_path) {
                    if let Ok(status) = fs::read_to_string(&status_path) {
                        let name = status
                            .lines()
                            .find(|line| line.starts_with("Name:"))
                            .and_then(|line| line.split_whitespace().nth(1))
                            .unwrap_or("")
                            .to_string();

                        let parent_pid = status
                            .lines()
                            .find(|line| line.starts_with("PPid:"))
                            .and_then(|line| line.split_whitespace().nth(1))
                            .and_then(|s| s.parse::<u32>().ok())
                            .unwrap_or(0);

                        processes.push(ProcessInfo {
                            pid,
                            name,
                            cmdline: cmdline.replace('\0', " "),
                            parent_pid,
                        });
                    }
                }
            }
        }

        Ok(processes)
    }

    fn capture_network() -> Result<NetworkInfo, Box<dyn std::error::Error>> {
        // Capture network interfaces
        let mut interfaces = Vec::new();
        if let Ok(ifaces) = fs::read_dir("/sys/class/net") {
            for iface in ifaces.flatten() {
                let name = iface.file_name().to_string_lossy().to_string();
                let mut addresses = Vec::new();
                let addr_path = format!("/sys/class/net/{}/address", name);
                let mac = fs::read_to_string(&addr_path)
                    .unwrap_or_default()
                    .trim()
                    .to_string();

                // Try to get IPv4/IPv6 addresses from /proc/net/f or /proc/net/if_inet6
                // For simplicity, just use `ip addr show` if available
                let output = std::process::Command::new("ip")
                    .args(["addr", "show", &name])
                    .output();

                if let Ok(output) = output {
                    if output.status.success() {
                        let stdout = String::from_utf8_lossy(&output.stdout);
                        for line in stdout.lines() {
                            let line = line.trim();
                            if line.starts_with("inet ") {
                                if let Some(addr) = line.split_whitespace().nth(1) {
                                    addresses.push(addr.to_string());
                                }
                            } else if line.starts_with("inet6 ") {
                                if let Some(addr) = line.split_whitespace().nth(1) {
                                    addresses.push(addr.to_string());
                                }
                            }
                        }
                    }
                }

                interfaces.push(NetworkInterface {
                    name,
                    addresses,
                    mac,
                });
            }
        }

        // Capture listening ports
        let mut listening_ports = Vec::new();
        // Use `ss` if available, fallback to `netstat`
        let output = std::process::Command::new("ss")
            .args(["-tulnp"])
            .output()
            .or_else(|_| {
                std::process::Command::new("netstat")
                    .args(["-tulnp"])
                    .output()
            });

        if let Ok(output) = output {
            if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                for line in stdout.lines() {
                    // Skip header lines
                    if line.starts_with("Netid") || line.starts_with("Proto") {
                        continue;
                    }
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() < 5 {
                        continue;
                    }
                    // For ss: Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port Process
                    // For netstat: Proto Recv-Q Send-Q Local Address Foreign Address State PID/Program name
                    let (proto, local_addr, process) = if line.contains("Netid") {
                        // ss format
                        (parts[0], parts[4], parts.get(6).unwrap_or(&""))
                    } else {
                        // netstat format
                        (parts[0], parts[3], parts.get(6).unwrap_or(&""))
                    };

                    // Extract port
                    if let Some(pos) = local_addr.rfind(':') {
                        if let Ok(port) = local_addr[pos + 1..].parse::<u16>() {
                            listening_ports.push(PortInfo {
                                port,
                                protocol: proto.to_string(),
                                process: process.to_string(),
                            });
                        }
                    }
                }
            }
        }

        Ok(NetworkInfo {
            interfaces,
            listening_ports,
        })
    }

    fn capture_kernel() -> Result<KernelInfo, Box<dyn std::error::Error>> {
        // Capture loaded kernel modules
        let modules = if let Ok(content) = fs::read_to_string("/proc/modules") {
            content
                .lines()
                .map(|line| line.split_whitespace().next().unwrap_or("").to_string())
                .filter(|s| !s.is_empty())
                .collect()
        } else {
            Vec::new()
        };

        // Capture sysctl values related to heuristics and signature monitoring
        let mut sysctl = HashMap::new();
        let sysctl_keys = vec![
            // Common kernel parameters for security/monitoring
            "kernel.kptr_restrict",
            "kernel.dmesg_restrict",
            "kernel.modules_disabled",
            "fs.protected_hardlinks",
            "fs.protected_symlinks",
            "kernel.yama.ptrace_scope",
            "kernel.randomize_va_space",
            "kernel.sysrq",
            "kernel.unprivileged_bpf_disabled",
            "kernel.unprivileged_userns_clone",
            // Add more keys as needed for heuristics/signature monitoring
        ];

        for key in sysctl_keys {
            let output = std::process::Command::new("sysctl")
                .arg("-n")
                .arg(key)
                .output();

            if let Ok(output) = output {
                if output.status.success() {
                    let value = String::from_utf8_lossy(&output.stdout).trim().to_string();
                    sysctl.insert(key.to_string(), value);
                }
            }
        }

        Ok(KernelInfo { modules, sysctl })
    }
}

/// Baseline database for storing and analyzing baseline snapshots
#[derive(Debug)]
pub struct BaselineDatabase {
    conn: Connection,
}

impl BaselineDatabase {
    pub fn new<P: AsRef<std::path::Path>>(path: P) -> Result<Self> {
        let conn = Connection::open(path)?;

        // Create tables
        conn.execute(
            "CREATE TABLE IF NOT EXISTS baselines (
                id INTEGER PRIMARY KEY,
                timestamp INTEGER NOT NULL,
                data TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )",
            [],
        )?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS anomalies (
                id INTEGER PRIMARY KEY,
                baseline_id INTEGER,
                anomaly_type TEXT NOT NULL,
                description TEXT NOT NULL,
                severity TEXT NOT NULL,
                detected_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(baseline_id) REFERENCES baselines(id)
            )",
            [],
        )?;

        Ok(Self { conn })
    }

    pub fn store_baseline(&self, timestamp: u64, data: &Value) -> Result<i64> {
        self.conn.execute(
            "INSERT INTO baselines (timestamp, data) VALUES (?1, ?2)",
            params![timestamp as i64, data.to_string()],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    #[allow(dead_code)]
    pub fn get_recent_baselines(&self, limit: usize) -> Result<Vec<(i64, u64, Value)>> {
        let mut stmt = self
            .conn
            .prepare("SELECT id, timestamp, data FROM baselines ORDER BY timestamp DESC LIMIT ?")?;

        let rows = stmt.query_map(params![limit as i64], |row| {
            let id: i64 = row.get(0)?;
            let timestamp: i64 = row.get(1)?;
            let data_str: String = row.get(2)?;
            let data: Value = serde_json::from_str(&data_str).map_err(|e| {
                rusqlite::Error::FromSqlConversionFailure(
                    0,
                    rusqlite::types::Type::Text,
                    Box::new(e),
                )
            })?;
            Ok((id, timestamp as u64, data))
        })?;

        rows.collect()
    }

    #[allow(dead_code)]
    pub fn detect_anomalies(&self, current: &Value) -> Result<Vec<String>> {
        let mut anomalies = Vec::new();
        let recent = self.get_recent_baselines(5)?;

        if recent.len() < 2 {
            return Ok(anomalies);
        }

        // Simple heuristic: check for significant changes in process count
        let baseline_avg = recent
            .iter()
            .map(|(_, _, data)| data["processes"].as_array().map(|a| a.len()).unwrap_or(0))
            .sum::<usize>() as f64
            / recent.len() as f64;

        let current_count = current["processes"]
            .as_array()
            .map(|a| a.len())
            .unwrap_or(0);

        if (current_count as f64 - baseline_avg).abs() > baseline_avg * 0.2 {
            anomalies.push(format!(
                "Process count anomaly: {} vs baseline {}",
                current_count, baseline_avg as usize
            ));
        }

        // Check for significant changes in network connections
        let baseline_net_avg = recent
            .iter()
            .map(|(_, _, data)| {
                data["network"]["connections"]
                    .as_array()
                    .map(|a| a.len())
                    .unwrap_or(0)
            })
            .sum::<usize>() as f64
            / recent.len() as f64;

        let current_net_count = current["network"]["connections"]
            .as_array()
            .map(|a| a.len())
            .unwrap_or(0);

        if (current_net_count as f64 - baseline_net_avg).abs() > baseline_net_avg * 0.3 {
            anomalies.push(format!(
                "Network connections anomaly: {} vs baseline {}",
                current_net_count, baseline_net_avg as usize
            ));
        }

        Ok(anomalies)
    }

    pub fn cleanup_old_baselines(&self, max_age_days: u64) -> Result<usize> {
        let now = SystemTime::now();
        let thirty_days_ago = now - Duration::from_secs(max_age_days * 24 * 60 * 60);
        let cutoff_timestamp = thirty_days_ago
            .duration_since(UNIX_EPOCH)
            .map_err(|_| rusqlite::Error::InvalidQuery)?
            .as_secs() as i64;

        let rows_affected = self.conn.execute(
            "DELETE FROM baselines WHERE timestamp < ?",
            params![cutoff_timestamp],
        )?;

        Ok(rows_affected)
    }

    pub fn get_baseline_count(&self) -> Result<i64> {
        let mut stmt = self.conn.prepare("SELECT COUNT(*) FROM baselines")?;
        let count: i64 = stmt.query_row([], |row| row.get(0))?;
        Ok(count)
    }

    pub fn get_anomaly_count(&self) -> Result<i64> {
        let mut stmt = self.conn.prepare("SELECT COUNT(*) FROM anomalies")?;
        let count: i64 = stmt.query_row([], |row| row.get(0))?;
        Ok(count)
    }

    pub fn get_latest_baseline_timestamp(&self) -> Result<Option<i64>> {
        let mut stmt = self
            .conn
            .prepare("SELECT timestamp FROM baselines ORDER BY timestamp DESC LIMIT 1")?;
        let result = stmt.query_row([], |row| row.get(0));
        match result {
            Ok(timestamp) => Ok(Some(timestamp)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e),
        }
    }

    pub fn get_database_size(&self) -> Result<u64> {
        let path = self.conn.path().unwrap_or(":memory:");
        if path == ":memory:" {
            return Ok(0);
        }
        match std::fs::metadata(path) {
            Ok(metadata) => Ok(metadata.len()),
            Err(_) => Err(rusqlite::Error::InvalidQuery),
        }
    }
}
