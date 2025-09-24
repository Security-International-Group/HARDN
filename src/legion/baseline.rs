use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};
use std::os::unix::fs::PermissionsExt;
use sha2::{Sha256, Digest};
use std::io::Read;

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
}

impl BaselineManager {
    pub fn new(config: &super::config::Config) -> Result<Self, Box<dyn std::error::Error>> {
        fs::create_dir_all(&config.baseline_dir)?;
        Ok(Self {
            config: std::sync::Arc::new(config.clone()),
            current_baseline: None,
        })
    }

    pub fn save(&self, baseline: &Baseline) -> Result<(), Box<dyn std::error::Error>> {
        let timestamp = baseline.timestamp;
        let filename = format!("{}/baseline_{}.json", self.config.baseline_dir, timestamp);
        let json = serde_json::to_string_pretty(baseline)?;
        fs::write(&filename, json)?;
        println!(" Baseline saved to: {}", filename);
        Ok(())
    }

    pub fn load(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let pattern = format!("{}/baseline_*.json", self.config.baseline_dir);
        let paths = glob::glob(&pattern)?;

        let latest_path = paths
            .filter_map(Result::ok)
            .max_by_key(|path| {
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
            println!("Loaded baseline from: {}", path.display());
        } else {
            return Err("No baseline found. Run with --create-baseline to create one.".into());
        }

        Ok(())
    }

    #[allow(dead_code)]
    pub fn get_current(&self) -> Option<&Baseline> {
        self.current_baseline.as_ref()
    }
}

impl Baseline {
    /// Capture current system state as baseline
    pub fn capture() -> Result<Self, Box<dyn std::error::Error>> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)?
            .as_secs();

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
        
        let hostname = fs::read_to_string("/proc/sys/kernel/hostname")?.trim().to_string();
        let os_release = fs::read_to_string("/etc/os-release")?;
        let kernel_version = fs::read_to_string("/proc/version")?;
        let architecture = std::env::consts::ARCH.to_string();

        // Generate a simple UUID-like identifier
        let uuid = format!("{:x}-{:x}-{:x}",
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
            .args(&["-W", "-f=${Package}\t${Version}\t${Status}\n"])
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
                let mac = fs::read_to_string(&addr_path).unwrap_or_default().trim().to_string();

                // Try to get IPv4/IPv6 addresses from /proc/net/f or /proc/net/if_inet6
                // For simplicity, just use `ip addr show` if available
                let output = std::process::Command::new("ip")
                    .args(&["addr", "show", &name])
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
            .args(&["-tulnp"])
            .output()
            .or_else(|_| std::process::Command::new("netstat").args(&["-tulnp"]).output());

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

        Ok(KernelInfo {
            modules,
            sysctl,
        })
    }
}