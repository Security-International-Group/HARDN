use chrono::{DateTime, Utc};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::path::{Path, PathBuf};

/// Process behavior analysis for anomaly detection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessBehavior {
    pub process_id: u32,
    pub parent_pid: u32,
    pub name: String,
    pub command_line: String,
    pub network_connections: Vec<Connection>,
    pub file_access: Vec<FileOperation>,
    pub system_calls: Vec<SystemCall>,
    pub memory_usage: MemoryStats,
    pub cpu_usage: CpuStats,
    pub start_time: DateTime<Utc>,
    pub behavior_score: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Connection {
    pub local_addr: String,
    pub remote_addr: String,
    pub protocol: String,
    pub state: String,
    pub timestamp: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileOperation {
    pub path: PathBuf,
    pub operation: FileOpType,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FileOpType {
    Read,
    Write,
    Execute,
    Delete,
    Create,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemCall {
    pub syscall: String,
    pub args: Vec<String>,
    pub return_value: i64,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MemoryStats {
    pub rss: u64,    // Resident Set Size
    pub vsz: u64,    // Virtual Memory Size
    pub shared: u64, // Shared memory
    pub text: u64,   // Text (code)
    pub data: u64,   // Data + stack
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CpuStats {
    pub user_time: u64,
    pub system_time: u64,
    pub total_time: u64,
    pub priority: i32,
    pub nice: i32,
}

#[derive(Debug, Clone, PartialEq)]
#[allow(dead_code)]
pub enum BehaviorClassification {
    Normal,
    Suspicious,
    Malicious,
    Unknown,
}

impl ProcessBehavior {
    pub fn new(pid: u32, name: String, cmdline: String) -> Self {
        Self {
            process_id: pid,
            parent_pid: 0,
            name,
            command_line: cmdline,
            network_connections: Vec::new(),
            file_access: Vec::new(),
            system_calls: Vec::new(),
            memory_usage: MemoryStats::default(),
            cpu_usage: CpuStats::default(),
            start_time: Utc::now(),
            behavior_score: 0.0,
        }
    }

    pub fn analyze_behavior(&self) -> BehaviorClassification {
        let mut suspicious_indicators = 0;
        let mut malicious_indicators = 0;

        // Check for suspicious network connections
        for conn in &self.network_connections {
            if self.is_suspicious_connection(conn) {
                suspicious_indicators += 1;
            }
        }

        // Check for suspicious file access patterns
        if self.has_suspicious_file_access() {
            suspicious_indicators += 1;
        }

        // Check for suspicious system calls
        for syscall in &self.system_calls {
            if self.is_suspicious_syscall(syscall) {
                suspicious_indicators += 1;
            }
        }

        // Check for abnormal resource usage
        if self.has_abnormal_resource_usage() {
            suspicious_indicators += 1;
        }

        // Check for known malicious patterns
        if self.matches_malicious_patterns() {
            malicious_indicators += 1;
        }

        // Classification logic
        if malicious_indicators > 0 {
            BehaviorClassification::Malicious
        } else if suspicious_indicators >= 1 {
            BehaviorClassification::Suspicious
        } else {
            BehaviorClassification::Normal
        }
    }

    fn is_suspicious_connection(&self, conn: &Connection) -> bool {
        // Check for connections to known suspicious ports
        let suspicious_ports = [22, 23, 25, 53, 80, 443, 993, 995]; // Common attack vectors
        if let Ok(port) = conn
            .remote_addr
            .split(':')
            .next_back()
            .unwrap_or("")
            .parse::<u16>()
        {
            if suspicious_ports.contains(&port) {
                // Additional check for unusual connection patterns
                return self.has_unusual_connection_pattern();
            }
        }

        // Check for connections to private IP ranges from unexpected processes
        if let Ok(ip) = conn
            .remote_addr
            .split(':')
            .next()
            .unwrap_or("")
            .parse::<IpAddr>()
        {
            match ip {
                IpAddr::V4(ipv4) => {
                    let octets = ipv4.octets();
                    // Private IP ranges
                    if (octets[0] == 10)
                        || (octets[0] == 172 && octets[1] >= 16 && octets[1] <= 31)
                        || (octets[0] == 192 && octets[1] == 168)
                    {
                        // Allow common services
                        if !self.is_expected_private_connection(&self.name) {
                            return true;
                        }
                    }
                }
                IpAddr::V6(_) => {
                    // IPv6 private connections - simplified check
                    if (conn.remote_addr.starts_with("fc00:")
                        || conn.remote_addr.starts_with("fd00:"))
                        && !self.is_expected_private_connection(&self.name)
                    {
                        return true;
                    }
                }
            }
        }

        false
    }

    fn has_unusual_connection_pattern(&self) -> bool {
        // Check for rapid connection attempts or unusual patterns
        let recent_connections: Vec<_> = self
            .network_connections
            .iter()
            .filter(|conn| {
                let duration =
                    Utc::now().signed_duration_since(conn.timestamp.unwrap_or(Utc::now()));
                duration.num_minutes() < 5
            })
            .collect();

        recent_connections.len() > 10 // More than 10 connections in 5 minutes
    }

    fn is_expected_private_connection(&self, process_name: &str) -> bool {
        let expected_processes = [
            "sshd",
            "apache2",
            "nginx",
            "mysql",
            "postgresql",
            "redis",
            "mongodb",
        ];
        expected_processes.contains(&process_name)
    }

    fn has_suspicious_file_access(&self) -> bool {
        let mut read_sensitive = false;
        let mut write_system = false;

        for file_op in &self.file_access {
            match file_op.operation {
                FileOpType::Read => {
                    if self.is_sensitive_file(&file_op.path) {
                        read_sensitive = true;
                    }
                }
                FileOpType::Write | FileOpType::Create => {
                    if self.is_system_file(&file_op.path) {
                        write_system = true;
                    }
                }
                _ => {}
            }
        }

        read_sensitive && write_system // Both reading sensitive files and writing to system files
    }

    fn is_sensitive_file(&self, path: &Path) -> bool {
        let sensitive_paths = [
            "/etc/passwd",
            "/etc/shadow",
            "/etc/sudoers",
            "/etc/ssh/sshd_config",
            "/root/.ssh",
            "/home",
        ];

        path.to_string_lossy().starts_with_any(&sensitive_paths)
    }

    fn is_system_file(&self, path: &Path) -> bool {
        let system_paths = ["/etc", "/usr", "/bin", "/sbin", "/lib"];

        path.to_string_lossy().starts_with_any(&system_paths)
    }

    fn is_suspicious_syscall(&self, syscall: &SystemCall) -> bool {
        let suspicious_syscalls = [
            "ptrace",
            "process_vm_readv",
            "process_vm_writev",
            "memfd_create",
            "userfaultfd",
            "bpf",
        ];

        suspicious_syscalls.contains(&syscall.syscall.as_str())
    }

    fn has_abnormal_resource_usage(&self) -> bool {
        // Check for abnormal memory usage (> 1GB)
        if self.memory_usage.rss > 1_000_000_000 {
            return true;
        }

        // Check for high CPU usage (> 80%)
        let total_cpu = self.cpu_usage.user_time + self.cpu_usage.system_time;
        if total_cpu > 80 {
            return true;
        }

        false
    }

    fn matches_malicious_patterns(&self) -> bool {
        // Check command line for known malicious patterns
        let malicious_patterns = [
            r"wget.*\|.*bash",
            r"curl.*\|.*sh",
            r"python.*-c.*import",
            r"perl.*-e.*system",
            r"base64.*-d.*\|.*bash",
            r"echo.*\|.*base64.*-d",
        ];

        for pattern in &malicious_patterns {
            if let Ok(regex) = Regex::new(pattern) {
                if regex.is_match(&self.command_line) {
                    return true;
                }
            }
        }

        false
    }

    pub fn update_behavior_score(&mut self) {
        let classification = self.analyze_behavior();
        self.behavior_score = match classification {
            BehaviorClassification::Normal => 0.0,
            BehaviorClassification::Suspicious => 0.6,
            BehaviorClassification::Malicious => 0.9,
            BehaviorClassification::Unknown => 0.5,
        };
    }
}

trait StartsWithAny {
    fn starts_with_any(&self, prefixes: &[&str]) -> bool;
}

impl StartsWithAny for str {
    fn starts_with_any(&self, prefixes: &[&str]) -> bool {
        prefixes.iter().any(|&prefix| self.starts_with(prefix))
    }
}

/// Behavioral Analysis Engine
#[derive(Debug)]
#[allow(dead_code)]
pub struct BehavioralAnalyzer {
    process_behaviors: HashMap<u32, ProcessBehavior>,
    suspicious_processes: HashSet<u32>,
    analysis_interval: std::time::Duration,
}

#[allow(dead_code)]
impl BehavioralAnalyzer {
    pub fn new() -> Self {
        Self {
            process_behaviors: HashMap::new(),
            suspicious_processes: HashSet::new(),
            analysis_interval: std::time::Duration::from_secs(60),
        }
    }

    pub fn analyze_process(
        &mut self,
        pid: u32,
        mut behavior: ProcessBehavior,
    ) -> BehaviorClassification {
        behavior.update_behavior_score();
        let classification = behavior.analyze_behavior();

        if classification == BehaviorClassification::Suspicious
            || classification == BehaviorClassification::Malicious
        {
            self.suspicious_processes.insert(pid);
        }

        self.process_behaviors.insert(pid, behavior);
        classification
    }

    pub fn get_suspicious_processes(&self) -> Vec<u32> {
        self.suspicious_processes.iter().cloned().collect()
    }

    pub fn get_process_behavior(&self, pid: u32) -> Option<&ProcessBehavior> {
        self.process_behaviors.get(&pid)
    }

    pub fn remove_process(&mut self, pid: u32) {
        self.process_behaviors.remove(&pid);
        self.suspicious_processes.remove(&pid);
    }

    pub fn get_overall_threat_score(&self) -> f64 {
        let total_processes = self.process_behaviors.len() as f64;
        if total_processes == 0.0 {
            return 0.0;
        }

        let suspicious_count = self.suspicious_processes.len() as f64;
        suspicious_count / total_processes
    }
}
