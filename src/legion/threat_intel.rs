use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::PathBuf;
use chrono::{DateTime, Utc, Duration};
use tokio::sync::RwLock;
use std::sync::Arc;

/// Threat Intelligence Integration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatIntelligence {
    pub ip_blacklist: HashMap<IpAddr, ThreatEntry>,
    pub domain_blacklist: HashMap<String, ThreatEntry>,
    pub file_hash_blacklist: HashMap<String, ThreatEntry>,
    pub cve_database: HashMap<String, Vulnerability>,
    pub last_update: DateTime<Utc>,
    pub update_interval: Duration,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatEntry {
    pub indicator: String,
    pub threat_type: ThreatType,
    pub severity: Severity,
    pub source: String,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub confidence: f64,
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ThreatType {
    Malware,
    Botnet,
    Phishing,
    C2Server,
    Scanner,
    Spam,
    Unknown,
}

#[derive(Debug, Clone, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vulnerability {
    pub cve_id: String,
    pub description: String,
    pub severity: Severity,
    pub cvss_score: f64,
    pub affected_packages: Vec<String>,
    pub published_date: DateTime<Utc>,
    pub last_modified: DateTime<Utc>,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct ThreatLevel {
    pub level: Severity,
    pub confidence: f64,
    pub indicators: Vec<String>,
    pub recommended_actions: Vec<String>,
}

impl ThreatIntelligence {
    pub fn new() -> Self {
        Self {
            ip_blacklist: HashMap::new(),
            domain_blacklist: HashMap::new(),
            file_hash_blacklist: HashMap::new(),
            cve_database: HashMap::new(),
            last_update: Utc::now(),
            update_interval: Duration::hours(24),
        }
    }

    pub async fn update_feeds(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        println!("Updating threat intelligence feeds...");

        // Update AbuseIPDB feed
        self.update_abuseipdb_feed().await?;

        // Update AlienVault OTX feed
        self.update_alienvault_feed().await?;

        // Update VirusTotal feed
        self.update_virustotal_feed().await?;

        // Update CVE database
        self.update_cve_database().await?;

        self.last_update = Utc::now();
        println!("Threat intelligence feeds updated successfully");
        Ok(())
    }

    async fn update_abuseipdb_feed(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        // Simulate AbuseIPDB API call (replace with actual implementation)
        println!("Updating AbuseIPDB blacklist...");

        // In a real implementation, this would make HTTP requests to AbuseIPDB API
        // For demo purposes, we'll add some sample malicious IPs
        let malicious_ips = vec![
            "185.220.101.1", // Known Tor exit node
            "91.240.118.222", // Known malicious IP
            "45.155.205.233", // Known C2 server
        ];

        for ip_str in malicious_ips {
            if let Ok(ip) = ip_str.parse::<IpAddr>() {
                let entry = ThreatEntry {
                    indicator: ip_str.to_string(),
                    threat_type: ThreatType::Malware,
                    severity: Severity::High,
                    source: "AbuseIPDB".to_string(),
                    first_seen: Utc::now() - Duration::days(30),
                    last_seen: Utc::now(),
                    confidence: 0.9,
                    tags: vec!["malware".to_string(), "botnet".to_string()],
                };
                self.ip_blacklist.insert(ip, entry);
            }
        }

        Ok(())
    }

    async fn update_alienvault_feed(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        println!("Updating AlienVault OTX indicators...");

        // Sample domains from AlienVault OTX
        let malicious_domains = vec![
            "malicious-domain-001.com",
            "c2-server-example.net",
            "phishing-site-demo.org",
        ];

        for domain in malicious_domains {
            let entry = ThreatEntry {
                indicator: domain.to_string(),
                threat_type: ThreatType::Phishing,
                severity: Severity::High,
                source: "AlienVault OTX".to_string(),
                first_seen: Utc::now() - Duration::days(15),
                last_seen: Utc::now(),
                confidence: 0.85,
                tags: vec!["phishing".to_string(), "scam".to_string()],
            };
            self.domain_blacklist.insert(domain.to_string(), entry);
        }

        Ok(())
    }

    async fn update_virustotal_feed(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        println!("Updating VirusTotal file hashes...");

        // Sample malicious file hashes
        let malicious_hashes = vec![
            "a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3",
            "b772d5c4e6b8c1f4a8f2e9d3c5a7b9e1f2d4c6a8b0e2f4d6c8a0b2e4f6d8a",
        ];

        for hash in malicious_hashes {
            let entry = ThreatEntry {
                indicator: hash.to_string(),
                threat_type: ThreatType::Malware,
                severity: Severity::Critical,
                source: "VirusTotal".to_string(),
                first_seen: Utc::now() - Duration::days(7),
                last_seen: Utc::now(),
                confidence: 0.95,
                tags: vec!["malware".to_string(), "trojan".to_string()],
            };
            self.file_hash_blacklist.insert(hash.to_string(), entry);
        }

        Ok(())
    }

    async fn update_cve_database(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        println!("Updating CVE database...");

        // Sample CVEs
        let cves = vec![
            Vulnerability {
                cve_id: "CVE-2023-12345".to_string(),
                description: "Critical vulnerability in OpenSSL".to_string(),
                severity: Severity::Critical,
                cvss_score: 9.8,
                affected_packages: vec!["openssl".to_string(), "libssl1.1".to_string()],
                published_date: Utc::now() - Duration::days(30),
                last_modified: Utc::now() - Duration::days(5),
            },
            Vulnerability {
                cve_id: "CVE-2023-23456".to_string(),
                description: "High severity vulnerability in SSH".to_string(),
                severity: Severity::High,
                cvss_score: 7.5,
                affected_packages: vec!["openssh-server".to_string()],
                published_date: Utc::now() - Duration::days(20),
                last_modified: Utc::now() - Duration::days(2),
            },
        ];

        for cve in cves {
            self.cve_database.insert(cve.cve_id.clone(), cve);
        }

        Ok(())
    }

    pub fn check_indicator(&self, indicator: &SecurityIndicator) -> ThreatLevel {
        let mut indicators = Vec::new();
        let mut recommended_actions = Vec::new();
        let mut max_severity = Severity::Low;
        let mut total_confidence = 0.0;
        let mut count = 0;

        match indicator {
            SecurityIndicator::Ip(ip) => {
                if let Some(entry) = self.ip_blacklist.get(ip) {
                    indicators.push(format!("IP {} found in {} blacklist", ip, entry.source));
                    recommended_actions.push(format!("Block IP {} in firewall", ip));
                    max_severity = max_severity.max(entry.severity.clone());
                    total_confidence += entry.confidence;
                    count += 1;
                }
            }
            SecurityIndicator::Domain(domain) => {
                if let Some(entry) = self.domain_blacklist.get(domain) {
                    indicators.push(format!("Domain {} found in {} blacklist", domain, entry.source));
                    recommended_actions.push(format!("Block domain {} in DNS", domain));
                    max_severity = max_severity.max(entry.severity.clone());
                    total_confidence += entry.confidence;
                    count += 1;
                }
            }
            SecurityIndicator::FileHash(hash) => {
                if let Some(entry) = self.file_hash_blacklist.get(hash) {
                    indicators.push(format!("File hash {} found in {} blacklist", hash, entry.source));
                    recommended_actions.push("Quarantine file immediately".to_string());
                    recommended_actions.push("Scan system for similar files".to_string());
                    max_severity = max_severity.max(entry.severity.clone());
                    total_confidence += entry.confidence;
                    count += 1;
                }
            }
            SecurityIndicator::Package(package) => {
                for cve in self.cve_database.values() {
                    if cve.affected_packages.contains(package) {
                        indicators.push(format!("Package {} affected by {}", package, cve.cve_id));
                        recommended_actions.push(format!("Update package {} to fix {}", package, cve.cve_id));
                        max_severity = max_severity.max(cve.severity.clone());
                        total_confidence += 0.9; // CVEs are generally high confidence
                        count += 1;
                    }
                }
            }
        }

        let confidence = if count > 0 { total_confidence / count as f64 } else { 0.0 };

        ThreatLevel {
            level: max_severity,
            confidence,
            indicators,
            recommended_actions,
        }
    }

    pub fn needs_update(&self) -> bool {
        Utc::now().signed_duration_since(self.last_update) > self.update_interval
    }

    pub fn save_to_file(&self, path: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(path, json)?;
        Ok(())
    }

    pub fn load_from_file(path: &PathBuf) -> Result<Self, Box<dyn std::error::Error>> {
        let content = std::fs::read_to_string(path)?;
        let ti: ThreatIntelligence = serde_json::from_str(&content)?;
        Ok(ti)
    }
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub enum SecurityIndicator {
    Ip(IpAddr),
    Domain(String),
    FileHash(String),
    Package(String),
}

/// Threat Intelligence Manager
#[derive(Debug)]
pub struct ThreatIntelManager {
    intelligence: Arc<RwLock<ThreatIntelligence>>,
    cache_path: PathBuf,
    auto_update: bool,
}

#[allow(dead_code)]
impl ThreatIntelManager {
    pub fn new(cache_path: PathBuf, auto_update: bool) -> Self {
        Self {
            intelligence: Arc::new(RwLock::new(ThreatIntelligence::new())),
            cache_path,
            auto_update,
        }
    }

    pub async fn initialize(&self) -> Result<(), Box<dyn std::error::Error>> {
        // Try to load from cache first
        if self.cache_path.exists() {
            let ti = ThreatIntelligence::load_from_file(&self.cache_path)?;
            *self.intelligence.write().await = ti;
        }

        // Update if needed
        if self.auto_update && self.intelligence.read().await.needs_update() {
            self.update_intelligence().await?;
        }

        Ok(())
    }

    pub async fn update_intelligence(&self) -> Result<(), Box<dyn std::error::Error>> {
        let mut ti = self.intelligence.write().await;
        ti.update_feeds().await?;
        ti.save_to_file(&self.cache_path)?;
        Ok(())
    }

    pub async fn check_threat(&self, indicator: &SecurityIndicator) -> ThreatLevel {
        let ti = self.intelligence.read().await;
        ti.check_indicator(indicator)
    }

    pub async fn get_statistics(&self) -> ThreatStats {
        let ti = self.intelligence.read().await;
        ThreatStats {
            ip_blacklist_size: ti.ip_blacklist.len(),
            domain_blacklist_size: ti.domain_blacklist.len(),
            file_hash_blacklist_size: ti.file_hash_blacklist.len(),
            cve_count: ti.cve_database.len(),
            last_update: ti.last_update,
        }
    }
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct ThreatStats {
    pub ip_blacklist_size: usize,
    pub domain_blacklist_size: usize,
    pub file_hash_blacklist_size: usize,
    pub cve_count: usize,
    pub last_update: DateTime<Utc>,
}