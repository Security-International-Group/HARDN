# HARDN Legion Daemon

## Purpose

HARDN Legion is an advanced heuristics-based security monitoring and anomaly detection system with machine learning capabilities. It performs comprehensive system monitoring, creates baselines of normal system behavior, detects potential security issues, and provides automated threat response. Legion integrates ML-powered anomaly detection, behavioral analysis, threat intelligence feeds, incident correlation, and real-time risk scoring for comprehensive security surveillance.

## Architecture Overview

### Design Goals
- **Unified Detection Core**: Blend signature intelligence, heuristic scoring, and baseline drift analytics to spot both known malware and novel intrusions quickly.
- **Lean Execution Model**: Prioritize sequential, CPU-friendly collectors and detectors; avoid GPU, SIMD batching, or other parallel hardware requirements so Legion stays lightweight on endpoints.
- **Deterministic Responsiveness**: Keep monitoring loops predictable and low latency, ensuring automated containment can fire without delaying user workloads.
- **Central Control Surface**: The Legion daemon is the authoritative interface for telemetry, configuration, response triggers, and GUI data access—every client reads from and writes to this service.

Legion operates in two primary modes with enhanced capabilities:

### 1. Interactive Scanning Mode
- **Purpose**: On-demand system security assessment with ML analysis
- **Execution**: Single-run analysis with detailed reporting and risk scoring
- **Output**: Human-readable or JSON formatted results with contributing factors
- **Use Case**: Manual security audits, investigations, and compliance checks

### 2. Daemon Monitoring Mode (`legion-daemon.service`)
- **Purpose**: Continuous background security monitoring with automated response
- **Execution**: Persistent service with ML anomaly detection and threat intelligence
- **Output**: Systemd journal logging with anomaly alerts and incident correlation
- **Use Case**: 24/7 security surveillance, automated threat response, and risk assessment

## Service Configuration

### Legion Daemon Service

The Legion daemon runs as a systemd service with the following configuration:

```ini
[Unit]
Description=HARDN LEGION Security Monitoring Daemon
After=network.target syslog.target
Wants=network.target

[Service]
Type=simple
User=hardn
Group=hardn
ExecStart=/usr/local/bin/hardn legion --daemon --ml-enabled --response-enabled --verbose
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=legion-daemon

# Security settings
NoNewPrivileges=yes
ProtectHome=yes
ProtectSystem=strict
ReadWritePaths=/var/log /var/lib/hardn
MemoryLimit=256M
```
### Expected Behavior
- **Telemetry Hub**: Streams normalized event data, risk scores, and detailed findings to the GUI and external consumers through a single API surface.
- **Control Plane**: Accepts configuration pushes, response commands, and policy updates, applying them atomically to monitoring modules.
- **Baseline Steward**: Coordinates learning cycles, persists baselines, and manages drift heuristics without delegating to auxiliary workers.
- **Logging Authority**: Owns structured logging and alert journaling, guaranteeing consistent audit trails for every detection and automated response.

### Bottom-Up Framework
- **Collection Layer** (`TelemetrySource`): CPU-friendly collectors gather system, process, network, kernel, and filesystem telemetry sequentially without parallel fan-out, ensuring predictable latency and reduced resource impact.
- **Analysis Layer** (`HeuristicModule`, `SignatureModule`): Pure-Rust heuristics and signature engines operate on immutable telemetry batches, generating findings with explicit severity and provenance metadata for traceability.
- **Response Layer** (`ResponseModule`): Deterministic responders receive consolidated findings along with baseline context, enforcing policy decisions (alert, isolate, block) while honoring the daemon’s automatic-response allowance.
- **LegionCore Orchestrator**: The `framework` module provides a pristine pipeline that wires these layers together inside the daemon, delivering a single-cycle report for the GUI, logging system, and automated response engine.

### Baseline Management

Legion uses baseline files to establish "normal" system behavior:

- **Storage Location**: `/var/lib/hardn/legion/`
- **File Format**: JSON with timestamp-based naming
- **Update Frequency**: Manual creation, automatic comparison
- **Retention**: Multiple baselines maintained for historical analysis

## Usage Commands

### Interactive Scanning

```bash
# Run full security assessment
sudo hardn legion --verbose

# Run with ML anomaly detection enabled
sudo hardn legion --ml-enabled --verbose

# Run with threat intelligence and automated response
sudo hardn legion --predictive --response-enabled --verbose

# Create new system baseline
sudo hardn legion --create-baseline

# Output results in JSON format
sudo hardn legion --json

# Get help and usage information
hardn legion --help
```

### Daemon Management

```bash
# Start Legion daemon with full capabilities
sudo systemctl start legion-daemon

# Stop Legion daemon
sudo systemctl stop legion-daemon

# Check daemon status
sudo systemctl status legion-daemon

# View daemon logs
sudo journalctl -u legion-daemon -f

# Restart daemon
sudo systemctl restart legion-daemon
```

### Advanced Configuration

```bash
# Daemon with ML and response enabled
sudo hardn legion --daemon --ml-enabled --response-enabled --verbose

# Interactive scan with all features
sudo hardn legion --ml-enabled --predictive --response-enabled --verbose --json
```

### Baseline Operations

```bash
# Create initial baseline (run on clean system)
sudo hardn legion --create-baseline

# View current baseline information
ls -la /var/lib/hardn/legion/

# Compare current system against baseline
sudo hardn legion --verbose
```

## Security Monitoring Checks

### Enhanced System Analysis

**Machine Learning Anomaly Detection:**
- K-means clustering for system behavior baselining
- Real-time anomaly scoring with confidence metrics
- Historical pattern analysis and trend detection

**Behavioral Analysis Engine:**
- Process behavior monitoring and classification
- Suspicious activity pattern recognition
- Connection analysis and network behavior tracking

**Threat Intelligence Integration:**
- HTTP-based threat feed processing and caching
- Security indicator correlation and matching
- Automated threat level assessment and alerting

### System Inventory Checks

**Operating System Information:**
- Distribution and version detection
- Kernel version and architecture
- Hostname and system identifiers

**Hardware Inventory:**
- CPU model, core count, and performance
- Memory capacity and utilization
- Storage devices and capacity

### Authentication Security Checks

**SSH Authentication Analysis:**
- Failed authentication attempts tracking
- SSH configuration compliance
- Key-based authentication validation

**Privilege Management:**
- Sudoers configuration analysis
- Passwordless sudo detection
- User privilege escalation monitoring

### Package Integrity Verification

**Package Database Validation:**
- Installed package integrity checks
- Package manager database consistency
- Dependency chain verification

**Binary Integrity Monitoring:**
- System binary permission analysis
- SUID/SGID file detection
- Critical binary modification detection

### Filesystem Security Analysis

**File Permission Auditing:**
- SUID/SGID file enumeration
- World-writable file detection
- Critical system file permission checks

**Startup Persistence Detection:**
- Systemd service enumeration
- Cron job analysis
- Init script validation

### Enhanced Process Security Monitoring

**Behavioral Process Analysis:**
- Process behavior classification (Normal, Suspicious, Malicious)
- Network connection pattern analysis
- Resource usage anomaly detection
- Process lifecycle monitoring

**Process Tree Analysis:**
- Orphan process detection
- Zombie process identification
- Process ownership validation
- Parent-child relationship analysis

**Executable Security Checks:**
- Suspicious file detection in /tmp
- Unusual executable permissions
- Process anomaly identification
- Behavioral scoring and alerting

### Enhanced Network Security Assessment

**Threat Intelligence Correlation:**
- IP address blacklisting and monitoring
- Domain reputation checking
- File hash analysis and blocking
- Package vulnerability assessment

**Socket Analysis:**
- Listening port enumeration
- Suspicious port detection
- Network service exposure analysis
- Connection behavior monitoring

**Firewall Configuration:**
- UFW/iptables rule validation
- Firewall policy verification
- Network access control auditing
- Automated blocking capabilities

### Kernel Security Validation

**Kernel Module Security:**
- Loaded module enumeration
- Suspicious module detection
- Kernel extension analysis

**System Control Parameters:**
- Sysctl security setting validation
- Kernel parameter compliance checks
- Security-related kernel configuration

### Container Security Checks

**Container Runtime Detection:**
- Docker container enumeration
- Podman container analysis
- Container privilege escalation detection

**Build Tool Security:**
- Development tool availability
- Compiler and interpreter security
- Build environment validation

## Advanced Security Features

### Real-time Risk Scoring

**Adaptive Risk Assessment:**
- Multi-component risk calculation (anomaly, threat, behavioral, network, process, file, system health)
- Weighted scoring with adaptive algorithms
- Confidence metrics and contributing factor analysis
- Historical trending and risk level classification

**Risk Level Classification:**
- **Low (0.0-0.3)**: Normal system operation
- **Medium (0.3-0.7)**: Potential security concerns
- **High (0.7-0.9)**: Significant security risks
- **Critical (0.9-1.0)**: Immediate threat detected

### Automated Response System

**Response Orchestration:**
- Rule-based automated actions
- Process isolation and termination
- Network blocking and access control
- Incident logging and alerting

**Response Actions:**
- Process quarantine and isolation
- Network connection blocking
- Alert channel notifications
- Rate-limited execution with cooldowns

### Incident Correlation Engine

**Multi-Logic Correlation:**
- **Any Logic**: Trigger on any matching condition
- **All Logic**: Require all conditions to be met
- **Weighted Logic**: Threshold-based condition evaluation
- **Sequence Logic**: Time-ordered event pattern matching

**Correlation Rules:**
- Configurable condition matching
- Time window analysis
- Confidence scoring and incident creation
- Active incident tracking and status management

## Output Formats

### Human-Readable Output

```
LEGION - Heuristics Monitoring Script
==========================================
Loading baseline for comparison...
Loaded baseline from: /var/lib/hardn/legion/baseline_1758753033.json
Baseline loaded
Running system inventory checks...
  System Information:
    OS: Ubuntu 24.04.3 LTS
    Kernel: 6.14.0-29-generic
    Architecture: x86_64
    Hostname: tim-P53
  Hardware Information:
    CPU: Intel(R) Core(TM) i7-9750H CPU @ 2.60GHz (12 cores)
    Memory: 78 GB
Running authentication checks...
  Checking authentication failures...
    Found 1 SSH authentication failures in last hour
  Checking sudoers configuration...
    No passwordless sudo entries found
  Checking SSH configuration...
[... continues with all checks ...]
LEGION monitoring completed successfully
```

### JSON Output Format

```bash
sudo hardn legion --json
```

```json
{
  "timestamp": "2025-09-24T18:40:00Z",
  "system_info": {
    "os": "Ubuntu 24.04.3 LTS",
    "kernel": "6.14.0-29-generic",
    "architecture": "x86_64",
    "hostname": "tim-P53"
  },
  "hardware_info": {
    "cpu": "Intel(R) Core(TM) i7-9750H CPU @ 2.60GHz",
    "cpu_cores": 12,
    "memory_gb": 78
  },
  "security_checks": {
    "authentication": {
      "ssh_failures": 1,
      "passwordless_sudo": false
    },
    "filesystem": {
      "suid_sgid_files": 28,
      "systemd_services": 83
    },
    "network": {
      "listening_ports": 18,
      "firewall_active": true
    }
  },
  "anomalies_detected": 0,
  "status": "completed"
}
```

## Baseline System

### Creating Baselines

```bash
# Create baseline on a known-good system
sudo hardn legion --create-baseline
```

This creates a JSON file containing:
- System configuration snapshots
- Normal process patterns
- Expected file permissions
- Standard network configurations
- Baseline security metrics

### Baseline Comparison

When Legion runs, it:
1. Loads the most recent baseline
2. Compares current system state
3. Identifies deviations and anomalies
4. Reports potential security issues
5. Updates baseline with new "normal" patterns

### Baseline Management

```bash
# View available baselines
ls /var/lib/hardn/legion/baseline_*.json

# Backup important baselines
cp /var/lib/hardn/legion/baseline_1758753033.json /backup/

# Remove old baselines (keep last 5)
cd /var/lib/hardn/legion/
ls -t baseline_*.json | tail -n +6 | xargs rm
```

## Daemon Mode Operation

### Continuous Monitoring

The Legion daemon provides:
- **Real-time Analysis**: Continuous system state monitoring
- **Anomaly Detection**: Immediate alerting on suspicious activities
- **Log Integration**: Systemd journal integration
- **Resource Management**: Configurable memory and CPU limits

### Daemon Logging

```bash
# View recent daemon activity
sudo journalctl -u legion-daemon -n 50

# Follow daemon logs in real-time
sudo journalctl -u legion-daemon -f

# Search for specific events
sudo journalctl -u legion-daemon | grep "anomaly"
```

### Daemon Configuration

The daemon can be configured via environment variables or configuration files:

```bash
# Set monitoring interval (default: continuous)
export LEGION_MONITOR_INTERVAL=300

# Enable JSON logging
export LEGION_JSON_LOG=true

# Set log level
export LEGION_LOG_LEVEL=debug
```

## Integration with HARDN API

### API Endpoints

Legion data integrates with HARDN API endpoints:

- **Service Status**: `/overwatch/services` includes legion-daemon status
- **System Health**: `/overwatch/system` incorporates Legion security metrics
- **Security Events**: Legion anomalies feed into API monitoring alerts
- **Command Execution**: `/hardn/execute` can trigger Legion scans

### Remote Monitoring

```bash
# Check Legion daemon status via API
curl -H "Authorization: Bearer YOUR_SSH_KEY" http://localhost:8000/overwatch/services | jq '.services."legion-daemon.service"'

# Trigger Legion scan remotely
curl -X POST -H "Authorization: Bearer YOUR_SSH_KEY" \
  -H "Content-Type: application/json" \
  -d '{"command": "legion --verbose"}' \
  http://localhost:8000/hardn/execute
```

## Security Considerations

### Privilege Requirements

- **Root Access**: Required for comprehensive system monitoring
- **Service User**: Legion daemon runs as dedicated `hardn` user
- **Minimal Permissions**: Restricted filesystem access where possible

### Performance Impact

- **CPU Usage**: Low baseline monitoring (~1-2% CPU)
- **Memory Usage**: Configurable limits (default 256MB)
- **Disk I/O**: Minimal logging and baseline storage
- **Network**: Local socket analysis only

### False Positive Management

- **Baseline Tuning**: Regular baseline updates reduce false positives
- **Threshold Configuration**: Adjustable sensitivity settings
- **Whitelist Management**: Known safe processes/patterns can be excluded

## Troubleshooting

### Common Issues

**Daemon won't start:**
```bash
# Check service status
sudo systemctl status legion-daemon

# Check for missing dependencies
sudo hardn legion --help

# Verify user permissions
id hardn
```

**High resource usage:**
```bash
# Check daemon process
ps aux | grep legion

# Adjust memory limits
sudo systemctl edit legion-daemon
# Add: MemoryLimit=128M
```

**Baseline loading errors:**
```bash
# Check baseline file permissions
ls -la /var/lib/hardn/legion/

# Recreate baseline
sudo rm /var/lib/hardn/legion/baseline_*.json
sudo hardn legion --create-baseline
```

### Log Analysis

**Error Patterns:**
```bash
# Search for errors
sudo journalctl -u legion-daemon | grep "ERROR\|error"

# Check for permission issues
sudo journalctl -u legion-daemon | grep "permission\|access"
```

**Performance Monitoring:**
```bash
# Monitor daemon resource usage
sudo systemd-cgtop | grep legion

# Check log volume
sudo journalctl -u legion-daemon --since "1 hour ago" | wc -l
```

## Command Reference

### Legion Command Options

| Option | Description |
|--------|-------------|
| `--create-baseline` | Create new system baseline |
| `--ml-enabled` | Enable machine learning anomaly detection |
| `--predictive` | Enable threat intelligence and predictive analysis |
| `--response-enabled` | Enable automated response and incident handling |
| `--verbose` | Detailed output with all checks and metrics |
| `--json` | JSON formatted output for automation |
| `--daemon` | Run as background monitoring daemon |
| `--help` | Display help information |
| `--version` | Show version information |

### Systemd Service Commands

```bash
# Service management
sudo systemctl start legion-daemon
sudo systemctl stop legion-daemon
sudo systemctl restart legion-daemon
sudo systemctl status legion-daemon

# Log management
sudo journalctl -u legion-daemon
sudo journalctl -u legion-daemon -f
sudo journalctl -u legion-daemon --since "1 hour ago"
```

## Example Use Cases

### Comprehensive Security Assessment

```bash
# Full security assessment with ML and threat intelligence
sudo hardn legion --ml-enabled --predictive --response-enabled --verbose

# Generate detailed security report
sudo hardn legion --ml-enabled --verbose > security_audit_$(date +%Y%m%d).txt

# JSON output for automated processing and integration
sudo hardn legion --json | jq '.risk_score, .contributing_factors'
```

### ML-Powered Anomaly Detection

```bash
# Create baseline for ML training
sudo hardn legion --create-baseline

# Run ML-enabled monitoring
sudo hardn legion --ml-enabled --verbose

# Monitor for anomalies with automated response
sudo hardn legion --ml-enabled --response-enabled --daemon
```

### Threat Intelligence Integration

```bash
# Enable threat intelligence scanning
sudo hardn legion --predictive --verbose

# Full threat hunting with correlation
sudo hardn legion --predictive --response-enabled --ml-enabled --verbose
```

### Continuous Monitoring Setup

```bash
# Enable and start enhanced daemon
sudo systemctl enable legion-daemon
sudo systemctl start legion-daemon

# Monitor logs for anomalies and incidents
sudo journalctl -u legion-daemon -f | grep -E "(anomaly|incident|risk)"
sudo journalctl -u legion-daemon -f | grep -i anomaly
```

### Incident Response

```bash
# Quick system state assessment
sudo hardn legion --verbose | head -50

# Create incident baseline
sudo hardn legion --create-baseline

# Compare against known good state
sudo hardn legion --verbose | grep -i anomal
```

## Performance Optimization

### Resource Tuning

```bash
# Adjust daemon memory limits
sudo systemctl edit legion-daemon
[Service]
MemoryLimit=128M
CPUQuota=50%

# Set monitoring intervals (if implemented)
export LEGION_SCAN_INTERVAL=1800  # 30 minutes
```

### Log Management

```bash
# Configure log rotation
sudo journalctl --vacuum-time=7d -u legion-daemon

# Limit log size
sudo journalctl --vacuum-size=100M -u legion-daemon
```

### Baseline Optimization

```bash
# Regular baseline updates
sudo hardn legion --create-baseline

# Clean old baselines
find /var/lib/hardn/legion/ -name "baseline_*.json" -mtime +30 -delete
```

## Advanced Heuristics Monitoring & Response

### Current Capabilities Enhancement

#### 1. Machine Learning Anomaly Detection
```rust
// Enhanced baseline with ML clustering
pub struct MLBaseline {
    normal_patterns: Vec<FeatureVector>,
    anomaly_threshold: f64,
    model: Option<RandomForest>,
}

impl MLBaseline {
    pub fn train(&mut self, historical_data: Vec<SystemSnapshot>) {
        // Train ML model on normal system behavior
        // Use clustering to identify normal patterns
        // Calculate dynamic anomaly thresholds
    }

    pub fn detect_anomaly(&self, current_state: &SystemSnapshot) -> AnomalyScore {
        // Compare current state against ML model
        // Return confidence score and anomaly type
    }
}
```

#### 2. Behavioral Process Analysis
```rust
pub struct ProcessBehavior {
    process_id: u32,
    parent_pid: u32,
    command_line: String,
    network_connections: Vec<Connection>,
    file_access: Vec<FileOperation>,
    system_calls: Vec<SystemCall>,
    memory_usage: MemoryStats,
    cpu_usage: CpuStats,
}

impl ProcessBehavior {
    pub fn analyze_behavior(&self) -> BehaviorClassification {
        // Analyze process behavior patterns
        // Detect suspicious activities like:
        // - Unusual network connections
        // - Suspicious file access patterns
        // - Abnormal system call sequences
        // - Memory allocation anomalies
    }
}
```

#### 3. Threat Intelligence Integration
```rust
pub struct ThreatIntelligence {
    ip_blacklist: HashSet<IpAddr>,
    domain_blacklist: HashSet<String>,
    file_hash_blacklist: HashSet<String>,
    cve_database: HashMap<String, Vulnerability>,
}

impl ThreatIntelligence {
    pub async fn update_feeds(&mut self) {
        // Fetch updates from threat intelligence feeds
        // - AbuseIPDB, AlienVault OTX
        // - VirusTotal, MalwareBazaar
        // - NIST CVE database
    }

    pub fn check_indicator(&self, indicator: &SecurityIndicator) -> ThreatLevel {
        // Check against threat intelligence
        // Return threat classification
    }
}
```

### Automated Response System

#### 4. Response Orchestration Engine
```rust
pub enum ResponseAction {
    IsolateProcess { pid: u32 },
    BlockNetwork { ip: IpAddr, port: u16 },
    QuarantineFile { path: PathBuf },
    KillProcess { pid: u32 },
    DisableService { name: String },
    AlertAdmin { message: String, severity: Severity },
    LogIncident { details: IncidentDetails },
}

pub struct ResponseEngine {
    response_rules: Vec<ResponseRule>,
    quarantine_dir: PathBuf,
    alert_channels: Vec<AlertChannel>,
}

impl ResponseEngine {
    pub async fn execute_response(&self, anomaly: &Anomaly) -> Result<(), ResponseError> {
        // Evaluate response rules
        // Execute appropriate actions
        // Log response activities
    }
}
```

#### 5. Incident Correlation Engine
```rust
pub struct IncidentCorrelator {
    event_window: TimeWindow,
    correlation_rules: Vec<CorrelationRule>,
    active_incidents: HashMap<String, Incident>,
}

impl IncidentCorrelator {
    pub fn correlate_events(&mut self, events: Vec<SecurityEvent>) -> Vec<Incident> {
        // Group related security events
        // Identify attack patterns
        // Create incident reports
        // Update incident status
    }
}
```

### Enhanced Monitoring Features

#### 6. Real-time Risk Scoring
```rust
#[derive(Debug, Clone)]
pub struct RiskScore {
    overall_score: f64,  // 0.0 to 1.0
    components: HashMap<String, f64>,
    confidence: f64,
    timestamp: DateTime<Utc>,
}

impl RiskScore {
    pub fn calculate(&mut self, system_state: &SystemState) -> f64 {
        // Calculate risk based on:
        // - Anomaly severity
        // - Asset criticality
        // - Threat intelligence
        // - Historical patterns
        // - Environmental factors
    }
}
```

#### 7. Predictive Analysis
```rust
pub struct PredictiveAnalyzer {
    historical_data: Vec<SystemSnapshot>,
    prediction_model: Option<TimeSeriesModel>,
    prediction_window: Duration,
}

impl PredictiveAnalyzer {
    pub fn predict_threats(&self) -> Vec<PredictedThreat> {
        // Analyze trends in system behavior
        // Predict potential security issues
        // Forecast resource exhaustion
        // Identify emerging attack patterns
    }
}
```

### Implementation Roadmap

#### Phase 1: Core Enhancements
```bash
# Enhanced Legion with ML capabilities
sudo hardn legion --ml-enabled --train-model
sudo hardn legion --predictive-analysis

# Automated response testing
sudo hardn legion --response-test --dry-run
sudo hardn legion --incident-correlation
```

#### Phase 2: Advanced Features
```bash
# Threat intelligence integration
sudo hardn legion --threat-intel-update
sudo hardn legion --check-indicators

# Behavioral analysis
sudo hardn legion --behavior-analysis --process-tracking
sudo hardn legion --network-behavior
```

#### Phase 3: Enterprise Integration
```bash
# SIEM integration
sudo hardn legion --siem-export --format=cef
sudo hardn legion --webhook-alerts

# Multi-system correlation
sudo hardn legion --distributed-monitoring --cluster-nodes=10
```

### Configuration Examples

#### Enhanced legion.conf
```ini
[ml_detection]
enabled = true
model_path = /var/lib/hardn/legion/models/
training_interval = 24h
anomaly_threshold = 0.85

[automated_response]
enabled = true
dry_run = false
max_actions_per_hour = 10
quarantine_path = /var/lib/hardn/quarantine/

[threat_intelligence]
update_interval = 1h
feeds = abuseipdb,alienvault,virustotal
cache_ttl = 24h

[risk_scoring]
enabled = true
weight_anomalies = 0.4
weight_threat_intel = 0.3
weight_behavior = 0.3

[predictive_analysis]
enabled = true
forecast_window = 24h
confidence_threshold = 0.8
```

### API Integration Enhancements

#### New API Endpoints
```python
# Risk scoring endpoint
@app.get("/legion/risk-score")
def get_risk_score(api_key: str = Depends(verify_ssh_key)):
    return legion_engine.get_current_risk_score()

# Predictive threats
@app.get("/legion/predictions")
def get_predictions(api_key: str = Depends(verify_ssh_key)):
    return legion_engine.get_predicted_threats()

# Automated responses
@app.post("/legion/response")
def trigger_response(action: ResponseAction, api_key: str = Depends(verify_ssh_key)):
    return legion_engine.execute_response(action)

# Threat intelligence
@app.get("/legion/threat-intel")
def get_threat_intel(api_key: str = Depends(verify_ssh_key)):
    return legion_engine.get_threat_intelligence()
```

### Performance Considerations

#### Resource Optimization
- **ML Model Caching**: Cache trained models to reduce CPU usage
- **Incremental Updates**: Update baselines incrementally rather than full rebuilds
- **Parallel Processing**: Use multiple threads for different analysis types
- **Memory Pooling**: Reuse memory allocations for frequent operations

#### Scalability Features
- **Distributed Analysis**: Support for multi-node Legion deployments
- **Load Balancing**: Distribute monitoring tasks across cluster nodes
- **Data Partitioning**: Partition baseline data for large environments
- **Streaming Analytics**: Real-time analysis of high-volume event streams

### Security Hardening

#### Response Action Security
- **Action Validation**: Validate all automated responses before execution
- **Rollback Capability**: Ability to undo automated actions
- **Audit Logging**: Comprehensive logging of all response actions
- **Access Control**: Role-based permissions for response actions

#### Data Protection
- **Encryption**: Encrypt sensitive baseline and model data
- **Integrity Checks**: Verify integrity of ML models and baselines
- **Secure Updates**: Authenticated updates for threat intelligence feeds
- **Privacy Preservation**: Anonymize data used for behavioral analysis

This enhanced Legion system would provide enterprise-grade security monitoring with intelligent threat detection, automated response capabilities, and predictive analysis for comprehensive cybersecurity protection.