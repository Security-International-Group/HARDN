use crate::core::config::{EXIT_FAILURE, EXIT_SUCCESS, EXIT_USAGE};
use crate::core::{HardnError, HardnResult};
use crate::utils::{log_message, LogLevel};
use libc::geteuid;
use serde_json::json;
use std::env;
use std::fs::{self, File};
use std::io::Write;
use std::os::unix::fs as unix_fs;
use std::path::Path;
use std::process::{Command, Stdio};

const GRAFANA_KEY_URL: &str = "https://packages.grafana.com/gpg.key";
const GRAFANA_KEYRING_PATH: &str = "/usr/share/keyrings/grafana.gpg";
const GRAFANA_REPO_FILE: &str = "/etc/apt/sources.list.d/grafana.list";
const GRAFANA_REPO_LINE: &str =
	"deb [signed-by=/usr/share/keyrings/grafana.gpg arch=amd64] https://packages.grafana.com/oss/deb stable main\n";
const GRAFANA_CONFIG_PATH: &str = "/etc/grafana/grafana.ini";
const GRAFANA_DATA_DIR: &str = "/var/lib/grafana";
const GRAFANA_LOG_DIR: &str = "/var/log/grafana";
const GRAFANA_PLUGINS_DIR: &str = "/var/lib/grafana/plugins";
const GRAFANA_SERVICE_NAME: &str = "hardn-grafana";
const GRAFANA_SYSTEMD_UNIT: &str = "/etc/systemd/system/hardn-grafana.service";
const GRAFANA_SYSTEMD_SYMLINK: &str =
    "/etc/systemd/system/multi-user.target.wants/hardn-grafana.service";
const GRAFANA_PORT: u16 = 3000;
const GRAFANA_PROVISIONING_DIR: &str = "/etc/grafana/provisioning";
const GRAFANA_DATASOURCES_DIR: &str = "/etc/grafana/provisioning/datasources";
const GRAFANA_DASHBOARDS_DIR: &str = "/etc/grafana/provisioning/dashboards";
const GRAFANA_DATASOURCE_FILE: &str = "/etc/grafana/provisioning/datasources/hardn.yml";
const GRAFANA_DASHBOARD_PROVIDER_FILE: &str = "/etc/grafana/provisioning/dashboards/hardn.yml";
const GRAFANA_DASHBOARD_ROOT: &str = "/var/lib/grafana/dashboards";
const HARDN_DASHBOARD_DIR: &str = "/var/lib/grafana/dashboards/hardn";
const HARDN_DASHBOARD_FILE: &str = "/var/lib/grafana/dashboards/hardn/system-overview.json";

const UNIT_TEMPLATE: &str = r"[Unit]
Description=HARDN Grafana Visualization Service
After=network.target hardn.service hardn-monitor.service
Wants=network.target hardn.service hardn-monitor.service

[Service]
Type=simple
User=grafana
Group=grafana
Environment=GF_PATHS_DATA=/var/lib/grafana
Environment=GF_PATHS_LOGS=/var/log/grafana
Environment=GF_PATHS_PLUGINS=/var/lib/grafana/plugins
Environment=GF_SERVER_HTTP_PORT=3000
ExecStart=/usr/sbin/grafana-server --config=/etc/grafana/grafana.ini --homepath=/usr/share/grafana
Restart=always
RestartSec=10
LimitNOFILE=65536
StandardOutput=journal
StandardError=journal
SyslogIdentifier=hardn-grafana

# Security Hardening
NoNewPrivileges=yes
ProtectHome=yes
ProtectSystem=strict
ReadWritePaths=/var/lib/grafana /var/log/grafana
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
";

#[derive(Debug, Default)]
pub struct ServiceState {
    installed: bool,
    active: bool,
    enabled: bool,
}

pub struct GrafanaManager;

impl GrafanaManager {
    pub fn new() -> Self {
        Self
    }

    pub fn install(&self) -> HardnResult<()> {
        require_root("install Grafana")?;

        log_message(LogLevel::Info, "Configuring Grafana APT repository");
        self.ensure_repository()?;

        log_message(LogLevel::Info, "Updating package index");
        run_command_with_env(
            "apt-get",
            &["update"],
            Some(&[("DEBIAN_FRONTEND", "noninteractive")]),
        )?;

        log_message(LogLevel::Info, "Installing grafana package");
        run_command_with_env(
            "apt-get",
            &["install", "-y", "grafana"],
            Some(&[("DEBIAN_FRONTEND", "noninteractive")]),
        )?;

        log_message(
            LogLevel::Info,
            "Ensuring Grafana JSON API plugin (marcusolsson-json-datasource) is available",
        );
        self.optional_command(
            "/usr/sbin/grafana-cli",
            &["plugins", "install", "marcusolsson-json-datasource"],
        );

        self.configure()?;

        log_message(LogLevel::Info, "Enabling Grafana service");
        run_command("systemctl", &["enable", GRAFANA_SERVICE_NAME])?;
        self.ensure_systemd_symlink()?;

        log_message(LogLevel::Info, "Starting Grafana service");
        run_command("systemctl", &["start", GRAFANA_SERVICE_NAME])?;
        self.verify_service_running()?;

        if let Err(err) = self.configure_firewall() {
            log_message(
                LogLevel::Warning,
                &format!("Skipping firewall configuration: {}", err),
            );
        }

        log_message(
            LogLevel::Pass,
            "Grafana installation completed successfully",
        );
        Ok(())
    }

    pub fn configure(&self) -> HardnResult<()> {
        require_root("configure Grafana")?;

        self.ensure_directories()?;
        self.write_config()?;
        self.deploy_systemd_unit()?;
        self.write_datasource_provisioning()?;
        self.write_dashboard_provisioning()?;
        self.write_system_dashboard()?;
        run_command("systemctl", &["daemon-reload"])?;

        Ok(())
    }

    pub fn start_service(&self) -> HardnResult<()> {
        require_root("start Grafana service")?;
        run_command("systemctl", &["start", GRAFANA_SERVICE_NAME])?;
        self.verify_service_running()
    }

    pub fn stop_service(&self) -> HardnResult<()> {
        require_root("stop Grafana service")?;
        run_command("systemctl", &["stop", GRAFANA_SERVICE_NAME])
    }

    pub fn restart_service(&self) -> HardnResult<()> {
        require_root("restart Grafana service")?;
        run_command("systemctl", &["restart", GRAFANA_SERVICE_NAME])?;
        self.verify_service_running()
    }

    pub fn enable_service(&self) -> HardnResult<()> {
        require_root("enable Grafana service")?;
        run_command("systemctl", &["enable", GRAFANA_SERVICE_NAME])?;
        self.ensure_systemd_symlink()
    }

    pub fn disable_service(&self) -> HardnResult<()> {
        require_root("disable Grafana service")?;
        run_command("systemctl", &["disable", GRAFANA_SERVICE_NAME])
    }

    pub fn status(&self) -> HardnResult<ServiceState> {
        let installed = Path::new(GRAFANA_SYSTEMD_UNIT).exists()
            || Path::new("/lib/systemd/system/grafana-server.service").exists()
            || Path::new("/etc/systemd/system/grafana-server.service").exists();

        let active = Command::new("systemctl")
            .args(&["is-active", GRAFANA_SERVICE_NAME])
            .output()
            .map(|output| output.status.success())
            .unwrap_or(false);

        let enabled = Command::new("systemctl")
            .args(&["is-enabled", GRAFANA_SERVICE_NAME])
            .output()
            .map(|output| output.status.success())
            .unwrap_or(false);

        Ok(ServiceState {
            installed,
            active,
            enabled,
        })
    }

    fn ensure_repository(&self) -> HardnResult<()> {
        if !Path::new(GRAFANA_KEYRING_PATH).exists() {
            let key_bytes = Command::new("curl")
                .args(&["-fsSL", GRAFANA_KEY_URL])
                .output()
                .map_err(|e| {
                    HardnError::ExecutionFailed(format!(
                        "Failed to download Grafana GPG key: {}",
                        e
                    ))
                })?;

            if !key_bytes.status.success() {
                return Err(HardnError::ExecutionFailed(format!(
                    "Unable to download Grafana GPG key: {}",
                    String::from_utf8_lossy(&key_bytes.stderr)
                )));
            }

            let mut child = Command::new("gpg")
                .args(&["--dearmor", "-o", GRAFANA_KEYRING_PATH])
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .spawn()
                .map_err(|e| {
                    HardnError::ExecutionFailed(format!(
                        "Failed to start gpg to import Grafana key: {}",
                        e
                    ))
                })?;

            if let Some(stdin) = child.stdin.as_mut() {
                stdin.write_all(&key_bytes.stdout).map_err(|e| {
                    HardnError::ExecutionFailed(format!(
                        "Failed to write Grafana key to gpg: {}",
                        e
                    ))
                })?;
            }

            let status = child.wait().map_err(|e| {
                HardnError::ExecutionFailed(format!("Failed to import Grafana key: {}", e))
            })?;

            if !status.success() {
                return Err(HardnError::ExecutionFailed(
                    "gpg returned non-zero exit code while importing Grafana key".into(),
                ));
            }

            log_message(
                LogLevel::Pass,
                &format!(
                    "Imported Grafana repository key into {}",
                    GRAFANA_KEYRING_PATH
                ),
            );
        }

        if !Path::new(GRAFANA_REPO_FILE).exists() {
            fs::write(GRAFANA_REPO_FILE, GRAFANA_REPO_LINE)?;
            log_message(
                LogLevel::Pass,
                &format!("Configured Grafana repository at {}", GRAFANA_REPO_FILE),
            );
        }

        Ok(())
    }

    fn ensure_directories(&self) -> HardnResult<()> {
        for path in [
            GRAFANA_DATA_DIR,
            GRAFANA_LOG_DIR,
            GRAFANA_PLUGINS_DIR,
            GRAFANA_PROVISIONING_DIR,
            GRAFANA_DATASOURCES_DIR,
            GRAFANA_DASHBOARDS_DIR,
            GRAFANA_DASHBOARD_ROOT,
            HARDN_DASHBOARD_DIR,
        ] {
            if !Path::new(path).exists() {
                fs::create_dir_all(path)?;
                log_message(LogLevel::Info, &format!("Created {}", path));
            }
        }

        self.optional_command("chown", &["-R", "grafana:grafana", GRAFANA_DATA_DIR]);
        self.optional_command("chown", &["-R", "grafana:grafana", GRAFANA_LOG_DIR]);
        self.optional_command("chown", &["-R", "grafana:grafana", GRAFANA_PLUGINS_DIR]);
        self.optional_command("chown", &["-R", "grafana:grafana", GRAFANA_DASHBOARD_ROOT]);

        Ok(())
    }

    fn write_datasource_provisioning(&self) -> HardnResult<()> {
        let bridge_url = env::var("HARDN_GRAFANA_BRIDGE_URL")
            .unwrap_or_else(|_| "http://127.0.0.1:8686".to_string());

        let contents = format!(
            r#"apiVersion: 1
datasources:
  - name: HARDN Monitor
    uid: hardn-json-api
    type: marcusolsson-json-datasource
    access: proxy
    url: {bridge_url}
    jsonData:
      httpMethod: GET
      timeout: 5000
"#,
            bridge_url = bridge_url
        );

        log_message(
            LogLevel::Info,
            &format!("Provisioning Grafana datasource at {}", bridge_url),
        );

        let mut file = File::create(GRAFANA_DATASOURCE_FILE)?;
        file.write_all(contents.as_bytes())?;
        file.sync_all()?;
        self.optional_command("chown", &["grafana:grafana", GRAFANA_DATASOURCE_FILE]);

        Ok(())
    }

    fn write_dashboard_provisioning(&self) -> HardnResult<()> {
        let contents = format!(
            r#"apiVersion: 1
providers:
  - name: 'HARDN Dashboards'
    orgId: 1
    folder: 'HARDN'
    type: file
    disableDeletion: false
    editable: true
    updateIntervalSeconds: 30
    options:
      path: {}
"#,
            HARDN_DASHBOARD_DIR
        );

        let mut file = File::create(GRAFANA_DASHBOARD_PROVIDER_FILE)?;
        file.write_all(contents.as_bytes())?;
        file.sync_all()?;
        self.optional_command(
            "chown",
            &["grafana:grafana", GRAFANA_DASHBOARD_PROVIDER_FILE],
        );

        Ok(())
    }

    fn write_system_dashboard(&self) -> HardnResult<()> {
        let dashboard = json!({
            "id": null,
            "uid": "hardn-system-overview",
            "title": "HARDN System Overview",
            "tags": ["hardn", "systemd"],
            "timezone": "browser",
            "schemaVersion": 38,
            "version": 1,
            "refresh": "30s",
            "time": {"from": "now-6h", "to": "now"},
            "templating": {"list": []},
            "annotations": {"list": []},
            "panels": [
                {
                    "id": 1,
                    "type": "stat",
                    "title": "Service Coverage",
                    "gridPos": {"h": 4, "w": 8, "x": 0, "y": 0},
                    "datasource": {"type": "marcusolsson-json-datasource", "uid": "hardn-json-api"},
                    "targets": [
                        {
                            "refId": "A",
                            "format": "table",
                            "datasource": {"type": "marcusolsson-json-datasource", "uid": "hardn-json-api"},
                            "path": "/grafana/systemd"
                        }
                    ],
                    "options": {
                        "reduceOptions": {"calcs": ["count"], "fields": "Unit", "values": false},
                        "orientation": "horizontal",
                        "textMode": "value"
                    }
                },
                {
                    "id": 2,
                    "type": "table",
                    "title": "Systemd Service Status",
                    "gridPos": {"h": 16, "w": 24, "x": 0, "y": 4},
                    "datasource": {"type": "marcusolsson-json-datasource", "uid": "hardn-json-api"},
                    "targets": [
                        {
                            "refId": "A",
                            "format": "table",
                            "datasource": {"type": "marcusolsson-json-datasource", "uid": "hardn-json-api"},
                            "path": "/grafana/systemd"
                        }
                    ],
                    "fieldConfig": {
                        "defaults": {"custom": {"align": "auto"}},
                        "overrides": []
                    },
                    "options": {
                        "showHeader": true,
                        "footer": {
                            "show": false,
                            "fields": "",
                            "reducer": ["sum"]
                        }
                    }
                }
            ]
        });

        let dashboard_json = serde_json::to_string_pretty(&dashboard).map_err(|err| {
            HardnError::ExecutionFailed(format!(
                "Failed to serialize Grafana dashboard definition: {}",
                err
            ))
        })?;

        let mut file = File::create(HARDN_DASHBOARD_FILE)?;
        file.write_all(dashboard_json.as_bytes())?;
        file.sync_all()?;
        self.optional_command("chown", &["grafana:grafana", HARDN_DASHBOARD_FILE]);

        Ok(())
    }

    fn ensure_systemd_symlink(&self) -> HardnResult<()> {
        let wants_dir = Path::new("/etc/systemd/system/multi-user.target.wants");
        if !wants_dir.exists() {
            fs::create_dir_all(wants_dir)?;
        }

        let link_path = Path::new(GRAFANA_SYSTEMD_SYMLINK);
        if link_path.exists() {
            if let Ok(target) = fs::read_link(link_path) {
                if target == Path::new(GRAFANA_SYSTEMD_UNIT) {
                    return Ok(());
                }
            }
            fs::remove_file(link_path)?;
        }

        unix_fs::symlink(GRAFANA_SYSTEMD_UNIT, link_path)?;
        log_message(
            LogLevel::Info,
            &format!(
                "Created systemd symlink {} -> {}",
                link_path.display(),
                GRAFANA_SYSTEMD_UNIT
            ),
        );

        Ok(())
    }

    fn verify_service_running(&self) -> HardnResult<()> {
        let output = Command::new("systemctl")
            .args(&["is-active", GRAFANA_SERVICE_NAME])
            .output()?;

        if output.status.success() && String::from_utf8_lossy(&output.stdout).trim() == "active" {
            log_message(LogLevel::Pass, "Grafana service is active and running");
            Ok(())
        } else {
            Err(HardnError::ExecutionFailed(format!(
                "Grafana service failed to start (stdout: {}, stderr: {})",
                String::from_utf8_lossy(&output.stdout).trim(),
                String::from_utf8_lossy(&output.stderr).trim()
            )))
        }
    }

    fn write_config(&self) -> HardnResult<()> {
        let admin_user = env::var("HARDN_GRAFANA_ADMIN_USER").unwrap_or_else(|_| "admin".into());
        let admin_password =
            env::var("HARDN_GRAFANA_ADMIN_PASSWORD").unwrap_or_else(|_| "changeme".into());

        if admin_password == "changeme" {
            log_message(
				LogLevel::Warning,
				"Using default Grafana admin password 'changeme'; set HARDN_GRAFANA_ADMIN_PASSWORD to change",
			);
        }

        let config = format!(
            r#"; Managed by HARDN - do not edit manually without updating automation
[server]
http_port = {port}
domain = localhost
root_url = http://localhost:{port}/
serve_from_sub_path = false

[security]
admin_user = {admin_user}
admin_password = {admin_password}
disable_gravatar = true
cookie_secure = true

[users]
default_theme = dark
auto_assign_org_role = Admin

[auth.anonymous]
enabled = false

[metrics]
enabled = true

[paths]
data = {data_dir}
logs = {log_dir}
plugins = {plugins_dir}
provisioning = /etc/grafana/provisioning
"#,
            port = GRAFANA_PORT,
            admin_user = admin_user,
            admin_password = admin_password,
            data_dir = GRAFANA_DATA_DIR,
            log_dir = GRAFANA_LOG_DIR,
            plugins_dir = GRAFANA_PLUGINS_DIR,
        );

        if Path::new(GRAFANA_CONFIG_PATH).exists() {
            let existing = fs::read_to_string(GRAFANA_CONFIG_PATH)?;
            if !existing.contains("Managed by HARDN") {
                let backup_path = format!("{}.hardn.bak", GRAFANA_CONFIG_PATH);
                fs::write(&backup_path, existing)?;
                log_message(
                    LogLevel::Warning,
                    &format!("Existing Grafana config backed up to {}", backup_path),
                );
            }
        }

        let mut file = File::create(GRAFANA_CONFIG_PATH)?;
        file.write_all(config.as_bytes())?;
        file.sync_all()?;

        self.optional_command("chown", &["grafana:grafana", GRAFANA_CONFIG_PATH]);

        Ok(())
    }

    fn deploy_systemd_unit(&self) -> HardnResult<()> {
        let mut file = File::create(GRAFANA_SYSTEMD_UNIT)?;
        file.write_all(UNIT_TEMPLATE.as_bytes())?;
        file.sync_all()?;
        log_message(
            LogLevel::Info,
            &format!("Installed systemd unit at {}", GRAFANA_SYSTEMD_UNIT),
        );

        Ok(())
    }

    fn configure_firewall(&self) -> HardnResult<()> {
        require_root("adjust firewall rules for Grafana")?;

        let status_output = Command::new("ufw").arg("status").output();
        let output = match status_output {
            Ok(out) => out,
            Err(err) => {
                return Err(HardnError::ExecutionFailed(format!(
                    "ufw not available: {}",
                    err
                )));
            }
        };

        let stdout = String::from_utf8_lossy(&output.stdout);
        if stdout.contains("Status: inactive") {
            log_message(
                LogLevel::Info,
                "UFW is inactive; skipping Grafana firewall rule",
            );
            return Ok(());
        }

        let allow_cmd = Command::new("ufw")
            .args(&["allow", &format!("{}/tcp", GRAFANA_PORT)])
            .output();

        match allow_cmd {
            Ok(result) if result.status.success() => {
                log_message(
                    LogLevel::Pass,
                    &format!("Opened TCP port {} via UFW", GRAFANA_PORT),
                );
                Ok(())
            }
            Ok(result) => Err(HardnError::ExecutionFailed(format!(
                "Failed to open Grafana port: {}",
                String::from_utf8_lossy(&result.stderr)
            ))),
            Err(err) => Err(HardnError::ExecutionFailed(format!(
                "Failed to invoke ufw: {}",
                err
            ))),
        }
    }

    fn optional_command(&self, program: &str, args: &[&str]) {
        match Command::new(program).args(args).output() {
            Ok(output) if output.status.success() => {}
            Ok(output) => {
                log_message(
                    LogLevel::Warning,
                    &format!(
                        "Optional command {} {:?} exited with status {}: {}",
                        program,
                        args,
                        output.status,
                        String::from_utf8_lossy(&output.stderr)
                    ),
                );
            }
            Err(err) => {
                log_message(
                    LogLevel::Warning,
                    &format!("Optional command {} {:?} failed: {}", program, args, err),
                );
            }
        }
    }
}

pub fn handle_grafana_command(args: &[String]) -> i32 {
    let manager = GrafanaManager::new();

    if args.is_empty() {
        print_grafana_help();
        return EXIT_USAGE;
    }

    match args[0].as_str() {
        "install" | "setup" => handle_result(manager.install()),
        "configure" => handle_result(manager.configure()),
        "start" => handle_result(manager.start_service()),
        "stop" => handle_result(manager.stop_service()),
        "restart" => handle_result(manager.restart_service()),
        "enable" => handle_result(manager.enable_service()),
        "disable" => handle_result(manager.disable_service()),
        "status" => match manager.status() {
            Ok(state) => {
                if !state.installed {
                    log_message(
                        LogLevel::Warning,
                        "Grafana service not installed. Run 'hardn grafana install' first.",
                    );
                }

                if state.active {
                    log_message(LogLevel::Pass, "Grafana service is active and running");
                } else {
                    log_message(LogLevel::Info, "Grafana service is not running");
                }

                if state.enabled {
                    log_message(LogLevel::Info, "Grafana service is enabled on boot");
                } else {
                    log_message(LogLevel::Warning, "Grafana service is disabled on boot");
                }

                EXIT_SUCCESS
            }
            Err(err) => {
                log_message(
                    LogLevel::Error,
                    &format!("Failed to query Grafana status: {}", err),
                );
                EXIT_FAILURE
            }
        },
        "help" | "--help" | "-h" => {
            print_grafana_help();
            EXIT_SUCCESS
        }
        other => {
            log_message(
                LogLevel::Error,
                &format!("Unknown Grafana subcommand: {}", other),
            );
            print_grafana_help();
            EXIT_USAGE
        }
    }
}

pub fn print_grafana_help() {
    println!(
        r#"Grafana integration commands:

  hardn grafana install      Install Grafana OSS and configure dashboards
  hardn grafana setup        Alias for install
  hardn grafana configure    Reapply HARDN defaults (config, unit, dirs)
  hardn grafana start        Start the Grafana service
  hardn grafana stop         Stop the Grafana service
  hardn grafana restart      Restart the Grafana service
  hardn grafana enable       Enable Grafana to start on boot
  hardn grafana disable      Disable Grafana from starting on boot
  hardn grafana status       Show current Grafana service state

Environment overrides:
  HARDN_GRAFANA_ADMIN_USER        Change default admin username (default: admin)
  HARDN_GRAFANA_ADMIN_PASSWORD    Change default admin password (default: changeme)

Note: Commands that modify the system require root privileges.
"#
    );
}

fn handle_result(result: HardnResult<()>) -> i32 {
    match result {
        Ok(_) => EXIT_SUCCESS,
        Err(err) => {
            log_message(
                LogLevel::Error,
                &format!("Grafana operation failed: {}", err),
            );
            EXIT_FAILURE
        }
    }
}

fn run_command(program: &str, args: &[&str]) -> HardnResult<()> {
    run_command_with_env(program, args, None)
}

fn run_command_with_env(
    program: &str,
    args: &[&str],
    envs: Option<&[(&'static str, &'static str)]>,
) -> HardnResult<()> {
    let mut command = Command::new(program);
    command.args(args);

    if let Some(env_pairs) = envs {
        for &(key, value) in env_pairs {
            command.env(key, value);
        }
    }

    let output = command.output().map_err(|e| {
        HardnError::ExecutionFailed(format!("Failed to run {} {:?}: {}", program, args, e))
    })?;

    if output.status.success() {
        Ok(())
    } else {
        Err(HardnError::ExecutionFailed(format!(
            "Command {} {:?} failed: {}",
            program,
            args,
            String::from_utf8_lossy(&output.stderr)
        )))
    }
}

fn require_root(action: &str) -> HardnResult<()> {
    unsafe {
        if geteuid() != 0 {
            return Err(HardnError::ExecutionFailed(format!(
                "You must run this command as root to {}",
                action
            )));
        }
    }
    Ok(())
}
