use std::fs;

/// Detect the Debian version and codename from /etc/os-release
/// Returns ("unknown", "unknown") if detection fails
pub fn detect_debian_version() -> (String, String) {
    match fs::read_to_string("/etc/os-release") {
        Ok(content) => parse_os_release(&content),
        Err(_) => ("unknown".to_string(), "unknown".to_string()),
    }
}

/// Parse os-release file content to extract version info
fn parse_os_release(content: &str) -> (String, String) {
    let version_id = extract_os_field(content, "VERSION_ID");
    let codename = extract_os_field(content, "VERSION_CODENAME");
    (version_id, codename)
}

/// Extract a field value from os-release format
/// Handles both KEY=value and KEY="value" formats
fn extract_os_field(content: &str, field_name: &str) -> String {
    content
        .lines()
        .find(|line| line.starts_with(&format!("{}=", field_name)))
        .and_then(|line| {
            line.split_once('=')
                .map(|(_, value)| value.trim_matches('"').to_string())
        })
        .unwrap_or_else(|| "unknown".to_string())
}
