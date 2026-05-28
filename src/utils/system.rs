use std::fs;

/// Distro identity parsed from `/etc/os-release`. `id` is the lower-case
/// short name (`debian`, `ubuntu`, `pop`, ...); `version` is `VERSION_ID`
/// (`12`, `13`, `24.04`, `26.04`); `codename` is `VERSION_CODENAME`
/// (`bookworm`, `trixie`, `noble`, `questing`). Any field that cannot be
/// read returns `"unknown"`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OsInfo {
    pub id: String,
    pub version: String,
    pub codename: String,
}

impl OsInfo {
    /// Human-readable single line. Examples:
    ///   "Ubuntu 26.04 (questing)"
    ///   "Debian 13 (trixie)"
    ///   "unknown unknown (unknown)"
    pub fn display(&self) -> String {
        let pretty_id = match self.id.as_str() {
            "debian" => "Debian".to_string(),
            "ubuntu" => "Ubuntu".to_string(),
            other => {
                let mut chars = other.chars();
                match chars.next() {
                    Some(c) => c.to_uppercase().collect::<String>() + chars.as_str(),
                    None => "unknown".to_string(),
                }
            }
        };
        format!("{} {} ({})", pretty_id, self.version, self.codename)
    }
}

/// Read `/etc/os-release` and return the parsed identity.
pub fn detect_os() -> OsInfo {
    match fs::read_to_string("/etc/os-release") {
        Ok(content) => parse_os_release(&content),
        Err(_) => OsInfo {
            id: "unknown".into(),
            version: "unknown".into(),
            codename: "unknown".into(),
        },
    }
}

/// Backwards-compatible wrapper. New code should call `detect_os()` directly.
/// This existed to print "Debian X (codename)" but did the wrong thing on
/// Ubuntu (printed "Debian 26.04 (questing)" on a 26.04 host). Kept so the
/// rename doesn't break out-of-tree callers; will be removed in a future
/// major.
#[allow(dead_code)]
#[deprecated(since = "1.0.1", note = "use detect_os() which returns an OsInfo struct")]
pub fn detect_debian_version() -> (String, String) {
    let info = detect_os();
    (info.version, info.codename)
}

fn parse_os_release(content: &str) -> OsInfo {
    OsInfo {
        id: extract_os_field(content, "ID"),
        version: extract_os_field(content, "VERSION_ID"),
        codename: extract_os_field(content, "VERSION_CODENAME"),
    }
}

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

#[cfg(test)]
mod tests {
    use super::*;

    const UBUNTU_2604: &str = r#"NAME="Ubuntu"
VERSION="26.04 LTS (Questing Quokka)"
ID=ubuntu
ID_LIKE=debian
PRETTY_NAME="Ubuntu 26.04 LTS"
VERSION_ID="26.04"
HOME_URL="https://www.ubuntu.com/"
SUPPORT_URL="https://help.ubuntu.com/"
BUG_REPORT_URL="https://bugs.launchpad.net/ubuntu/"
PRIVACY_POLICY_URL="https://www.ubuntu.com/legal/terms-and-policies/privacy-policy"
VERSION_CODENAME=questing
UBUNTU_CODENAME=questing
"#;

    const DEBIAN_13: &str = r#"PRETTY_NAME="Debian GNU/Linux 13 (trixie)"
NAME="Debian GNU/Linux"
VERSION_ID="13"
VERSION="13 (trixie)"
VERSION_CODENAME=trixie
ID=debian
HOME_URL="https://www.debian.org/"
"#;

    #[test]
    fn ubuntu_26_04_parses_correctly() {
        let info = parse_os_release(UBUNTU_2604);
        assert_eq!(info.id, "ubuntu");
        assert_eq!(info.version, "26.04");
        assert_eq!(info.codename, "questing");
        assert_eq!(info.display(), "Ubuntu 26.04 (questing)");
    }

    #[test]
    fn debian_13_parses_correctly() {
        let info = parse_os_release(DEBIAN_13);
        assert_eq!(info.id, "debian");
        assert_eq!(info.version, "13");
        assert_eq!(info.codename, "trixie");
        assert_eq!(info.display(), "Debian 13 (trixie)");
    }

    #[test]
    fn missing_fields_yield_unknown() {
        let info = parse_os_release("PRETTY_NAME=\"weirdo\"\n");
        assert_eq!(info.id, "unknown");
        assert_eq!(info.version, "unknown");
        assert_eq!(info.codename, "unknown");
    }

    #[test]
    fn quoted_and_unquoted_values_both_work() {
        let content = "ID=\"ubuntu\"\nVERSION_ID=24.04\nVERSION_CODENAME=\"noble\"\n";
        let info = parse_os_release(content);
        assert_eq!(info.id, "ubuntu");
        assert_eq!(info.version, "24.04");
        assert_eq!(info.codename, "noble");
    }

    #[test]
    fn display_prettifies_unknown_id() {
        let info = OsInfo { id: "pop".into(), version: "22.04".into(), codename: "jammy".into() };
        assert_eq!(info.display(), "Pop 22.04 (jammy)");
    }
}
