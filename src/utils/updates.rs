//! Update-availability check against the GitHub Releases API.
//!
//! On GUI launch we want to tell the operator when a newer HARDN release is
//! out, but we deliberately stop short of installing it: the operator runs
//! `apt upgrade hardn` themselves. That keeps the update path going through
//! the system package manager (which already has signing, rollback, and
//! local policy) and avoids fighting with `apt` over file ownership.
//!
//! No new compile-time deps. The HTTP call is a shell-out to `curl`, the
//! same pattern `utils::alerts` uses for the webhook sink.
//!
//! Configuration env vars:
//!
//!   * `HARDN_NO_UPDATE_CHECK=1`         skip the check entirely
//!   * `HARDN_UPDATE_CHECK_TTL_SEC`      cache TTL (default 21600 s = 6 h)
//!   * `HARDN_UPDATE_RELEASES_URL`       override the API URL (CI / testing)

use std::fs;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

/// Application version. Pulled from the Cargo manifest so the same value
/// lands in both the `hardn` binary (which imports `core::config::VERSION`)
/// and the standalone `hardn-gui` binary (which pulls this file in via
/// `#[path]` without crate::core).
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Default cache TTL: 6 hours. Long enough that we never come close to
/// GitHub's unauthenticated 60-requests-per-hour budget, short enough that
/// a freshly-cut release lands in the GUI within a day.
const DEFAULT_TTL_SEC: u64 = 6 * 3600;
const MIN_TTL_SEC: u64 = 3600;
const MAX_TTL_SEC: u64 = 30 * 24 * 3600;
const CURL_TIMEOUT_SEC: u64 = 5;

/// Default API endpoint. Override via `HARDN_UPDATE_RELEASES_URL` for tests
/// or for a private mirror.
pub const DEFAULT_RELEASES_URL: &str =
    "https://api.github.com/repos/Security-International-Group/HARDN/releases/latest";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateInfo {
    /// Tag the release ships under, e.g. "1.3.0".
    pub latest_tag: String,
    /// Browser-friendly URL for the release page.
    pub release_url: String,
    /// `published_at` from the API, RFC3339. Stored as a string so we don't
    /// pull a date crate; the GUI just displays it.
    pub published_at: String,
}

#[derive(Debug)]
#[allow(dead_code)]
pub enum CheckError {
    OptedOut,
    NetworkUnavailable,
    BadResponse(String),
    ParseFailed(String),
    NoNewerRelease,
}

/// True when the operator has opted out via the env var. Checked BEFORE
/// any network call so air-gapped hosts never see a curl invocation at all.
pub fn opt_out() -> bool {
    matches!(
        std::env::var("HARDN_NO_UPDATE_CHECK").as_deref(),
        Ok("1" | "true" | "TRUE" | "yes" | "YES")
    )
}

/// Parsed TTL with the safety bounds applied. Operators who pass a bogus
/// value get the default; we never honour an unbounded TTL.
fn ttl_seconds() -> u64 {
    let parsed: u64 = std::env::var("HARDN_UPDATE_CHECK_TTL_SEC")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_TTL_SEC);
    parsed.clamp(MIN_TTL_SEC, MAX_TTL_SEC)
}

fn releases_url() -> String {
    std::env::var("HARDN_UPDATE_RELEASES_URL").unwrap_or_else(|_| DEFAULT_RELEASES_URL.to_string())
}

fn cache_dir() -> PathBuf {
    let base = std::env::var("XDG_CACHE_HOME")
        .ok()
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
            PathBuf::from(home).join(".cache")
        });
    base.join("hardn")
}

fn cache_file() -> PathBuf {
    cache_dir().join("update-check.json")
}

fn config_dir() -> PathBuf {
    let base = std::env::var("XDG_CONFIG_HOME")
        .ok()
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
            PathBuf::from(home).join(".config")
        });
    base.join("hardn")
}

/// Marker file used by "Don't show again for this version". One marker per
/// tag so the next release pops the banner regardless of an earlier dismiss.
pub fn dismiss_marker(tag: &str) -> PathBuf {
    let safe: String = tag
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_' { c } else { '_' })
        .collect();
    config_dir().join(format!("update-dismissed-{}.marker", safe))
}

pub fn is_dismissed(tag: &str) -> bool {
    dismiss_marker(tag).exists()
}

#[allow(dead_code)]
pub fn dismiss(tag: &str) -> std::io::Result<()> {
    let path = dismiss_marker(tag);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&path, "1\n")
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// On-disk shape of the cache file. We hand-roll the JSON read/write so we
/// don't pull serde_derive into this module path; the format is two strings,
/// a u64, and an Option<{string,string,string}>.
fn read_cache() -> Option<CachedResult> {
    let raw = fs::read_to_string(cache_file()).ok()?;
    CachedResult::parse(&raw)
}

fn write_cache(cached: &CachedResult) {
    let path = cache_file();
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let tmp = path.with_extension("tmp");
    if fs::write(&tmp, cached.serialize()).is_ok() {
        let _ = fs::rename(&tmp, &path);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CachedResult {
    checked_at: u64,
    current_version_at_check: String,
    info: Option<UpdateInfo>,
}

impl CachedResult {
    fn parse(raw: &str) -> Option<Self> {
        let val: serde_json::Value = serde_json::from_str(raw).ok()?;
        let checked_at = val.get("checked_at")?.as_u64()?;
        let current = val.get("current_version_at_check")?.as_str()?.to_string();
        let info = val.get("info").and_then(|v| {
            if v.is_null() {
                None
            } else {
                Some(UpdateInfo {
                    latest_tag: v.get("latest_tag")?.as_str()?.to_string(),
                    release_url: v.get("release_url")?.as_str()?.to_string(),
                    published_at: v.get("published_at")?.as_str()?.to_string(),
                })
            }
        });
        Some(Self { checked_at, current_version_at_check: current, info })
    }

    fn serialize(&self) -> String {
        let info_json = match &self.info {
            Some(i) => serde_json::json!({
                "latest_tag": i.latest_tag,
                "release_url": i.release_url,
                "published_at": i.published_at,
            }),
            None => serde_json::Value::Null,
        };
        serde_json::json!({
            "checked_at": self.checked_at,
            "current_version_at_check": self.current_version_at_check,
            "info": info_json,
        })
        .to_string()
    }
}

/// Strip a leading 'v' (we ship both v1.2.3 and 1.2.3 in tags).
fn normalize_tag(t: &str) -> &str {
    t.strip_prefix('v').unwrap_or(t)
}

/// True when `latest` is a strictly newer semver-ish triple than `current`.
/// We do a numeric component compare so v1.10.0 wins over v1.2.0 (string
/// compare gets that backwards). Non-numeric components fall back to a
/// string compare on whatever's left, which is good enough for the
/// "shipped most recently" signal we actually need.
pub fn is_strictly_newer(current: &str, latest: &str) -> bool {
    let c = normalize_tag(current);
    let l = normalize_tag(latest);
    if c == l {
        return false;
    }
    let parse = |s: &str| -> Vec<u64> {
        s.split('.')
            .map(|part| {
                part.chars()
                    .take_while(|c| c.is_ascii_digit())
                    .collect::<String>()
                    .parse::<u64>()
                    .unwrap_or(0)
            })
            .collect()
    };
    let cp = parse(c);
    let lp = parse(l);
    // Pad the shorter side with zeros so 1.2 vs 1.2.1 works.
    let n = cp.len().max(lp.len());
    for i in 0..n {
        let a = cp.get(i).copied().unwrap_or(0);
        let b = lp.get(i).copied().unwrap_or(0);
        if b > a {
            return true;
        }
        if b < a {
            return false;
        }
    }
    // Same numeric prefix, different string suffix (e.g. 1.2.3 vs 1.2.3-rc1).
    // Treat the cleaner tag as "newer" only when the existing one is a
    // pre-release marker; otherwise leave the operator alone.
    c.contains('-') && !l.contains('-')
}

/// Public entry point. Returns Ok(Some) when a strictly newer release is
/// available, Ok(None) when the running version is current, or one of the
/// CheckError variants for the operator-actionable paths.
pub fn check_for_update() -> Result<Option<UpdateInfo>, CheckError> {
    if opt_out() {
        return Err(CheckError::OptedOut);
    }

    if let Some(cached) = read_cache() {
        if cached.current_version_at_check == VERSION
            && unix_now().saturating_sub(cached.checked_at) < ttl_seconds()
        {
            return match cached.info {
                Some(info) if is_strictly_newer(VERSION, &info.latest_tag) => Ok(Some(info)),
                _ => Ok(None),
            };
        }
    }

    if !curl_available() {
        return Err(CheckError::NetworkUnavailable);
    }

    let body = fetch_latest_release()?;
    let info = parse_release_payload(&body)?;
    let result = if is_strictly_newer(VERSION, &info.latest_tag) {
        Some(info)
    } else {
        None
    };
    write_cache(&CachedResult {
        checked_at: unix_now(),
        current_version_at_check: VERSION.to_string(),
        info: result.clone(),
    });
    Ok(result)
}

fn curl_available() -> bool {
    std::path::Path::new("/usr/bin/curl").exists() || std::path::Path::new("/bin/curl").exists()
}

fn user_agent() -> String {
    format!("hardn/{}", VERSION)
}

/// Shell out to curl. GitHub requires a non-empty User-Agent or the request
/// is rate-limited aggressively.
fn fetch_latest_release() -> Result<String, CheckError> {
    let url = releases_url();
    let out = Command::new("curl")
        .args([
            "-fsS",
            "-m", &CURL_TIMEOUT_SEC.to_string(),
            "-A", &user_agent(),
            "-H", "Accept: application/vnd.github+json",
            &url,
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .map_err(|e| CheckError::BadResponse(format!("curl spawn failed: {}", e)))?;
    if !out.status.success() {
        return Err(CheckError::NetworkUnavailable);
    }
    let body = String::from_utf8_lossy(&out.stdout).to_string();
    Ok(body)
}

fn parse_release_payload(raw: &str) -> Result<UpdateInfo, CheckError> {
    let val: serde_json::Value =
        serde_json::from_str(raw).map_err(|e| CheckError::ParseFailed(e.to_string()))?;
    // Skip pre-releases and drafts: notifier should only fire on stable cuts.
    let draft = val.get("draft").and_then(|v| v.as_bool()).unwrap_or(false);
    let prerelease = val.get("prerelease").and_then(|v| v.as_bool()).unwrap_or(false);
    if draft || prerelease {
        return Err(CheckError::NoNewerRelease);
    }
    let tag = val
        .get("tag_name")
        .and_then(|v| v.as_str())
        .ok_or_else(|| CheckError::ParseFailed("missing tag_name".into()))?
        .to_string();
    let url = val
        .get("html_url")
        .and_then(|v| v.as_str())
        .ok_or_else(|| CheckError::ParseFailed("missing html_url".into()))?
        .to_string();
    let published = val
        .get("published_at")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    Ok(UpdateInfo {
        latest_tag: tag,
        release_url: url,
        published_at: published,
    })
}

/// Convenience for the GUI: returns Some(info) only when there's something
/// worth showing AND the operator hasn't dismissed it for that version.
#[allow(dead_code)]
pub fn check_for_update_to_show() -> Option<UpdateInfo> {
    match check_for_update() {
        Ok(Some(info)) if !is_dismissed(&info.latest_tag) => Some(info),
        _ => None,
    }
}

/// Best-effort open of a URL in the operator's preferred browser. Used by
/// the GUI banner's "view release notes" link.
#[allow(dead_code)]
pub fn open_url(url: &str) {
    // Only allow http/https; refuse anything else so a future caller can't
    // accidentally pass a file:// or javascript: scheme.
    if !(url.starts_with("http://") || url.starts_with("https://")) {
        return;
    }
    let _ = Command::new("xdg-open")
        .arg(url)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ttl_within_safe_bounds() {
        // The default we ship should sit between the safety bounds. If a
        // future change drops one but not the other, this catches it.
        assert!(DEFAULT_TTL_SEC >= MIN_TTL_SEC);
        assert!(DEFAULT_TTL_SEC <= MAX_TTL_SEC);
    }

    #[test]
    fn is_strictly_newer_basic() {
        assert!(is_strictly_newer("1.2.0", "1.2.1"));
        assert!(is_strictly_newer("1.2.0", "1.3.0"));
        assert!(is_strictly_newer("1.2.0", "2.0.0"));
        assert!(is_strictly_newer("v1.2.0", "1.2.1"));
        assert!(is_strictly_newer("1.2.0", "v1.2.1"));
    }

    #[test]
    fn is_strictly_newer_lexical_trap() {
        // Pure string compare gets this backwards: "1.10.0" < "1.2.0".
        // We MUST get this right or operators on v1.10 keep seeing
        // bogus "update available to v1.2" prompts.
        assert!(is_strictly_newer("1.2.0", "1.10.0"));
        assert!(!is_strictly_newer("1.10.0", "1.2.0"));
    }

    #[test]
    fn is_strictly_newer_no_downgrade() {
        assert!(!is_strictly_newer("1.3.0", "1.2.9"));
        assert!(!is_strictly_newer("2.0.0", "1.99.99"));
    }

    #[test]
    fn is_strictly_newer_same_version() {
        assert!(!is_strictly_newer("1.2.3", "1.2.3"));
        assert!(!is_strictly_newer("v1.2.3", "1.2.3"));
    }

    #[test]
    fn is_strictly_newer_padded_lengths() {
        // 1.2 vs 1.2.0 should be equal, not a "newer".
        assert!(!is_strictly_newer("1.2", "1.2.0"));
        assert!(!is_strictly_newer("1.2.0", "1.2"));
        assert!(is_strictly_newer("1.2", "1.2.1"));
    }

    #[test]
    fn dismiss_marker_sanitizes_tag() {
        // Slashes / spaces in a tag must not produce a path-traversal.
        let path = dismiss_marker("../etc/passwd");
        assert!(path.file_name().unwrap().to_string_lossy().starts_with("update-dismissed-"));
        assert!(!path.to_string_lossy().contains("/etc/passwd"));
    }

    #[test]
    fn opt_out_recognises_truthy_values() {
        let saved = std::env::var("HARDN_NO_UPDATE_CHECK").ok();
        // SAFETY: tests in the same binary may race on env, accept that
        // this is a single-process check; we restore the previous state
        // at the end.
        for v in ["1", "true", "TRUE", "yes", "YES"] {
            unsafe { std::env::set_var("HARDN_NO_UPDATE_CHECK", v) };
            assert!(opt_out(), "should opt out for value {}", v);
        }
        for v in ["0", "false", "no", ""] {
            unsafe { std::env::set_var("HARDN_NO_UPDATE_CHECK", v) };
            assert!(!opt_out(), "should NOT opt out for value {}", v);
        }
        match saved {
            Some(v) => unsafe { std::env::set_var("HARDN_NO_UPDATE_CHECK", v) },
            None => unsafe { std::env::remove_var("HARDN_NO_UPDATE_CHECK") },
        }
    }

    #[test]
    fn release_payload_parses_minimum_fields() {
        let raw = r#"{
            "tag_name": "v1.3.0",
            "html_url": "https://github.com/Security-International-Group/HARDN/releases/tag/v1.3.0",
            "published_at": "2026-07-01T00:00:00Z",
            "draft": false,
            "prerelease": false
        }"#;
        let info = parse_release_payload(raw).expect("must parse");
        assert_eq!(info.latest_tag, "v1.3.0");
        assert!(info.release_url.starts_with("https://"));
    }

    #[test]
    fn release_payload_skips_drafts_and_prereleases() {
        let draft = r#"{
            "tag_name": "v1.3.0",
            "html_url": "https://x/",
            "draft": true,
            "prerelease": false
        }"#;
        assert!(matches!(
            parse_release_payload(draft),
            Err(CheckError::NoNewerRelease)
        ));

        let pre = r#"{
            "tag_name": "v1.3.0-rc1",
            "html_url": "https://x/",
            "draft": false,
            "prerelease": true
        }"#;
        assert!(matches!(
            parse_release_payload(pre),
            Err(CheckError::NoNewerRelease)
        ));
    }

    #[test]
    fn cached_result_roundtrip() {
        let original = CachedResult {
            checked_at: 1_780_000_000,
            current_version_at_check: "1.2.3".into(),
            info: Some(UpdateInfo {
                latest_tag: "1.2.4".into(),
                release_url: "https://github.com/x".into(),
                published_at: "2026-07-01T00:00:00Z".into(),
            }),
        };
        let raw = original.serialize();
        let parsed = CachedResult::parse(&raw).expect("must parse");
        assert_eq!(original, parsed);
    }

    #[test]
    fn cached_result_handles_null_info() {
        let r = CachedResult {
            checked_at: 1,
            current_version_at_check: "1.0.0".into(),
            info: None,
        };
        let raw = r.serialize();
        let parsed = CachedResult::parse(&raw).expect("must parse");
        assert!(parsed.info.is_none());
    }
}
