// SPDX-License-Identifier: MIT
//! Local authentication + RBAC for the compliance console.
//!
//! The console is loopback-only but still refuses anonymous access (threat
//! T2). On first run it mints two secrets under the state dir (mode 0600): an
//! operator token (read + mutate) and a viewer token (read only). A client
//! presents one via the `Authorization: Bearer` header or the `hardn_session`
//! cookie. This is the GA model; mutual TLS is the planned follow-up.

use axum::Json;
use axum::extract::FromRequestParts;
use axum::http::{StatusCode, header, request::Parts};
use axum::response::{IntoResponse, Response};
use serde_json::json;
use std::env;
use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Viewer,
    Operator,
}

impl Role {
    pub fn as_str(self) -> &'static str {
        match self {
            Role::Viewer => "viewer",
            Role::Operator => "operator",
        }
    }
}

pub struct Secrets {
    pub operator: String,
    pub viewer: String,
}

static SECRETS: OnceLock<Secrets> = OnceLock::new();

/// Load or mint the console secrets. Idempotent; safe to call once at startup.
pub fn init() -> &'static Secrets {
    SECRETS.get_or_init(|| {
        let dir = state_dir();
        let _ = fs::create_dir_all(&dir);
        let _ = fs::set_permissions(&dir, fs::Permissions::from_mode(0o700));
        Secrets {
            operator: load_or_create(&dir.join("operator.secret")),
            viewer: load_or_create(&dir.join("viewer.secret")),
        }
    })
}

fn secrets() -> &'static Secrets {
    SECRETS
        .get()
        .expect("auth::init() must run before request handling")
}

/// State directory for secrets and the audit log. Packaging points this at
/// `/var/lib/hardn` via the systemd unit; for a user session it resolves to
/// the XDG data dir.
pub fn state_dir() -> PathBuf {
    if let Ok(x) = env::var("HARDN_STATE_DIR") {
        return PathBuf::from(x);
    }
    if let Ok(x) = env::var("XDG_DATA_HOME") {
        return PathBuf::from(x).join("hardn");
    }
    if let Ok(h) = env::var("HOME") {
        return PathBuf::from(h).join(".local/share/hardn");
    }
    PathBuf::from("/var/lib/hardn")
}

fn load_or_create(path: &Path) -> String {
    if let Ok(s) = fs::read_to_string(path) {
        let t = s.trim().to_string();
        if !t.is_empty() {
            return t;
        }
    }
    let tok = random_hex(32);
    if let Ok(mut f) = fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
    {
        let _ = f.write_all(tok.as_bytes());
    }
    tok
}

fn random_hex(n: usize) -> String {
    let mut buf = vec![0u8; n];
    if let Ok(mut f) = fs::File::open("/dev/urandom") {
        let _ = f.read_exact(&mut buf);
    }
    buf.iter().map(|b| format!("{b:02x}")).collect()
}

/// Length-checked, constant-time-ish token comparison. Not a crypto
/// primitive; it just avoids leaking a match position via early return.
fn ct_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

pub fn resolve(token: &str) -> Option<Role> {
    let s = secrets();
    if ct_eq(token, &s.operator) {
        Some(Role::Operator)
    } else if ct_eq(token, &s.viewer) {
        Some(Role::Viewer)
    } else {
        None
    }
}

/// Extract a bearer or cookie token from request headers.
pub fn token_from_parts(parts: &Parts) -> Option<String> {
    if let Some(v) = parts
        .headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        && let Some(t) = v.strip_prefix("Bearer ")
    {
        return Some(t.trim().to_string());
    }
    if let Some(c) = parts
        .headers
        .get(header::COOKIE)
        .and_then(|v| v.to_str().ok())
    {
        for part in c.split(';') {
            if let Some(t) = part.trim().strip_prefix("hardn_session=") {
                return Some(t.to_string());
            }
        }
    }
    None
}

/// Build a hardened session cookie for a token.
pub fn session_cookie(token: &str) -> String {
    format!("hardn_session={token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=86400")
}

/// Authenticated request context. Extraction fails with 401 when no valid
/// token is present, so every route that takes it is gated.
pub struct AuthCtx {
    pub role: Role,
}

impl<S: Send + Sync> FromRequestParts<S> for AuthCtx {
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        match token_from_parts(parts).as_deref().and_then(resolve) {
            Some(role) => Ok(AuthCtx { role }),
            None => Err((
                StatusCode::UNAUTHORIZED,
                Json(json!({ "error": "unauthenticated", "detail": "present a valid console token" })),
            )
                .into_response()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::Request;

    // Build request Parts carrying the given headers so token_from_parts can
    // be exercised without standing up a server.
    fn parts_with(headers: &[(&str, &str)]) -> Parts {
        let mut b = Request::builder();
        for (k, v) in headers {
            b = b.header(*k, *v);
        }
        b.body(()).unwrap().into_parts().0
    }

    #[test]
    fn ct_eq_matches_only_identical_strings() {
        assert!(ct_eq("s3cret", "s3cret"));
        assert!(ct_eq("", ""));
        assert!(!ct_eq("s3cret", "s3creT")); // one-byte difference
        assert!(!ct_eq("s3cret", "s3cret1")); // length mismatch
        assert!(!ct_eq("", "x"));
    }

    #[test]
    fn random_hex_has_expected_length_and_is_hex() {
        let tok = random_hex(32);
        assert_eq!(tok.len(), 64, "32 bytes -> 64 hex chars (256-bit token)");
        assert!(tok.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn random_hex_is_not_constant() {
        // 256-bit tokens; a collision here would be astronomically unlikely
        // and would indicate /dev/urandom was not read.
        assert_ne!(random_hex(32), random_hex(32));
    }

    #[test]
    fn bearer_token_is_extracted() {
        let p = parts_with(&[("authorization", "Bearer tok-abc")]);
        assert_eq!(token_from_parts(&p).as_deref(), Some("tok-abc"));
    }

    #[test]
    fn cookie_token_is_extracted_among_others() {
        let p = parts_with(&[("cookie", "foo=1; hardn_session=cookie-tok; bar=2")]);
        assert_eq!(token_from_parts(&p).as_deref(), Some("cookie-tok"));
    }

    #[test]
    fn bearer_takes_precedence_over_cookie() {
        let p = parts_with(&[
            ("authorization", "Bearer from-header"),
            ("cookie", "hardn_session=from-cookie"),
        ]);
        assert_eq!(token_from_parts(&p).as_deref(), Some("from-header"));
    }

    #[test]
    fn no_token_when_absent_or_wrong_scheme() {
        assert_eq!(token_from_parts(&parts_with(&[])), None);
        assert_eq!(
            token_from_parts(&parts_with(&[("authorization", "Basic dXNlcjpwYXNz")])),
            None
        );
        assert_eq!(
            token_from_parts(&parts_with(&[("cookie", "session=other")])),
            None
        );
    }

    #[test]
    fn session_cookie_is_hardened() {
        let c = session_cookie("tok");
        assert!(c.contains("hardn_session=tok"));
        assert!(c.contains("HttpOnly"), "cookie must be HttpOnly");
        assert!(
            c.contains("SameSite=Strict"),
            "cookie must be SameSite=Strict"
        );
    }

    #[test]
    fn load_or_create_mints_0600_token_and_persists() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("operator.secret");

        let first = load_or_create(&path);
        assert_eq!(first.len(), 64, "minted token is a 256-bit hex string");
        assert!(first.chars().all(|c| c.is_ascii_hexdigit()));

        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "secret file must be created mode 0600");

        // Idempotent: a second call reads the persisted token, not a new one.
        assert_eq!(load_or_create(&path), first);
    }

    #[test]
    fn role_as_str_is_stable() {
        assert_eq!(Role::Operator.as_str(), "operator");
        assert_eq!(Role::Viewer.as_str(), "viewer");
    }
}
