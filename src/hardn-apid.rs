// SPDX-License-Identifier: MIT
//! hardn-apid: Rust replacement for the Python `hardn-api` FastAPI service.
//!
//! This is step one of retiring the Python runtime (and its pip supply
//! chain). It serves the health endpoint over a Unix domain socket rather
//! than a TCP port, because the API is local-only: `hardn-monitor` talks to
//! it from the same host. A Unix socket removes the network attack surface
//! entirely and lets the kernel enforce access with file permissions.
//!
//! The socket path is `HARDN_APID_SOCKET` (default
//! `/run/hardn/hardn-apid.sock`). The remaining endpoints (`/metrics`,
//! `/overwatch/*`, `/legion/*`) are ported in follow-up changes, each
//! diff-tested against the Python implementation before the Python side is
//! removed.

use axum::{Json, Router, routing::get};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

/// Default socket path. Under `/run` so it is tmpfs-backed and cleared on
/// reboot; the parent dir is created at startup if missing.
const DEFAULT_SOCKET: &str = "/run/hardn/hardn-apid.sock";

/// Body of the health response. Kept as a free function so it can be unit
/// tested without standing up a server. Shape matches the Python
/// `/health` so consumers do not have to change during the migration.
fn health_body() -> serde_json::Value {
    serde_json::json!({
        "status": "healthy",
        "service": "hardn-apid",
        "version": env!("CARGO_PKG_VERSION"),
    })
}

async fn health() -> Json<serde_json::Value> {
    Json(health_body())
}

/// Build the router. Separate from `main` so tests can serve the exact same
/// routes on a throwaway socket.
fn app() -> Router {
    Router::new().route("/health", get(health))
}

/// Bind the Unix socket at `path`, replacing any stale socket file and
/// creating the parent directory. Restricts the socket to `0660` so only the
/// owning user and group can connect.
fn bind_socket(path: &str) -> std::io::Result<tokio::net::UnixListener> {
    if let Some(parent) = Path::new(path).parent() {
        std::fs::create_dir_all(parent)?;
    }
    // A leftover socket file from a previous run would make bind() fail with
    // EADDRINUSE even though nothing is listening.
    let _ = std::fs::remove_file(path);
    let listener = tokio::net::UnixListener::bind(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660))?;
    Ok(listener)
}

#[tokio::main]
async fn main() {
    let socket_path =
        std::env::var("HARDN_APID_SOCKET").unwrap_or_else(|_| DEFAULT_SOCKET.to_string());

    let listener = match bind_socket(&socket_path) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("hardn-apid: cannot bind {socket_path}: {e}");
            std::process::exit(1);
        }
    };

    eprintln!("hardn-apid: listening on {socket_path}");
    if let Err(e) = axum::serve(listener, app()).await {
        eprintln!("hardn-apid: serve error: {e}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn health_body_reports_healthy() {
        let b = health_body();
        assert_eq!(b["status"], "healthy");
        assert_eq!(b["service"], "hardn-apid");
        assert!(b["version"].is_string());
    }

    #[tokio::test]
    async fn serves_health_over_unix_socket() {
        // Bind a throwaway socket under the test's temp dir, serve the real
        // router, then speak raw HTTP/1.1 to it over the socket.
        let dir = tempfile::tempdir().expect("tempdir");
        let sock = dir.path().join("apid.sock");
        let sock_str = sock.to_str().unwrap().to_string();

        let listener = bind_socket(&sock_str).expect("bind");
        // set_permissions 0660 must have applied; confirm the socket exists.
        assert!(sock.exists());

        let server = tokio::spawn(async move {
            let _ = axum::serve(listener, app()).await;
        });

        // Connect and issue GET /health.
        let mut stream = tokio::net::UnixStream::connect(&sock)
            .await
            .expect("connect");
        stream
            .write_all(b"GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .await
            .expect("write");

        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await.expect("read");
        let resp = String::from_utf8_lossy(&buf);

        assert!(resp.starts_with("HTTP/1.1 200"), "status line: {resp}");
        assert!(resp.contains("\"status\":\"healthy\""), "body: {resp}");
        assert!(resp.contains("\"service\":\"hardn-apid\""), "body: {resp}");

        server.abort();
    }
}
