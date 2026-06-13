use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};

use crate::core::config::{DEFAULT_LIB_DIR, DEFAULT_LOG_DIR, DEFAULT_MODULE_DIRS, VERSION};
use crate::core::{HardnError, HardnResult};
use crate::utils::{log_message, LogLevel};

/// Executes a shell script with proper environment setup
/// Returns the exit status for proper error propagation
pub fn run_script(path: &Path, kind: &str, module_dirs: &[PathBuf]) -> HardnResult<ExitStatus> {
    // Validate the script exists and is readable
    if !path.exists() {
        return Err(HardnError::ExecutionFailed(format!(
            "Script does not exist: {}",
            path.display()
        )));
    }

    // Security: Ensure the path is absolute to prevent directory traversal
    let absolute_path = path.canonicalize().map_err(|e| {
        HardnError::ExecutionFailed(format!("Failed to resolve path {}: {}", path.display(), e))
    })?;

    log_message(
        LogLevel::Info,
        &format!("Executing {}: {}", kind, absolute_path.display()),
    );

    // Set required environment variables for shell modules
    let module_dir = module_dirs
        .first()
        .map(|d| d.display().to_string())
        .unwrap_or_else(|| DEFAULT_MODULE_DIRS[0].to_string());

    let status = Command::new("bash")
        .arg(&absolute_path)
        .env("HARDN_MODULES_DIR", &module_dir)
        .env("HARDN_LOG_DIR", DEFAULT_LOG_DIR)
        .env("HARDN_LIB_DIR", DEFAULT_LIB_DIR)
        .env("HARDN_VERSION", VERSION)
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .map_err(|e| HardnError::ExecutionFailed(format!("Failed to execute {}: {}", kind, e)))?;

    // Note: a zero exit code does NOT mean the script ran without warnings.
    // HARDN_STATUS warning / error calls inside a tool do not change the
    // exit code, so we report the run as "finished" and leave it to the
    // operator to inspect the inline [WARNING] / [ERROR] lines the tool
    // itself emitted. Claiming "completed successfully" after warnings
    // confused testers (Orinax, dev_testing 2026-06-13).
    if status.success() {
        log_message(LogLevel::Info, &format!("{} run finished (exit 0)", kind));
    } else {
        log_message(
            LogLevel::Warning,
            &format!("{} exited with status: {}", kind, status),
        );
    }

    Ok(status)
}
