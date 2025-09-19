use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};

use crate::core::{HardnResult, HardnError};
use crate::core::config::{VERSION, DEFAULT_LOG_DIR, DEFAULT_LIB_DIR, DEFAULT_MODULE_DIRS};
use crate::utils::{LogLevel, log_message};

/// Executes a shell script with proper environment setup
/// Returns the exit status for proper error propagation
pub fn run_script(path: &Path, kind: &str, module_dirs: &[PathBuf]) -> HardnResult<ExitStatus> {
    // Validate the script exists and is readable
    if !path.exists() {
        return Err(HardnError::ExecutionFailed(
            format!("Script does not exist: {}", path.display())
        ));
    }
    
    // Security: Ensure the path is absolute to prevent directory traversal
    let absolute_path = path.canonicalize()
        .map_err(|e| HardnError::ExecutionFailed(
            format!("Failed to resolve path {}: {}", path.display(), e)
        ))?;
    
    log_message(LogLevel::Info, &format!("Executing {}: {}", kind, absolute_path.display()));

    // Set required environment variables for shell modules
    let module_dir = module_dirs.first()
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
        .map_err(|e| HardnError::ExecutionFailed(
            format!("Failed to execute {}: {}", kind, e)
        ))?;

    if status.success() {
        log_message(LogLevel::Pass, &format!("{} completed successfully", kind));
    } else {
        log_message(LogLevel::Warning, &format!("{} exited with status: {}", kind, status));
    }
    
    Ok(status)
}
