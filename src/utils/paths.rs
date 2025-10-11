use std::collections::HashSet;
use std::env;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use crate::core::HardnResult;

/// Returns paths from environment variable or defaults if not set
/// Supports colon-separated paths like Unix PATH variable
pub fn env_or_defaults(var: &str, defaults: &[&str]) -> Vec<PathBuf> {
    match env::var(var) {
        Ok(value) if !value.trim().is_empty() => parse_path_list(&value),
        _ => defaults.iter().map(|&s| PathBuf::from(s)).collect(),
    }
}

/// Parse a colon-separated list of paths into a vector of PathBufs
/// Filters out empty paths and trims whitespace
pub fn parse_path_list(path_str: &str) -> Vec<PathBuf> {
    path_str
        .split(':')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
        .collect()
}

/// Searches for a script by name in the given directories
/// Handles both with and without .sh extension
/// Returns the first matching file found
pub fn find_script(dirs: &[PathBuf], name: &str) -> Option<PathBuf> {
    // Build list of possible filenames to search for
    let candidates = build_script_candidates(name);

    // Search through directories and candidates
    dirs.iter()
        .filter(|dir| dir.is_dir())
        .flat_map(|dir| candidates.iter().map(move |candidate| dir.join(candidate)))
        .find(|path| is_valid_script_file(path))
}

/// Build list of candidate filenames for a given script name
fn build_script_candidates(name: &str) -> Vec<String> {
    if name.ends_with(".sh") {
        vec![name.to_string()]
    } else {
        vec![format!("{}.sh", name), name.to_string()]
    }
}

/// Check if a path points to a valid script file
/// Made more robust to match the logic used in list_modules
fn is_valid_script_file(path: &Path) -> bool {
    // Use metadata approach consistently with extract_module_name
    match fs::metadata(path) {
        Ok(metadata) => {
            // First check if it's a regular file
            if !metadata.is_file() {
                return false;
            }

            // On Unix, check if file has read permission
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mode = metadata.permissions().mode();
                (mode & 0o444) != 0 // Check if any read bit is set
            }
            #[cfg(not(unix))]
            {
                true // On non-Unix, just check if it's a file
            }
        }
        Err(_) => false,
    }
}

/// Lists all .sh files in the given directories
/// Returns a sorted list of module/tool names (without .sh extension)
/// Collects modules from ALL directories, not just the first one found
pub fn list_modules(dirs: &[PathBuf]) -> HardnResult<Vec<String>> {
    // Use HashSet for automatic deduplication
    let mut module_names: HashSet<String> = HashSet::new();

    // Process each directory
    for dir in dirs {
        // Skip non-existent directories
        if !dir.is_dir() {
            continue;
        }

        // Read directory and handle errors gracefully
        let entries = match fs::read_dir(dir) {
            Ok(entries) => entries,
            Err(e) => {
                // Log warning but continue with other directories
                eprintln!("Warning: Could not read directory {}: {}", dir.display(), e);
                continue;
            }
        };

        // Process each entry in the directory
        for entry in entries {
            // Extract the module name if valid
            if let Some(module_name) = extract_module_name(entry) {
                module_names.insert(module_name);
            }
        }
    }

    // Convert to sorted vector
    let mut sorted_names: Vec<String> = module_names.into_iter().collect();
    sorted_names.sort();

    Ok(sorted_names)
}

/// Helper function to extract module name from a directory entry
/// Returns Some(name) if the entry is a valid .sh file, None otherwise
fn extract_module_name(entry: io::Result<fs::DirEntry>) -> Option<String> {
    // Handle potential I/O error for the entry
    let entry = entry.ok()?;
    let path = entry.path();

    // Check if it's a .sh file
    let extension = path.extension()?.to_str()?;
    if extension != "sh" {
        return None;
    }

    // Extract the filename without extension
    let stem = path.file_stem()?.to_str()?;

    // Additional validation: ensure it's a regular file (not directory or symlink to directory)
    match entry.metadata() {
        Ok(metadata) if metadata.is_file() => Some(stem.to_string()),
        _ => None,
    }
}

pub fn join_paths(dirs: &[PathBuf]) -> String {
    dirs.iter()
        .map(|p| p.display().to_string())
        .collect::<Vec<_>>()
        .join(":")
}
