use std::path::{Path, PathBuf, Component};

/// Validates and sanitizes a path to prevent path traversal attacks
/// Returns None if the path contains dangerous patterns
pub fn sanitize_path(user_path: &str) -> Option<PathBuf> {
    let path = Path::new(user_path);
    
    // Reject absolute paths from user input (unless whitelisted)
    if path.is_absolute() {
        return None;
    }
    
    // Check each component for traversal attempts
    for component in path.components() {
        match component {
            Component::ParentDir => return None, // Reject ".."
            Component::CurDir => continue, // Allow "."
            Component::Normal(s) => {
                // Reject null bytes
                if s.to_string_lossy().contains('\0') {
                    return None;
                }
            }
            _ => continue,
        }
    }
    
    Some(path.to_path_buf())
}

/// Validates a path from environment variable against a whitelist of allowed directories
pub fn validate_env_path(env_path: &str, allowed_prefixes: &[&str]) -> Option<PathBuf> {
    let path = PathBuf::from(env_path);
    
    // Canonicalize to resolve symlinks and relative paths
    let canonical = path.canonicalize().ok()?;
    
    // Check if path starts with any allowed prefix
    for prefix in allowed_prefixes {
        let prefix_path = PathBuf::from(prefix);
        if let Ok(canonical_prefix) = prefix_path.canonicalize() {
            if canonical.starts_with(&canonical_prefix) {
                return Some(canonical);
            }
        }
    }
    
    None
}

/// Safely reads a file from an environment variable path
/// with validation against allowed directories
pub fn safe_read_env_file(env_var: &str, allowed_dirs: &[&str]) -> Result<String, std::io::Error> {
    let path_str = std::env::var(env_var)
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::NotFound, "Environment variable not set"))?;
    
    let validated_path = validate_env_path(&path_str, allowed_dirs)
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::PermissionDenied, "Path not in allowed directories"))?;
    
    std::fs::read_to_string(validated_path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sanitize_rejects_parent_dir() {
        assert!(sanitize_path("../etc/passwd").is_none());
        assert!(sanitize_path("foo/../../etc/passwd").is_none());
    }

    #[test]
    fn test_sanitize_accepts_safe_paths() {
        assert!(sanitize_path("config/file.txt").is_some());
        assert!(sanitize_path("./config/file.txt").is_some());
    }

    #[test]
    fn test_sanitize_rejects_null_bytes() {
        assert!(sanitize_path("file\0.txt").is_none());
    }
}
