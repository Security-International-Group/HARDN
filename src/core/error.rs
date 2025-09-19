use std::fmt;
use std::error::Error;
use std::io;

/// Custom error type for better error handling
#[derive(Debug)]
pub enum HardnError {
    #[allow(dead_code)]
    ModuleNotFound(String),
    #[allow(dead_code)]
    ToolNotFound(String),
    ExecutionFailed(String),
    IoError(io::Error),
    #[allow(dead_code)]
    InvalidArgument(String),
}

impl fmt::Display for HardnError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            HardnError::ModuleNotFound(name) => write!(f, "Module '{}' not found", name),
            HardnError::ToolNotFound(name) => write!(f, "Tool '{}' not found", name),
            HardnError::ExecutionFailed(msg) => write!(f, "Execution failed: {}", msg),
            HardnError::IoError(err) => write!(f, "I/O error: {}", err),
            HardnError::InvalidArgument(msg) => write!(f, "Invalid argument: {}", msg),
        }
    }
}

impl Error for HardnError {}

impl From<io::Error> for HardnError {
    fn from(err: io::Error) -> Self {
        HardnError::IoError(err)
    }
}

/// Result type alias for cleaner code
pub type HardnResult<T> = Result<T, HardnError>;
