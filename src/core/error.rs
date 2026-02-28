use std::error::Error;
use std::fmt;
use std::io;

/// Custom error type for better error handling
#[derive(Debug)]
pub enum HardnError {
    ExecutionFailed(String),
    IoError(io::Error),
}

impl fmt::Display for HardnError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            HardnError::ExecutionFailed(msg) => write!(f, "Execution failed: {}", msg),
            HardnError::IoError(err) => write!(f, "I/O error: {}", err),
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
