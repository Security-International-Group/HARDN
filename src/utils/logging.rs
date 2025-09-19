use std::fmt;

/// Log levels for colored console output
#[derive(Debug, Clone, Copy)]
pub enum LogLevel {
    Pass,
    Info,
    Warning,
    Error,
}

impl LogLevel {
    pub fn color_code(&self) -> &'static str {
        match self {
            Self::Pass => "\x1b[1;32m",    // Green
            Self::Info => "\x1b[1;34m",    // Blue
            Self::Warning => "\x1b[1;33m", // Yellow
            Self::Error => "\x1b[1;31m",   // Red
        }
    }

    pub fn prefix(&self) -> &'static str {
        match self {
            Self::Pass => "[PASS]",
            Self::Info => "[INFO]",
            Self::Warning => "[WARNING]",
            Self::Error => "[ERROR]",
        }
    }
}

impl fmt::Display for LogLevel {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}{}{}", self.color_code(), self.prefix(), "\x1b[0m")
    }
}

/// Improved logging function with direct enum usage
pub fn log_message(level: LogLevel, message: &str) {
    println!("{} {}", level, message);
}
