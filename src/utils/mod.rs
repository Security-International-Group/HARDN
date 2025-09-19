pub mod logging;
pub mod paths;
pub mod system;

// Re-export commonly used functions
pub use logging::{LogLevel, log_message};
pub use paths::{env_or_defaults, find_script, list_modules, join_paths};
pub use system::detect_debian_version;
