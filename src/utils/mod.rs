pub mod alerts;
pub mod logging;
pub mod paths;
pub mod system;

// Re-export commonly used functions
pub use alerts::emit_alert;
pub use logging::{log_message, LogLevel};
pub use paths::{env_or_defaults, find_script, join_paths, list_modules};
#[allow(deprecated, unused_imports)]
pub use system::detect_debian_version;
#[allow(unused_imports)]
pub use system::{detect_os, OsInfo};
