pub mod alerts;
pub mod logging;
pub mod paths;
pub mod system;
pub mod updates;

// Re-export commonly used functions
pub use alerts::emit_alert;
pub use logging::{log_message, LogLevel};
pub use paths::{env_or_defaults, find_script, join_paths, list_modules};
pub use system::detect_debian_version;
#[allow(unused_imports)]
pub use updates::{check_for_update_to_show, UpdateInfo};
