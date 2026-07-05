// SPDX-License-Identifier: MIT
/// Application version — read from Cargo.toml at compile time so it always
/// matches the release tag. To change the displayed version, update `version`
/// in Cargo.toml only.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Application name
pub const APP_NAME: &str = "HARDN";

/// Default environment variable values
pub const DEFAULT_LOG_DIR: &str = "/var/log/hardn";
pub const DEFAULT_LIB_DIR: &str = "/var/lib/hardn";

/// Exit codes
pub const EXIT_SUCCESS: i32 = 0;
pub const EXIT_FAILURE: i32 = 1;
pub const EXIT_USAGE: i32 = 2;
/// POSIX convention: "command not found". Returned when a requested
/// tool/module script doesn't exist on disk, distinct from EXIT_FAILURE
/// which means "the tool ran and failed". Lets cron and CI tell the two apart.
pub const EXIT_NOT_FOUND: i32 = 127;

/// Default directories to search for module scripts
/// These are searched in order, with the first match being used
pub const DEFAULT_MODULE_DIRS: &[&str] = &[
    "/usr/share/hardn/modules",         // Production: installed via package
    "/usr/lib/hardn/src/setup/modules", // Development/legacy
    "/usr/local/share/hardn/modules",   // Local installation
];

/// Default directories to search for tool scripts
/// Tools are standalone security utilities that can be run independently
pub const DEFAULT_TOOL_DIRS: &[&str] = &[
    "/usr/share/hardn/tools",         // Production: installed via package
    "/usr/lib/hardn/src/setup/tools", // Development/legacy
    "/usr/local/share/hardn/tools",   // Local installation
];
