/// Application version - single source of truth
pub const VERSION: &str = "2.2.0";

/// Application name
pub const APP_NAME: &str = "HARDN-XDR";

/// Default environment variable values
pub const DEFAULT_LOG_DIR: &str = "/var/log/hardn";
pub const DEFAULT_LIB_DIR: &str = "/var/lib/hardn";

/// Exit codes
pub const EXIT_SUCCESS: i32 = 0;
pub const EXIT_FAILURE: i32 = 1;
pub const EXIT_USAGE: i32 = 2;

/// Default directories to search for module scripts
/// These are searched in order, with the first match being used
pub const DEFAULT_MODULE_DIRS: &[&str] = &[
    "/usr/share/hardn/modules",              // Production: installed via package
    "/usr/lib/hardn-xdr/src/setup/modules",  // Development/legacy
    "/usr/local/share/hardn/modules",        // Local installation
];

/// Default directories to search for tool scripts
/// Tools are standalone security utilities that can be run independently
pub const DEFAULT_TOOL_DIRS: &[&str] = &[
    "/usr/share/hardn/tools",                // Production: installed via package
    "/usr/lib/hardn-xdr/src/setup/tools",    // Development/legacy
    "/usr/local/share/hardn/tools",          // Local installation
];
