use atty::Stream;
use once_cell::sync::Lazy;
use std::sync::atomic::{AtomicBool, Ordering};

// use crate::legion::safe_println;
use crate::utils::LogLevel;

static COLOR_ENABLED: Lazy<AtomicBool> = Lazy::new(|| {
    let enabled = atty::is(Stream::Stdout) && std::env::var_os("NO_COLOR").is_none();
    AtomicBool::new(enabled)
});

const RESET: &str = "\x1b[0m";

fn format_line(level: LogLevel, message: &str) -> String {
    if COLOR_ENABLED.load(Ordering::Relaxed) {
        format!(
            "{}{}{} {}",
            level.color_code(),
            level.prefix(),
            RESET,
            message
        )
    } else {
        format!("{} {}", level.prefix(), message)
    }
}

pub fn enable_color(enable: bool) {
    COLOR_ENABLED.store(enable, Ordering::Relaxed);
}

pub fn log(level: LogLevel, message: impl AsRef<str>) {
    safe_println!("{}", format_line(level, message.as_ref()));
}

pub fn info(message: impl AsRef<str>) {
    log(LogLevel::Info, message);
}

pub fn warn(message: impl AsRef<str>) {
    log(LogLevel::Warning, message);
}

pub fn error(message: impl AsRef<str>) {
    log(LogLevel::Error, message);
}

pub fn success(message: impl AsRef<str>) {
    log(LogLevel::Pass, message);
}

pub fn heading(title: impl AsRef<str>) {
    let title = title.as_ref();
    safe_println!("{}", title);
    safe_println!("{}", "=".repeat(title.chars().count()));
}

pub fn detail(message: impl AsRef<str>) {
    safe_println!("    {}", message.as_ref());
}

pub fn blank_line() {
    safe_println!();
}
