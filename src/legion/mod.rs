//! Legion security HEURISTICS engine module DEMO
//! This crate exposes two primary groups of functionality:
//! - `core`: foundational orchestration, configuration, and baseline collectors
//! - `modules`: domain-specific analytics and response capabilities

macro_rules! safe_println {
	() => {{
		use std::io::{self, Write};
		if let Err(e) = writeln!(io::stdout()) {
			if e.kind() == std::io::ErrorKind::BrokenPipe {
				std::process::exit(0);
			} else {
				let _ = writeln!(io::stderr(), "Write error: {}", e);
			}
		}
	}};
	($($arg:tt)*) => {{
		use std::io::{self, Write};
		if let Err(e) = writeln!(io::stdout(), $($arg)*) {
			if e.kind() == std::io::ErrorKind::BrokenPipe {
				std::process::exit(0);
			} else {
				let _ = writeln!(io::stderr(), "Write error: {}", e);
			}
		}
	}};
}

// pub(crate) use safe_println;

pub mod banner;
pub mod core;
pub mod functions;
pub mod modules;
