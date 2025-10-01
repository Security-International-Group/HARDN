use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use glib::clone;
use glib::timeout_add_local;
use glib::ControlFlow;
use gtk4::prelude::{ApplicationExt, ApplicationExtManual};
use gtk4::{prelude::*, Application, ApplicationWindow, ScrolledWindow, TextBuffer, TextView};

// Simple normalized event structure
#[derive(Clone, Debug)]
struct EventItem {
    timestamp: String,
    source: String,
    message: String,
}

// Ring buffer to cap memory usage
struct EventBuffer {
    items: Vec<EventItem>,
    max_items: usize,
}

impl EventBuffer {
    fn new(max_items: usize) -> Self {
        Self {
            items: Vec::with_capacity(max_items.min(10_000)),
            max_items,
        }
    }

    fn push(&mut self, item: EventItem) {
        self.items.push(item);
        if self.items.len() > self.max_items {
            let overflow = self.items.len() - self.max_items;
            self.items.drain(0..overflow);
        }
    }

    fn to_display_text(&self) -> String {
        let mut out = String::with_capacity(self.items.len().saturating_mul(96));
        for ev in &self.items {
            out.push_str(&format!(
                "[{}] {}: {}\n",
                ev.timestamp, ev.source, ev.message
            ));
        }
        out
    }
}

// Very small journald tailer via `journalctl -fu` spawned process.
// This keeps the implementation lightweight without extra deps.
// NOTE: journald integration removed per product design: GUI monitors only HARDN log files

fn spawn_file_tail(path: &str) -> std::io::Result<std::process::Child> {
    // Tail last 100 lines then follow
    std::process::Command::new("tail")
        .args(["-n", "100", "-F", path])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
}

#[derive(Clone, Debug, Default)]
struct ServiceHealth {
    hardn: Option<bool>,
    api: Option<bool>,
    legion: Option<bool>,
    monitor: Option<bool>,
}

#[derive(Clone, Debug, Default)]
struct AlertsState {
    metrics: Option<String>,        // e.g., "cpu=12% mem=34% load=0.50,0.40,0.30"
    legion_summary: Option<String>, // e.g., "risk=0.123 level=Low indicators=2 issues=1"
}

fn parse_service_status(line: &str) -> Option<ServiceHealth> {
    if !line.contains("Service Status -") {
        return None;
    }
    let mut health = ServiceHealth::default();
    if let Some(idx) = line.find("Service Status -") {
        let slice = &line[idx + "Service Status -".len()..];
        for part in slice.split(',') {
            let p = part.trim();
            let (name, state) = if let Some((n, s)) = p.split_once(':') {
                (n.trim(), s.trim())
            } else {
                continue;
            };
            let running =
                state.eq_ignore_ascii_case("running") || state.eq_ignore_ascii_case("active");
            match name {
                "hardn" => health.hardn = Some(running),
                "hardn-api" | "api" => health.api = Some(running),
                "legion-daemon" | "legion" => health.legion = Some(running),
                "hardn-monitor" | "monitor" => health.monitor = Some(running),
                _ => {}
            }
        }
        return Some(health);
    }
    None
}

fn render_header_text(h: &ServiceHealth) -> String {
    let mk = |label: &str, v: Option<bool>| match v {
        Some(true) => format!("{}: RUNNING", label),
        Some(false) => format!("{}: DOWN", label),
        None => format!("{}: ?", label),
    };
    let header = format!(
        "{}  {}  {}  {}\n",
        mk("HARDN", h.hardn),
        mk("API", h.api),
        mk("LEGION", h.legion),
        mk("MONITOR", h.monitor)
    );
    let any_down = [h.hardn, h.api, h.legion, h.monitor]
        .into_iter()
        .any(|x| matches!(x, Some(false)));
    if any_down {
        format!(
            "{}Tip: To interact with HARDN run: sudo hardn-service-manager\n\n",
            header
        )
    } else {
        format!("{}\n", header)
    }
}

fn parse_metrics(line: &str) -> Option<String> {
    // From monitor: "Metrics - cpu=..% mem=..% load=x,y,z"
    if let Some(idx) = line.find("Metrics - ") {
        return Some(line[idx + "Metrics - ".len()..].trim().to_string());
    }
    None
}

fn parse_legion_summary(line: &str) -> Option<String> {
    if let Some(idx) = line.find("LEGION SUMMARY:") {
        return Some(line[idx + "LEGION SUMMARY:".len()..].trim().to_string());
    }
    None
}

fn normalize_line(line: &str) -> Option<EventItem> {
    // journalctl short-iso typically: "2025-09-27T12:34:56+00:00 hostname unit[pid]: message"
    // We'll try to split timestamp and the rest; keep robust if format varies.
    let line = line.trim();
    if line.is_empty() {
        return None;
    }

    // Extract timestamp (first token) and message
    let mut parts = line.splitn(2, ' ');
    let ts = parts.next().unwrap_or("").to_string();
    let rest = parts.next().unwrap_or("");

    // Attempt to extract source like "unit[pid]:" before message
    let source_end = rest.find(':');
    let (source, message) = match source_end {
        Some(idx) => {
            let (src, msg) = rest.split_at(idx);
            (
                src.trim().to_string(),
                msg.trim_start_matches(':').trim().to_string(),
            )
        }
        None => ("journal".to_string(), rest.to_string()),
    };

    Some(EventItem {
        timestamp: ts,
        source,
        message,
    })
}

fn now_iso() -> String {
    let now = SystemTime::now();
    let dt: chrono::DateTime<chrono::Utc> = now.into();
    dt.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

fn main() {
    // Keep GUI separate and read-only
    // Use no application_id to avoid session D-Bus registration requirement
    let app = Application::new(None::<&str>, Default::default());

    app.connect_activate(|app| {
        // UI widgets
        let text_view = TextView::new();
        text_view.set_editable(false);
        text_view.set_cursor_visible(false);
        text_view.set_monospace(true);
        text_view.add_css_class("view");
        let buffer: TextBuffer = text_view.buffer();

        let scroll = ScrolledWindow::new();
        scroll.set_policy(gtk4::PolicyType::Automatic, gtk4::PolicyType::Automatic);
        scroll.set_child(Some(&text_view));

        let window = ApplicationWindow::builder()
            .application(app)
            .title("HARDN Monitor (Read-Only)")
            .default_width(980)
            .default_height(640)
            .child(&scroll)
            .build();

        // Ring buffer: assume ~200 bytes/event average -> 500_000 events ~100MB; we target ~50MB.
        // Choose 250_000 events cap conservatively (<200MB with safety margin depending on strings).
        let event_buffer = Arc::new(Mutex::new(EventBuffer::new(250_000)));
        let service_health = Arc::new(Mutex::new(ServiceHealth::default()));
        let alerts_state = Arc::new(Mutex::new(AlertsState::default()));

        // Journald support removed; this GUI reads only HARDN log files.
        let child: Option<std::process::Child> = None;

        // Also try to tail primary log files if they exist
        let mut file_children: Vec<(String, std::process::Child)> = Vec::new();
        for path in [
            "/var/log/hardn/hardn-monitor.log",
            "/var/log/hardn/legion.log",
            "/var/log/hardn/legion-audit.log",
        ] {
            if std::path::Path::new(path).exists() {
                if let Ok(ch) = spawn_file_tail(path) { file_children.push((path.to_string(), ch)); }
            }
        }

        // Shared state for reader
        let rb = event_buffer.clone();
        let health_ref = service_health.clone();
        let alerts_ref = alerts_state.clone();
        let buf_for_ui = buffer.clone();

        // Periodic UI refresh (pull model) ~10 times/second is cheap; we use 5/sec
        timeout_add_local(Duration::from_millis(200), clone!(@strong rb, @strong buf_for_ui, @strong alerts_ref => move || {
            let header = if let Ok(h) = health_ref.lock() { render_header_text(&*h) } else { String::new() };
            let alerts = if let Ok(a) = alerts_ref.lock() {
                let mut s = String::new();
                if let Some(ref m) = a.metrics { s.push_str(&format!("Metrics: {}\n", m)); }
                if let Some(ref l) = a.legion_summary { s.push_str(&format!("LEGION: {}\n", l)); }
                if !s.is_empty() { s.push('\n'); }
                s
            } else { String::new() };
            let body = rb.lock().map(|b| b.to_display_text()).unwrap_or_else(|_| String::new());
            buf_for_ui.set_text(&(header + &alerts + &body));
            ControlFlow::Continue
        }));

        // Background thread to read stdout lines from journalctl and append to ring buffer
        if let Some(mut child) = child {
            if let Some(stdout) = child.stdout.take() {
                let rb_lines = event_buffer.clone();
                std::thread::spawn(move || {
                    use std::io::{BufRead, BufReader};
                    let reader = BufReader::new(stdout);
                    for line in reader.lines().flatten() {
                        if let Ok(mut guard) = rb_lines.lock() {
                            if let Some(item) = normalize_line(&line) {
                                guard.push(item);
                            } else {
                                guard.push(EventItem { timestamp: now_iso(), source: "journal".into(), message: line });
                            }
                        }
                    }
                });
            }
        } else {
            // Journald disabled by default; nothing to report here.
        }

        // Collect from file tails as well
        for (path, mut ch) in file_children.into_iter() {
            if let Some(stdout) = ch.stdout.take() {
                let rb_lines = event_buffer.clone();
                let service_health_ref = service_health.clone();
                let alerts_local = alerts_state.clone();
                std::thread::spawn(move || {
                    use std::io::{BufRead, BufReader};
                    let reader = BufReader::new(stdout);
                    for line in reader.lines().flatten() {
                        if let Ok(mut g) = rb_lines.lock() {
                            if let Some(h) = parse_service_status(&line) {
                                if let Ok(mut hs) = service_health_ref.lock() {
                                    // merge
                                    if h.hardn.is_some() { hs.hardn = h.hardn; }
                                    if h.api.is_some() { hs.api = h.api; }
                                    if h.legion.is_some() { hs.legion = h.legion; }
                                    if h.monitor.is_some() { hs.monitor = h.monitor; }
                                }
                            }
                            if let Some(m) = parse_metrics(&line) {
                                if let Ok(mut a) = alerts_local.lock() { a.metrics = Some(m); }
                            }
                            if let Some(ls) = parse_legion_summary(&line) {
                                if let Ok(mut a) = alerts_local.lock() { a.legion_summary = Some(ls); }
                            }
                            // If this tail is from hardn-monitor itself, mark monitor as running
                            if path.ends_with("hardn-monitor.log") {
                                if let Ok(mut hs) = service_health_ref.lock() {
                                    hs.monitor = Some(true);
                                }
                            }
                            g.push(EventItem { timestamp: now_iso(), source: "file".into(), message: line });
                        }
                    }
                });
            }
        }

        window.present();
    });

    app.run();
}
