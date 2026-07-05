use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use gtk4::glib::{ControlFlow, timeout_add_local};
use gtk4::prelude::{ApplicationExt, ApplicationExtManual};
use gtk4::{
    Application, ApplicationWindow, Box as GtkBox, CssProvider, Label, Notebook, Orientation,
    Paned, Picture, STYLE_PROVIDER_PRIORITY_APPLICATION, ScrolledWindow, TextBuffer, TextMark,
    TextView, gdk, prelude::*,
};
use std::cell::RefCell;
use std::rc::Rc;
use vte4::{PtyFlags, Terminal as VteTerminal, TerminalExt, TerminalExtManual};

// Simple normalized event structure
#[derive(Clone, Debug)]
struct EventItem {
    timestamp: String,
    source: String,
    message: String,
}

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

    fn len(&self) -> usize {
        self.items.len()
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

/// Strip ANSI escape sequences and bare control characters from a log line so
/// GTK's TextView renders it cleanly at any window size.
///
/// Without this, tools that emit cursor-movement codes (e.g. ufw emitting
/// \r\033[G between "Rules updated" lines) store those bytes verbatim in the
/// log file. When read back by `tail -f`, GTK renders \r as a paragraph break
/// and ESC bytes as replacement-character boxes, pushing each following line
/// progressively further to the right — the staircase misalignment reported
/// on resize (un-maximising the window makes re-layout re-trigger the effect).
fn strip_control(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\x1b' {
            // ANSI/VT escape sequence — skip until final byte (ASCII letter)
            if chars.peek() == Some(&'[') {
                chars.next(); // consume '['
                for c2 in chars.by_ref() {
                    if c2.is_ascii_alphabetic() {
                        break;
                    }
                }
            } else {
                chars.next(); // two-char escape (e.g. \x1b=)
            }
        } else if c == '\r' {
            // Bare carriage return — drop it; split on \n only
        } else if c.is_control() && c != '\n' && c != '\t' {
            // Other C0 control chars — skip
        } else {
            out.push(c);
        }
    }
    out
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
    core_services: Option<String>, // e.g., "systemd=running networkd=running journald=running"
    systemd_metrics: Option<String>, // e.g., "failed_units=0 queued_jobs=0"
    journal_metrics: Option<String>, // e.g., "disk_usage_mb=12.3"
    network_metrics: Option<String>, // e.g., "links=3 online=3 degraded=0"
    metrics: Option<String>,       // e.g., "cpu=12% mem=34% load=0.50,0.40,0.30"
    database_metrics: Option<String>, // e.g., "status=healthy baselines=5 anomalies=2 size=1.2MB"
    legion_summary: Option<String>, // e.g., "risk=0.123 level=Low indicators=2 issues=1"
}

/// One actionable alert emitted by hardn-monitor (or any other producer) into
/// /var/log/hardn/alerts.jsonl. Alerts with the same `key` collapse to a
/// single row in the GUI so a service that's down for many poll cycles
/// produces one alert that updates in place rather than a flood.
#[derive(Clone, Debug)]
struct Alert {
    ts: String,
    severity: String,
    source: String,
    message: String,
    key: String,
}

#[derive(Default)]
struct AlertsList {
    /// Insertion-ordered map from dedup key to alert. We use Vec<(key, Alert)>
    /// rather than HashMap so display order stays stable.
    entries: Vec<(String, Alert)>,
    /// Monotonic counter of alerts seen since GUI start. Used for the badge.
    total_seen: usize,
}

impl AlertsList {
    fn ingest(&mut self, alert: Alert) {
        self.total_seen += 1;
        let key = if alert.key.is_empty() {
            // No key supplied — treat each alert as unique
            format!("noKey:{}:{}", alert.ts, self.total_seen)
        } else {
            alert.key.clone()
        };
        if let Some(slot) = self.entries.iter_mut().find(|(k, _)| k == &key) {
            slot.1 = alert;
        } else {
            self.entries.push((key, alert));
        }
    }

    fn render_text(&self) -> String {
        if self.entries.is_empty() {
            return String::from("(no alerts)\n");
        }
        let mut out = String::new();
        for (_, a) in &self.entries {
            out.push_str(&format!(
                "[{}] {} {} :: {}\n",
                a.severity.to_uppercase(),
                a.ts,
                a.source,
                a.message,
            ));
        }
        out
    }

    fn count_by_max_severity(&self) -> (usize, &'static str) {
        let mut count = 0usize;
        let mut max_sev = "info";
        let rank = |s: &str| match s {
            "critical" => 4,
            "error" => 3,
            "warning" => 2,
            "info" => 1,
            _ => 0,
        };
        for (_, a) in &self.entries {
            count += 1;
            if rank(&a.severity) > rank(max_sev) {
                max_sev = match a.severity.as_str() {
                    "critical" => "critical",
                    "error" => "error",
                    "warning" => "warning",
                    _ => "info",
                };
            }
        }
        (count, max_sev)
    }
}

fn parse_alert_line(line: &str) -> Option<Alert> {
    let v: serde_json::Value = serde_json::from_str(line.trim()).ok()?;
    Some(Alert {
        ts: v.get("ts")?.as_str()?.to_string(),
        severity: v
            .get("severity")
            .and_then(|s| s.as_str())
            .unwrap_or("info")
            .to_string(),
        source: v
            .get("source")
            .and_then(|s| s.as_str())
            .unwrap_or("unknown")
            .to_string(),
        message: v.get("message")?.as_str()?.to_string(),
        key: v
            .get("key")
            .and_then(|s| s.as_str())
            .unwrap_or("")
            .to_string(),
    })
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

fn parse_metrics(line: &str) -> Option<String> {
    // From monitor: "Metrics - cpu=..% mem=..% load=x,y,z"
    if let Some(idx) = line.find("Metrics - ") {
        return Some(line[idx + "Metrics - ".len()..].trim().to_string());
    }
    None
}

fn parse_core_services(line: &str) -> Option<String> {
    if let Some(idx) = line.find("Core Services - ") {
        return Some(line[idx + "Core Services - ".len()..].trim().to_string());
    }
    None
}

fn parse_systemd_metrics(line: &str) -> Option<String> {
    if let Some(idx) = line.find("Systemd Metrics - ") {
        return Some(line[idx + "Systemd Metrics - ".len()..].trim().to_string());
    }
    None
}

fn parse_journal_metrics(line: &str) -> Option<String> {
    if let Some(idx) = line.find("Journal Metrics - ") {
        return Some(line[idx + "Journal Metrics - ".len()..].trim().to_string());
    }
    None
}

fn parse_networkd_metrics(line: &str) -> Option<String> {
    if let Some(idx) = line.find("Networkd Metrics - ") {
        return Some(line[idx + "Networkd Metrics - ".len()..].trim().to_string());
    }
    None
}

fn parse_database_metrics(line: &str) -> Option<String> {
    // From monitor: "Database - status=healthy baselines=X anomalies=Y size=Z"
    if let Some(idx) = line.find("Database - ") {
        return Some(line[idx + "Database - ".len()..].trim().to_string());
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

/// Build a plain-text inventory of the security tools shipped under
/// `/usr/share/hardn/tools/*.sh`. The first non-shebang, non-blank comment
/// line of each script is used as the description. Cheap directory walk;
/// runs once at GUI startup and the text is static thereafter.
fn build_tools_inventory() -> String {
    let candidates = [
        "/usr/share/hardn/tools",
        "/usr/local/share/hardn/tools",
        "./usr/share/hardn/tools",
    ];
    let mut dir = None;
    for c in &candidates {
        if std::path::Path::new(c).is_dir() {
            dir = Some(*c);
            break;
        }
    }
    let dir = match dir {
        Some(d) => d,
        None => {
            return "Tools directory not found.\n\n\
                    Searched:\n  /usr/share/hardn/tools\n  /usr/local/share/hardn/tools\n"
                .to_string();
        }
    };

    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(err) => return format!("Unable to read {}: {}\n", dir, err),
    };

    let mut tools: Vec<(String, String)> = Vec::new();
    for ent in entries.flatten() {
        let path = ent.path();
        if path.extension().and_then(|s| s.to_str()) != Some("sh") {
            continue;
        }
        let name = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("?")
            .to_string();
        let desc = first_comment_summary(&path).unwrap_or_else(|| "(no description)".into());
        tools.push((name, desc));
    }
    tools.sort_by(|a, b| a.0.cmp(&b.0));

    let mut out = String::new();
    out.push_str(&format!(
        "HARDN Tools Inventory\n\
         =====================\n\
         Source: {}\n\
         {} tools shipped.\n\n",
        dir,
        tools.len()
    ));
    for (name, desc) in &tools {
        out.push_str(&format!("  • {:<22} {}\n", name, desc));
    }
    out.push_str(
        "\nRun a tool from the command line with:\n  sudo hardn run-tool <name>\n\
         Or from the Terminal tab via hardn-service-manager.\n",
    );
    out
}

/// First non-empty, non-shebang comment line. Used to show a one-line
/// summary alongside each tool name in the inventory tab.
fn first_comment_summary(path: &std::path::Path) -> Option<String> {
    let s = std::fs::read_to_string(path).ok()?;
    for (i, line) in s.lines().enumerate() {
        let line = line.trim();
        if i == 0 && line.starts_with("#!") {
            continue;
        }
        if line.is_empty() || line == "#" {
            continue;
        }
        if let Some(rest) = line.strip_prefix("# ") {
            return Some(rest.trim().to_string());
        }
        if let Some(rest) = line.strip_prefix('#') {
            let t = rest.trim();
            if !t.is_empty() {
                return Some(t.to_string());
            }
        }
        // First code line — give up
        break;
    }
    None
}

/// Path to the marker file. When it exists, the welcome wizard does not
/// pop up on startup. The user can re-trigger by passing `--welcome` or
/// deleting the file. Lives in $XDG_CONFIG_HOME (default ~/.config).
fn welcome_marker_path() -> std::path::PathBuf {
    let base = std::env::var("XDG_CONFIG_HOME")
        .ok()
        .filter(|s| !s.is_empty())
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| {
            let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
            std::path::PathBuf::from(home).join(".config")
        });
    base.join("hardn").join("welcome-seen")
}

/// Show a Debian-style stepped welcome dialog. Modal, transient on the
/// main window, drives a `Stack` between four pages with Back / Next /
/// Skip / Done buttons. A "Don't show again" checkbox on the final page
/// writes the marker file so the wizard never re-opens on this user's
/// account.
fn show_welcome_wizard(parent: &ApplicationWindow) {
    let dialog = gtk4::Window::builder()
        .transient_for(parent)
        .modal(true)
        .title("Welcome to HARDN")
        .default_width(640)
        .default_height(440)
        .build();
    dialog.set_resizable(true);

    let outer = GtkBox::new(Orientation::Vertical, 0);

    let header = gtk4::HeaderBar::new();
    header.set_show_title_buttons(true);
    let header_title = gtk4::Label::new(Some("HARDN — first run"));
    header.set_title_widget(Some(&header_title));
    outer.append(&header);

    let stack = gtk4::Stack::new();
    stack.set_transition_type(gtk4::StackTransitionType::SlideLeftRight);
    stack.set_hexpand(true);
    stack.set_vexpand(true);
    stack.set_margin_top(18);
    stack.set_margin_bottom(8);
    stack.set_margin_start(20);
    stack.set_margin_end(20);

    let pages: [(&str, &str, &str); 4] = [
        (
            "p1",
            "What is HARDN?",
            "HARDN is a Debian/Ubuntu security hardening toolkit. It bundles \
             dozens of small modules (SSH hardening, auditd rules, sysctl tuning, \
             AppArmor, fail2ban, AIDE, …) behind one orchestrator, and runs \
             continuous detection through a built-in monitor called LEGION.\n\n\
             This window is a <b>read-only monitor</b>. It never runs privileged \
             commands on your behalf without you typing a password at a sudo prompt.",
        ),
        (
            "p2",
            "Reading the GUI",
            "<b>Logs</b> — live tail of <tt>/var/log/hardn/*.log</tt> with ANSI \
             control codes stripped so the text stays legible at any window size.\n\n\
             <b>Terminal</b> — an embedded VTE terminal. Selecting this tab \
             auto-launches <tt>sudo hardn-service-manager</tt>; you'll be asked for \
             your password.\n\n\
             <b>Logs + Terminal</b> — the previous two in a single vertical split.\n\n\
             <b>Alerts</b> — deduplicated entries from \
             <tt>/var/log/hardn/alerts.jsonl</tt>: SENTRY file-drift alerts, service \
             health, LEGION findings.\n\n\
             <b>Tools</b> — inventory of every script under \
             <tt>/usr/share/hardn/tools/</tt> with a one-line description.",
        ),
        (
            "p3",
            "Common actions",
            "From a regular shell — none of these need this GUI to be open:\n\n\
             <tt>  sudo hardn --help</tt>             list every command\n\
             <tt>  sudo hardn --sentry-check</tt>     diff high-value files vs baseline\n\
             <tt>  sudo hardn run-module <i>name</i></tt>     run one hardening module\n\
             <tt>  sudo hardn run-tool   <i>name</i></tt>     run one security tool\n\
             <tt>  sudo hardn legion --create-baseline</tt>   capture a fresh baseline\n\n\
             To remove HARDN cleanly:\n\
             <tt>  sudo /usr/share/hardn/scripts/hardn-uninstall.sh --help</tt>",
        ),
        (
            "p4",
            "Where to get help",
            "Issues, feature requests, and security reports:\n\n\
             <tt>  https://github.com/Security-International-Group/HARDN</tt>\n\n\
             Logs to attach when reporting:\n\
             <tt>  /var/log/hardn/*.log</tt>\n\
             <tt>  /var/log/hardn/alerts.jsonl</tt>\n\
             <tt>  journalctl -u hardn -u hardn-monitor -u hardn-api</tt>",
        ),
    ];

    for (id, title, body) in &pages {
        let page_box = GtkBox::new(Orientation::Vertical, 14);
        let h = gtk4::Label::new(None);
        h.set_xalign(0.0);
        h.set_markup(&format!(
            "<span size='x-large' weight='bold'>{}</span>",
            title
        ));
        let b = gtk4::Label::new(None);
        b.set_use_markup(true);
        b.set_wrap(true);
        b.set_xalign(0.0);
        b.set_markup(body);
        page_box.append(&h);
        page_box.append(&b);
        stack.add_named(&page_box, Some(*id));
    }

    outer.append(&stack);

    // Page indicator: "Step 1 of 4" etc.
    let indicator = gtk4::Label::new(Some("Step 1 of 4"));
    indicator.add_css_class("clock"); // reuse muted style
    indicator.set_margin_start(20);
    indicator.set_margin_end(20);
    indicator.set_xalign(0.0);
    outer.append(&indicator);

    // "Don't show again" — only meaningful on the last page, but expose it
    // throughout so users can tick it whenever they're sure.
    let dont_show = gtk4::CheckButton::with_label("Don't show this on next launch");
    dont_show.set_margin_start(20);
    dont_show.set_margin_end(20);
    dont_show.set_margin_top(6);
    dont_show.set_margin_bottom(6);
    outer.append(&dont_show);

    let btn_box = GtkBox::new(Orientation::Horizontal, 8);
    btn_box.set_margin_start(20);
    btn_box.set_margin_end(20);
    btn_box.set_margin_bottom(14);
    btn_box.set_halign(gtk4::Align::End);

    let btn_skip = gtk4::Button::with_label("Skip");
    btn_skip.set_tooltip_text(Some("Close this wizard without finishing the tour"));
    let btn_back = gtk4::Button::with_label("Back");
    btn_back.set_sensitive(false);
    let btn_next = gtk4::Button::with_label("Next");
    btn_next.add_css_class("suggested-action");
    btn_box.append(&btn_skip);
    btn_box.append(&btn_back);
    btn_box.append(&btn_next);
    outer.append(&btn_box);

    dialog.set_child(Some(&outer));

    // Page-walk state.
    let current = Rc::new(RefCell::new(0usize));
    let total = pages.len();

    // Closure to refresh the visible page + button labels + indicator.
    let refresh = {
        let stack = stack.clone();
        let indicator = indicator.clone();
        let btn_back = btn_back.clone();
        let btn_next = btn_next.clone();
        let current = current.clone();
        let page_ids: Vec<&'static str> = pages.iter().map(|(id, _, _)| *id).collect();
        move || {
            let idx = *current.borrow();
            stack.set_visible_child_name(page_ids[idx]);
            indicator.set_text(&format!("Step {} of {}", idx + 1, total));
            btn_back.set_sensitive(idx > 0);
            if idx + 1 == total {
                btn_next.set_label("Done");
            } else {
                btn_next.set_label("Next");
            }
        }
    };
    refresh();

    {
        let current = current.clone();
        let refresh = refresh.clone();
        btn_back.connect_clicked(move |_| {
            let mut idx = current.borrow_mut();
            if *idx > 0 {
                *idx -= 1;
                drop(idx);
                refresh();
            }
        });
    }

    let close_action = {
        let dialog = dialog.clone();
        let dont_show = dont_show.clone();
        move || {
            if dont_show.is_active() {
                let path = welcome_marker_path();
                if let Some(parent) = path.parent() {
                    let _ = std::fs::create_dir_all(parent);
                }
                let _ = std::fs::write(&path, "1\n");
            }
            dialog.close();
        }
    };

    {
        let current = current.clone();
        let refresh = refresh.clone();
        let close_action = close_action.clone();
        btn_next.connect_clicked(move |_| {
            let mut idx = current.borrow_mut();
            if *idx + 1 >= total {
                drop(idx);
                close_action();
            } else {
                *idx += 1;
                drop(idx);
                refresh();
            }
        });
    }

    {
        let close_action = close_action.clone();
        btn_skip.connect_clicked(move |_| close_action());
    }

    dialog.present();
}

fn main() {
    // Keep GUI separate and read-only
    // Use no application_id to avoid session D-Bus registration requirement
    let app = Application::new(None::<&str>, Default::default());

    app.connect_activate(|app| {
        // Application styling (prefer external CSS for separation of concerns)
        if let Some(display) = gdk::Display::default() {
            let provider = CssProvider::new();
            let css_data = {
                // External CSS search order
                let mut data: Option<String> = None;
                if let Ok(path_str) = std::env::var("HARDN_GUI_CSS") {
                    // Validate path from environment variable against whitelist
                    let allowed_css_dirs = [
                        "/usr/share/hardn",
                        "/usr/local/share/hardn",
                        "/etc/hardn",
                    ];

                    // Validate path against whitelist of allowed directories
                    let validated = std::path::PathBuf::from(&path_str)
                        .canonicalize()
                        .ok()
                        .filter(|p| allowed_css_dirs.iter().any(|d| p.starts_with(d)));
                    if let Some(validated_path) = validated {
                        data = std::fs::read_to_string(validated_path).ok();
                    }
                }
                if data.is_none() {
                    for p in [
                        "/usr/share/hardn/gui/style.css",
                        "/usr/local/share/hardn/gui/style.css",
                        "./etc/gui/style.css",
                        "./gui/style.css",
                    ] {
                        if let Ok(s) = std::fs::read_to_string(p) { data = Some(s); break; }
                    }
                }
                data.unwrap_or_else(|| {
                    // Fallback embedded theme (black + green, tactical)
                    String::from(
                        "* { background: #000; color: #d1ffe8; font-family: \"JetBrains Mono\", monospace; }\nwindow, scrolledwindow, viewport, notebook, textview, textview.view, vte-terminal, paned { background: #000; color: #d1ffe8; }\n/* Tabs */\nnotebook > header { padding: 2px 8px; }\nnotebook > header > tabs > tab { background: #000; color: #81e6d9; padding: 8px 12px; margin-right: 6px; border-radius: 6px 6px 0 0; border-bottom: 2px solid transparent; }\nnotebook > header > tabs > tab:checked { color: #d1ffe8; border-bottom: 2px solid #10b981; }\n/* Content boxes */\ntextview.view, vte-terminal { border: 1px solid #073e2c; box-shadow: inset 0 0 0 1px rgba(16,185,129,0.08); }\n.box-header { padding: 8px 10px; }\n.clock { color: #86efac; }\n/* Badges */\n.badge { border-radius: 14px; padding: 3px 10px; margin-right: 8px; background: #000; color: #81e6d9; border: 1px solid #073e2c; }\n.badge-ok { background: #001a14; color: #34d399; border-color: #10b981; }\n.badge-down { background: #1a0000; color: #fca5a5; border-color: #ef4444; }\n.badge-unknown { background: #000; color: #94a3b8; border-style: dashed; border-color: #334155; }\n/* Gridlines subtle */\ntextview.view, vte-terminal { background-image: linear-gradient(rgba(16, 185, 129, 0.03) 1px, transparent 1px), linear-gradient(90deg, rgba(16, 185, 129, 0.03) 1px, transparent 1px); background-size: 32px 32px, 32px 32px; }\n",
                    )
                })
            };
            provider.load_from_data(&css_data);
            gtk4::style_context_add_provider_for_display(&display, &provider, STYLE_PROVIDER_PRIORITY_APPLICATION);
        }
        if let Some(settings) = gtk4::Settings::default() {
            settings.set_gtk_application_prefer_dark_theme(true);
        }

        // Logs buffer with two separate views (tab and split)
        let buffer: TextBuffer = TextBuffer::new(None);
        // Keep a mark at the end to allow smooth follow scrolling
        let tmp_end = buffer.end_iter();
        let end_mark: TextMark = buffer.create_mark(Some("log_end"), &tmp_end, true);

    let text_view_tab = TextView::new();
        text_view_tab.set_editable(false);
        text_view_tab.set_cursor_visible(false);
        text_view_tab.set_monospace(true);
        text_view_tab.set_wrap_mode(gtk4::WrapMode::None);
        text_view_tab.add_css_class("view");
        text_view_tab.set_buffer(Some(&buffer));

        let text_view_split = TextView::new();
        text_view_split.set_editable(false);
        text_view_split.set_cursor_visible(false);
        text_view_split.set_monospace(true);
        text_view_split.set_wrap_mode(gtk4::WrapMode::None);
        text_view_split.add_css_class("view");
        text_view_split.set_buffer(Some(&buffer));

    // Main (left) logs view that lives outside the notebook so it can
    // occupy the full left column of the application. It shares the
    // same `buffer` as the tabbed views so content is consistent.
    let main_text_view = TextView::new();
    main_text_view.set_editable(false);
    main_text_view.set_cursor_visible(false);
    main_text_view.set_monospace(true);
    main_text_view.set_wrap_mode(gtk4::WrapMode::None);
    main_text_view.add_css_class("view");
    main_text_view.set_buffer(Some(&buffer));

        let logs_scroll_tab = ScrolledWindow::new();
        logs_scroll_tab.set_policy(gtk4::PolicyType::Automatic, gtk4::PolicyType::Automatic);
        logs_scroll_tab.set_child(Some(&text_view_tab));
        logs_scroll_tab.set_overlay_scrolling(false);
        logs_scroll_tab.set_kinetic_scrolling(false);
        logs_scroll_tab.set_hexpand(true);
        logs_scroll_tab.set_vexpand(true);

    let logs_scroll_split = ScrolledWindow::new();
        logs_scroll_split.set_policy(gtk4::PolicyType::Automatic, gtk4::PolicyType::Automatic);
        logs_scroll_split.set_child(Some(&text_view_split));
        logs_scroll_split.set_overlay_scrolling(false);
        logs_scroll_split.set_kinetic_scrolling(false);
        logs_scroll_split.set_hexpand(true);
        logs_scroll_split.set_vexpand(true);

        // Terminal views (two instances: tab and split)
        let terminal_tab = VteTerminal::new();
        let term_scroll_tab = ScrolledWindow::new();
        term_scroll_tab.set_policy(gtk4::PolicyType::Automatic, gtk4::PolicyType::Automatic);
        term_scroll_tab.set_child(Some(&terminal_tab));
        term_scroll_tab.set_hexpand(true);
    term_scroll_tab.set_vexpand(true);
    // Make the terminal request a reasonable minimum height so it's visible
    // when the Logs view is large — users reported the terminal appearing
    // as a thin strip at the bottom. This gives the terminal more room.
    terminal_tab.set_vexpand(true);
    terminal_tab.set_hexpand(true);
    term_scroll_tab.set_height_request(480);

        let terminal_split = VteTerminal::new();
        let term_scroll_split = ScrolledWindow::new();
        term_scroll_split.set_policy(gtk4::PolicyType::Automatic, gtk4::PolicyType::Automatic);
        term_scroll_split.set_child(Some(&terminal_split));
        term_scroll_split.set_hexpand(true);
    term_scroll_split.set_vexpand(true);
    terminal_split.set_vexpand(true);
    terminal_split.set_hexpand(true);
    term_scroll_split.set_height_request(480);

        // Start shells: keep idle shells; prompt/launch when tab is opened
        {
            let argv: [&str; 1] = ["/bin/bash"]; // login shell
            for term in [&terminal_tab, &terminal_split] {
                term.spawn_async(
                    PtyFlags::DEFAULT,
                    None::<&str>,
                    &argv,
                    &[],
                    gtk4::glib::SpawnFlags::SEARCH_PATH,
                    || {},
                    -1,
                    None::<&gtk4::gio::Cancellable>,
                    |_| {},
                );
            }
        }

    // Tabs container
        let notebook = Notebook::new();
        notebook.set_hexpand(true);
        notebook.set_vexpand(true);
        let tab_logs_label = gtk4::Label::new(Some("Logs"));
        tab_logs_label.set_tooltip_text(Some(
            "Live tail of /var/log/hardn/*.log with ANSI escape codes stripped",
        ));
        let tab_term_label = gtk4::Label::new(Some("Terminal"));
        tab_term_label.set_tooltip_text(Some(
            "Embedded VTE terminal. Auto-launches sudo hardn-service-manager when selected.",
        ));
        let tab_split_label = gtk4::Label::new(Some("Logs + Terminal"));
        tab_split_label.set_tooltip_text(Some(
            "Logs above, Terminal below — drag the divider to resize",
        ));

        // The Notebook requires owned children; wrap scrolled children in boxes to avoid shared child reuse.
        let logs_box = GtkBox::new(Orientation::Vertical, 0);
        logs_box.set_hexpand(true);
        logs_box.set_vexpand(true);
        logs_box.append(&logs_scroll_tab);
        let term_box = GtkBox::new(Orientation::Vertical, 0);
        term_box.set_hexpand(true);
        term_box.set_vexpand(true);
        term_box.append(&term_scroll_tab);
    let split_paned = Paned::new(Orientation::Vertical);
    split_paned.set_hexpand(true);
    split_paned.set_vexpand(true);
    split_paned.set_start_child(Some(&logs_scroll_split));
    split_paned.set_resize_start_child(true);
    split_paned.set_shrink_start_child(true);
    split_paned.set_end_child(Some(&term_scroll_split));
    split_paned.set_resize_end_child(true);
    split_paned.set_shrink_end_child(true);
    // Default to half the right column height (approx). Users can drag the sash.
    split_paned.set_position(400);

    // -----------------------------------------------------------------
    // Tools tab — inventory of what's installed under tools/. Generated
    // at GUI startup; cheap because it's just a directory walk.
    // -----------------------------------------------------------------
    let tools_text = build_tools_inventory();
    let tools_buffer: TextBuffer = TextBuffer::new(None);
    tools_buffer.set_text(&tools_text);
    let tools_view = TextView::new();
    tools_view.set_editable(false);
    tools_view.set_cursor_visible(false);
    tools_view.set_monospace(true);
    tools_view.set_wrap_mode(gtk4::WrapMode::WordChar);
    tools_view.add_css_class("view");
    tools_view.set_buffer(Some(&tools_buffer));
    let tools_scroll = ScrolledWindow::new();
    tools_scroll.set_policy(gtk4::PolicyType::Automatic, gtk4::PolicyType::Automatic);
    tools_scroll.set_child(Some(&tools_view));
    tools_scroll.set_overlay_scrolling(false);
    tools_scroll.set_hexpand(true);
    tools_scroll.set_vexpand(true);
    let tools_box = GtkBox::new(Orientation::Vertical, 0);
    tools_box.set_hexpand(true);
    tools_box.set_vexpand(true);
    tools_box.append(&tools_scroll);
    let tab_tools_label = gtk4::Label::new(Some("Tools"));
    tab_tools_label.set_tooltip_text(Some(
        "Inventory of HARDN security tools under /usr/share/hardn/tools",
    ));

    // Alerts tab: deduplicated, severity-tagged view of /var/log/hardn/alerts.jsonl
    let alerts_buffer: TextBuffer = TextBuffer::new(None);
    let alerts_text_view = TextView::new();
    alerts_text_view.set_editable(false);
    alerts_text_view.set_cursor_visible(false);
    alerts_text_view.set_monospace(true);
    alerts_text_view.set_wrap_mode(gtk4::WrapMode::WordChar);
    alerts_text_view.add_css_class("view");
    alerts_text_view.set_buffer(Some(&alerts_buffer));
    let alerts_scroll = ScrolledWindow::new();
    alerts_scroll.set_policy(gtk4::PolicyType::Automatic, gtk4::PolicyType::Automatic);
    alerts_scroll.set_child(Some(&alerts_text_view));
    alerts_scroll.set_overlay_scrolling(false);
    alerts_scroll.set_hexpand(true);
    alerts_scroll.set_vexpand(true);
    let alerts_box = GtkBox::new(Orientation::Vertical, 0);
    alerts_box.set_hexpand(true);
    alerts_box.set_vexpand(true);
    alerts_box.append(&alerts_scroll);
    let tab_alerts_label = gtk4::Label::new(Some("Alerts"));
    tab_alerts_label.set_tooltip_text(Some(
        "Deduplicated alerts from /var/log/hardn/alerts.jsonl — sentry drift, service health, LEGION findings",
    ));

    notebook.append_page(&logs_box, Some(&tab_logs_label));
    notebook.append_page(&term_box, Some(&tab_term_label));
    notebook.append_page(&split_paned, Some(&tab_split_label));
    notebook.append_page(&alerts_box, Some(&tab_alerts_label));
    notebook.append_page(&tools_box, Some(&tab_tools_label));
        notebook.set_tab_pos(gtk4::PositionType::Top);

        // Prepare on-demand terminal launch per tab selection (one-time per view)
        let term_prompted_tab = Rc::new(RefCell::new(false));
        let term_prompted_split = Rc::new(RefCell::new(false));
        let terminal_tab_c = terminal_tab.clone();
        let terminal_split_c = terminal_split.clone();
        let tab_flag_c = term_prompted_tab.clone();
        let split_flag_c = term_prompted_split.clone();
        let split_paned_c_for_switch = split_paned.clone();
        notebook.connect_switch_page(move |_nb, _page, idx| {
            // Build the command to clear screen, print prompt, then trigger sudo to launch the manager
            // Use plain `sudo` (no -S) so sudo reads the password from the PTY prompt
            // instead of attempting to read from STDIN; this improves interactivity
            // in embedded terminals. Use full path to hardn-service-manager to avoid PATH issues.
            const LAUNCH_CMD: &[u8] = b"printf \"\\033c\\033]0;HARDN Service Console\\007\\033[38;5;48m>>> Enter password to launch HARDN Service Manager...\\033[0m\\n\"; sudo -k; sudo /usr/bin/hardn-service-manager\n";
            if idx == 1 {
                if !*tab_flag_c.borrow() {
                    terminal_tab_c.feed_child(LAUNCH_CMD);
                    *tab_flag_c.borrow_mut() = true;
                }
            } else if idx == 2 && !*split_flag_c.borrow() {
                terminal_split_c.feed_child(LAUNCH_CMD);
                *split_flag_c.borrow_mut() = true;
                // Make the split between logs and terminal roughly equal when the
                // "Logs + Terminal" tab is selected.
                split_paned_c_for_switch.set_position(400);
            }
        });

        // If current page is already Terminal or Split at startup, fire once
        {
            const LAUNCH_CMD: &[u8] = b"printf \"\\033c\\033]0;HARDN Service Console\\007\\033[38;5;48m>>> Enter password to launch HARDN Service Manager...\\033[0m\\n\"; sudo -k; sudo /usr/bin/hardn-service-manager\n";
            let current = notebook.current_page();
            if current == Some(1) && !*term_prompted_tab.borrow() {
                terminal_tab.feed_child(LAUNCH_CMD);
                *term_prompted_tab.borrow_mut() = true;
            } else if current == Some(2) && !*term_prompted_split.borrow() {
                terminal_split.feed_child(LAUNCH_CMD);
                *term_prompted_split.borrow_mut() = true;
            }
        }

        // Header with logo at top-left and clock at right
        let header_box = GtkBox::new(Orientation::Horizontal, 8);
        header_box.set_margin_top(6);
        header_box.set_margin_start(8);
        header_box.set_margin_end(8);
        header_box.add_css_class("box-header");
        let logo_path_candidates = [
            std::env::var("HARDN_GUI_LOGO").ok(),
            Some("/usr/share/pixmaps/hardn.png".to_string()),
            Some("/usr/share/pixmaps/hardn.jpg".to_string()),
            Some("/usr/share/pixmaps/hardn-gui.jpeg".to_string()),
            Some("/usr/share/hardn/docs/IMG_1233.jpeg".to_string()),
            Some("/usr/share/hardn/hardn-logo.png".to_string()),
            Some("./docs/assets/IMG_1233.jpeg".to_string()),
        ];
        let mut logo_picture: Option<Picture> = None;
        for p in logo_path_candidates.iter().flatten() {
            if std::path::Path::new(p).exists() {
                let pic = Picture::for_filename(p);
                pic.set_width_request(32);
                pic.set_height_request(32);
                pic.add_css_class("logo");
                logo_picture = Some(pic);
                break;
            }
        }
        if let Some(pic) = &logo_picture { header_box.append(pic); }
    let title_label = Label::new(Some("HARDN Monitor"));
        title_label.add_css_class("title-2");
        header_box.append(&title_label);
        // Spacer
        let spacer = GtkBox::new(Orientation::Horizontal, 0);
        spacer.set_hexpand(true);
        header_box.append(&spacer);
        // Clock (updates every second)
        let clock_label = Label::new(None);
        clock_label.add_css_class("clock");
        header_box.append(&clock_label);

        // Status badges row
        let badge_box = GtkBox::new(Orientation::Horizontal, 6);
        badge_box.set_margin_start(8);
        badge_box.set_margin_end(8);
        let badge_hardn = Label::new(Some("HARDN: ?"));
        let badge_api = Label::new(Some("API: ?"));
        let badge_legion = Label::new(Some("LEGION: ?"));
        let badge_monitor = Label::new(Some("MONITOR: ?"));
        for b in [&badge_hardn, &badge_api, &badge_legion, &badge_monitor] {
            b.add_css_class("badge");
            b.add_css_class("badge-unknown");
        }
        badge_box.append(&badge_hardn);
        badge_box.append(&badge_api);
        badge_box.append(&badge_legion);
        badge_box.append(&badge_monitor);
        let badge_alerts = Label::new(Some("ALERTS: 0"));
        badge_alerts.add_css_class("badge");
        badge_alerts.add_css_class("badge-unknown");
        badge_box.append(&badge_alerts);

        // Root-right container: header + badges + tabs (this will be the
        // right-hand pane of the main two-column layout)
        let right_box = GtkBox::new(Orientation::Vertical, 0);
        right_box.set_hexpand(true);
        right_box.set_vexpand(true);
        right_box.append(&header_box);
        right_box.append(&badge_box);
        right_box.append(&notebook);

        // Main two-column paned layout: logs on the left, GUI on the right.
        let main_paned = Paned::new(Orientation::Horizontal);
        main_paned.set_hexpand(true);
        main_paned.set_vexpand(true);
        // Left: a scrolled view containing `main_text_view`
        let main_logs_scroll = ScrolledWindow::new();
        main_logs_scroll.set_policy(gtk4::PolicyType::Automatic, gtk4::PolicyType::Automatic);
        main_logs_scroll.set_child(Some(&main_text_view));
        main_logs_scroll.set_overlay_scrolling(false);
        main_logs_scroll.set_hexpand(true);
        main_logs_scroll.set_vexpand(true);
        main_logs_scroll.set_height_request(640);

        main_paned.set_start_child(Some(&main_logs_scroll));
        main_paned.set_resize_start_child(true);
        main_paned.set_shrink_start_child(true);
        main_paned.set_end_child(Some(&right_box));
        main_paned.set_resize_end_child(true);
        main_paned.set_shrink_end_child(true);
        // TIM - discovered this on fresh Debian 13 install
        // Set initial divider position (pixels). Users can drag
        // the sash to resize the left logs pane as needed; Paned is
        // interactive by default.
        main_paned.set_position(480);

        let window = ApplicationWindow::builder()
            .application(app)
            .title("HARDN Monitor")
            .default_width(1280)
            .default_height(800)
            .child(&main_paned)
            .build();
        window.maximize();

        // Note: VTE already supports Ctrl+Shift+C / Ctrl+Shift+V in many environments.

        // Ring buffer: assume ~200 bytes/event average -> 500_000 events ~100MB; we target ~50MB.
        // Choose 250_000 events cap conservatively (<200MB with safety margin depending on strings).
        let event_buffer = Arc::new(Mutex::new(EventBuffer::new(250_000)));
        let service_health = Arc::new(Mutex::new(ServiceHealth::default()));
        let alerts_state = Arc::new(Mutex::new(AlertsState::default()));
        let alerts_list = Arc::new(Mutex::new(AlertsList::default()));

        // Journald support removed; this GUI reads only HARDN log files.
        let child: Option<std::process::Child> = None;

        // Tail every HARDN log file. We rely on `tail -F` (follow by name) so
        // files that don't exist yet at GUI start (e.g. hardn-tools.log before
        // any tool has run) are picked up the moment they're created.
        let _ = std::fs::create_dir_all("/var/log/hardn");
        let mut file_children: Vec<(String, std::process::Child)> = Vec::new();
        for path in [
            "/var/log/hardn/hardn.log",
            "/var/log/hardn/hardn-tools.log",
            "/var/log/hardn/hardn-monitor.log",
            "/var/log/hardn/legion.log",
            "/var/log/hardn/legion-audit.log",
        ] {
            if let Ok(ch) = spawn_file_tail(path) {
                file_children.push((path.to_string(), ch));
            }
        }

        // Separate tail for structured alerts (JSON lines).
        let alerts_child = spawn_file_tail("/var/log/hardn/alerts.jsonl").ok();
        if let Some(mut ch) = alerts_child
            && let Some(stdout) = ch.stdout.take() {
                let alerts_list_for_tail = alerts_list.clone();
                std::thread::spawn(move || {
                    use std::io::{BufRead, BufReader};
                    let reader = BufReader::new(stdout);
                    for line in reader.lines().map_while(Result::ok) {
                        if let Some(alert) = parse_alert_line(&line)
                            && let Ok(mut list) = alerts_list_for_tail.lock() {
                                list.ingest(alert);
                            }
                    }
                });
            }

        // Shared state for reader
        let rb = event_buffer.clone();
        let health_ref = service_health.clone();
        let alerts_ref = alerts_state.clone();
        let buf_for_ui = buffer.clone();

        // Auto-follow flags for each log view: follow only when at bottom
        let auto_follow_tab = Arc::new(Mutex::new(true));
        let auto_follow_split = Arc::new(Mutex::new(true));
    let auto_follow_main = Arc::new(Mutex::new(true));
        {
            let vadj = logs_scroll_tab.vadjustment();
            let auto_flag = auto_follow_tab.clone();
            vadj.connect_value_changed(move |adj| {
                let value = adj.value();
                let upper = adj.upper();
                let page = adj.page_size();
                let at_bottom = value + page >= upper - 2.0;
                if let Ok(mut f) = auto_flag.lock() { *f = at_bottom; }
            });
        }
        {
            let vadj = logs_scroll_split.vadjustment();
            let auto_flag = auto_follow_split.clone();
            vadj.connect_value_changed(move |adj| {
                let value = adj.value();
                let upper = adj.upper();
                let page = adj.page_size();
                let at_bottom = value + page >= upper - 2.0;
                if let Ok(mut f) = auto_flag.lock() { *f = at_bottom; }
            });
        }
        {
            let vadj = main_logs_scroll.vadjustment();
            let auto_flag = auto_follow_main.clone();
            vadj.connect_value_changed(move |adj| {
                let value = adj.value();
                let upper = adj.upper();
                let page = adj.page_size();
                let at_bottom = value + page >= upper - 2.0;
                if let Ok(mut f) = auto_flag.lock() { *f = at_bottom; }
            });
        }

        // Periodic UI refresh (pull model)
    let rb_c = rb.clone();
    let buf_for_ui_c = buf_for_ui.clone();
    let alerts_ref_c = alerts_ref.clone();
    let alerts_list_c = alerts_list.clone();
    let alerts_buffer_c = alerts_buffer.clone();
    let badge_alerts_c = badge_alerts.clone();
    let health_ref_c = health_ref.clone();
    let badge_hardn_c = badge_hardn.clone();
    let badge_api_c = badge_api.clone();
    let badge_legion_c = badge_legion.clone();
    let badge_monitor_c = badge_monitor.clone();
    let text_view_tab_c = text_view_tab.clone();
    let text_view_split_c = text_view_split.clone();
    let main_text_view_c = main_text_view.clone();
    let auto_follow_tab_c = auto_follow_tab.clone();
    let auto_follow_split_c = auto_follow_split.clone();
    let auto_follow_main_c = auto_follow_main.clone();
    let end_mark_c = end_mark.clone();
        let last_len: Rc<RefCell<usize>> = Rc::new(RefCell::new(0));
        let last_len_c = last_len.clone();
        // Update clock
        let clock_label_c = clock_label.clone();
        timeout_add_local(Duration::from_millis(1000), move || {
            let now = chrono::Local::now();
            clock_label_c.set_label(&now.format("%b %d %H:%M:%S").to_string());
            ControlFlow::Continue
        });

        timeout_add_local(Duration::from_millis(200), move || {
            // Remove header text from logs (no duplication)
            let header = String::new();
            // Update badges from service health
            if let Ok(hs) = health_ref_c.lock() {
                let update_badge = |lbl: &Label, name: &str, state: Option<bool>| {
                    lbl.set_label(&format!("{}: {}", name, match state { Some(true)=>"RUNNING", Some(false)=>"DOWN", None=>"?" }));
                    let ctx = lbl.style_context();
                    ctx.remove_class("badge-ok");
                    ctx.remove_class("badge-down");
                    ctx.remove_class("badge-unknown");
                    match state { Some(true)=>ctx.add_class("badge-ok"), Some(false)=>ctx.add_class("badge-down"), None=>ctx.add_class("badge-unknown") }
                };
                update_badge(&badge_hardn_c, "HARDN", hs.hardn);
                update_badge(&badge_api_c, "API", hs.api);
                update_badge(&badge_legion_c, "LEGION", hs.legion);
                update_badge(&badge_monitor_c, "MONITOR", hs.monitor);
            }
            let alerts = if let Ok(a) = alerts_ref_c.lock() {
                let mut s = String::new();
                if let Some(ref core) = a.core_services { s.push_str(&format!("Core Services: {}\n", core)); }
                if let Some(ref sys) = a.systemd_metrics { s.push_str(&format!("Systemd: {}\n", sys)); }
                if let Some(ref journal) = a.journal_metrics { s.push_str(&format!("Journal: {}\n", journal)); }
                if let Some(ref network) = a.network_metrics { s.push_str(&format!("Networkd: {}\n", network)); }
                if let Some(ref db) = a.database_metrics { s.push_str(&format!("Database: {}\n", db)); }
                if let Some(ref l) = a.legion_summary { s.push_str(&format!("LEGION: {}\n", l)); }
                if !s.is_empty() { s.push('\n'); }
                s
            } else { String::new() };
            // Only update the view when new lines arrived, and avoid redraw while user is paging
            let (len, body) = if let Ok(b) = rb_c.lock() {
                (b.len(), b.to_display_text())
            } else { (0usize, String::new()) };
            let any_following = auto_follow_tab_c.lock().map(|v| *v).unwrap_or(false)
                || auto_follow_split_c.lock().map(|v| *v).unwrap_or(false)
                || auto_follow_main_c.lock().map(|v| *v).unwrap_or(false);
            let should_update = len != *last_len_c.borrow() && any_following;
            if should_update {
                *last_len_c.borrow_mut() = len;
                buf_for_ui_c.set_text(&(header + &alerts + &body));
            }

            // Refresh the Alerts tab + header badge from the dedup'd alerts list
            if let Ok(list) = alerts_list_c.lock() {
                alerts_buffer_c.set_text(&list.render_text());
                let (count, max_sev) = list.count_by_max_severity();
                badge_alerts_c.set_label(&format!("ALERTS: {}", count));
                let ctx = badge_alerts_c.style_context();
                ctx.remove_class("badge-ok");
                ctx.remove_class("badge-down");
                ctx.remove_class("badge-unknown");
                if count == 0 {
                    ctx.add_class("badge-ok");
                } else if max_sev == "error" || max_sev == "critical" {
                    ctx.add_class("badge-down");
                } else {
                    ctx.add_class("badge-unknown");
                }
            }

            // Scroll to end if auto-follow is active for each view
            let end_iter = buf_for_ui_c.end_iter();
            buf_for_ui_c.move_mark(&end_mark_c, &end_iter);
            if auto_follow_tab_c.lock().map(|v| *v).unwrap_or(false) {
                text_view_tab_c.scroll_mark_onscreen(&end_mark_c);
            }
            if auto_follow_split_c.lock().map(|v| *v).unwrap_or(false) {
                text_view_split_c.scroll_mark_onscreen(&end_mark_c);
            }
            if auto_follow_main_c.lock().map(|v| *v).unwrap_or(false) {
                main_text_view_c.scroll_mark_onscreen(&end_mark_c);
            }
            ControlFlow::Continue
        });

        // Background thread to read stdout lines from journalctl and append to ring buffer
        if let Some(mut child) = child {
            if let Some(stdout) = child.stdout.take() {
                let rb_lines = event_buffer.clone();
                std::thread::spawn(move || {
                    use std::io::{BufRead, BufReader};
                    let reader = BufReader::new(stdout);
                    for line in reader.lines().map_while(Result::ok) {
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
                    for line in reader.lines().map_while(Result::ok) {
                        if let Ok(mut g) = rb_lines.lock() {
                            if let Some(h) = parse_service_status(&line)
                                && let Ok(mut hs) = service_health_ref.lock() {
                                    // merge
                                    if h.hardn.is_some() { hs.hardn = h.hardn; }
                                    if h.api.is_some() { hs.api = h.api; }
                                    if h.legion.is_some() { hs.legion = h.legion; }
                                    if h.monitor.is_some() { hs.monitor = h.monitor; }
                                }
                            if let Some(core) = parse_core_services(&line)
                                && let Ok(mut a) = alerts_local.lock() { a.core_services = Some(core); }
                            if let Some(sys) = parse_systemd_metrics(&line)
                                && let Ok(mut a) = alerts_local.lock() { a.systemd_metrics = Some(sys); }
                            if let Some(journal) = parse_journal_metrics(&line)
                                && let Ok(mut a) = alerts_local.lock() { a.journal_metrics = Some(journal); }
                            if let Some(network) = parse_networkd_metrics(&line)
                                && let Ok(mut a) = alerts_local.lock() { a.network_metrics = Some(network); }
                            if let Some(m) = parse_metrics(&line)
                                && let Ok(mut a) = alerts_local.lock() { a.metrics = Some(m); }
                            if let Some(db) = parse_database_metrics(&line)
                                && let Ok(mut a) = alerts_local.lock() { a.database_metrics = Some(db); }
                            if let Some(ls) = parse_legion_summary(&line)
                                && let Ok(mut a) = alerts_local.lock() { a.legion_summary = Some(ls); }
                            // If this tail is from hardn-monitor itself, mark monitor as running
                            if path.ends_with("hardn-monitor.log")
                                && let Ok(mut hs) = service_health_ref.lock() {
                                    hs.monitor = Some(true);
                                }
                            g.push(EventItem { timestamp: now_iso(), source: "file".into(), message: strip_control(&line) });
                        }
                    }
                });
            }
        }

        window.present();

        // Show the welcome wizard on first launch. Skipped when the marker
        // file exists or HARDN_NO_WELCOME=1 is set in the environment (handy
        // for kiosk / CI / autostart scenarios).
        let suppress_env = std::env::var("HARDN_NO_WELCOME")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        let marker = welcome_marker_path();
        if !suppress_env && !marker.exists() {
            show_welcome_wizard(&window);
        }
    });

    app.run();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mk(severity: &str, key: &str, msg: &str) -> Alert {
        Alert {
            ts: "2026-05-24T00:00:00Z".into(),
            severity: severity.into(),
            source: "test".into(),
            message: msg.into(),
            key: key.into(),
        }
    }

    #[test]
    fn alerts_dedupe_by_key_and_update_in_place() {
        let mut list = AlertsList::default();
        list.ingest(mk("warning", "svc-down:hardn.service", "first"));
        list.ingest(mk("warning", "svc-down:hardn.service", "second"));
        list.ingest(mk("error", "svc-restart-failed:legion-daemon", "boom"));
        assert_eq!(list.entries.len(), 2);
        assert_eq!(list.entries[0].1.message, "second");
        assert_eq!(list.entries[1].1.severity, "error");
        assert_eq!(list.total_seen, 3);
    }

    #[test]
    fn alerts_without_key_never_collapse() {
        let mut list = AlertsList::default();
        list.ingest(mk("info", "", "a"));
        list.ingest(mk("info", "", "b"));
        list.ingest(mk("info", "", "c"));
        assert_eq!(list.entries.len(), 3);
    }

    #[test]
    fn max_severity_picks_worst() {
        let mut list = AlertsList::default();
        list.ingest(mk("info", "k1", "x"));
        list.ingest(mk("warning", "k2", "y"));
        list.ingest(mk("error", "k3", "z"));
        let (count, max_sev) = list.count_by_max_severity();
        assert_eq!(count, 3);
        assert_eq!(max_sev, "error");
    }

    #[test]
    fn parse_alert_line_handles_well_formed_json() {
        let line = r#"{"ts":"2026-05-24T00:00:00Z","severity":"warning","source":"hardn-monitor","message":"hardn.service down","key":"svc-down:hardn.service"}"#;
        let a = parse_alert_line(line).expect("parse ok");
        assert_eq!(a.severity, "warning");
        assert_eq!(a.source, "hardn-monitor");
        assert_eq!(a.key, "svc-down:hardn.service");
    }

    #[test]
    fn parse_alert_line_rejects_garbage() {
        assert!(parse_alert_line("not json").is_none());
        assert!(parse_alert_line("{}").is_none()); // missing required ts/message
    }
}
