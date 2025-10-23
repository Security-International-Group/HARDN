use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use gtk4::glib::{timeout_add_local, ControlFlow};
use gtk4::prelude::{ApplicationExt, ApplicationExtManual};
use gtk4::{
    gdk, prelude::*, Application, ApplicationWindow, Box as GtkBox, CssProvider, Label, Notebook,
    Orientation, Paned, Picture, ScrolledWindow, TextBuffer, TextMark, TextView,
    STYLE_PROVIDER_PRIORITY_APPLICATION,
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
                if let Ok(path) = std::env::var("HARDN_GUI_CSS") {
                    data = std::fs::read_to_string(path).ok();
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
        text_view_tab.add_css_class("view");
        text_view_tab.set_buffer(Some(&buffer));

        let text_view_split = TextView::new();
        text_view_split.set_editable(false);
        text_view_split.set_cursor_visible(false);
        text_view_split.set_monospace(true);
        text_view_split.add_css_class("view");
        text_view_split.set_buffer(Some(&buffer));

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

        let terminal_split = VteTerminal::new();
        let term_scroll_split = ScrolledWindow::new();
        term_scroll_split.set_policy(gtk4::PolicyType::Automatic, gtk4::PolicyType::Automatic);
        term_scroll_split.set_child(Some(&terminal_split));
        term_scroll_split.set_hexpand(true);
        term_scroll_split.set_vexpand(true);

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

        // Split view (Logs + Terminal)
        let split = Paned::new(Orientation::Horizontal);
        split.set_hexpand(true);
        split.set_vexpand(true);
        split.set_start_child(Some(&logs_scroll_split));
        split.set_resize_start_child(true);
        split.set_shrink_start_child(true);
        split.set_end_child(Some(&term_scroll_split));
        split.set_resize_end_child(true);
        split.set_shrink_end_child(true);

        // Tabs container
        let notebook = Notebook::new();
        notebook.set_hexpand(true);
        notebook.set_vexpand(true);
        let tab_logs_label = gtk4::Label::new(Some("Logs"));
        let tab_term_label = gtk4::Label::new(Some("Terminal"));
        let tab_split_label = gtk4::Label::new(Some("Logs + Terminal"));

        // The Notebook requires owned children; wrap scrolled children in boxes to avoid shared child reuse.
        let logs_box = GtkBox::new(Orientation::Vertical, 0);
        logs_box.set_hexpand(true);
        logs_box.set_vexpand(true);
        logs_box.append(&logs_scroll_tab);
        let term_box = GtkBox::new(Orientation::Vertical, 0);
        term_box.set_hexpand(true);
        term_box.set_vexpand(true);
        term_box.append(&term_scroll_tab);
        let split_box = GtkBox::new(Orientation::Vertical, 0);
        split_box.set_hexpand(true);
        split_box.set_vexpand(true);
        split_box.append(&split);

        notebook.append_page(&logs_box, Some(&tab_logs_label));
        notebook.append_page(&term_box, Some(&tab_term_label));
        notebook.append_page(&split_box, Some(&tab_split_label));
        notebook.set_tab_pos(gtk4::PositionType::Top);

        // Prepare on-demand terminal launch per tab selection (one-time per view)
        let term_prompted_tab = Rc::new(RefCell::new(false));
        let term_prompted_split = Rc::new(RefCell::new(false));
        let terminal_tab_c = terminal_tab.clone();
        let terminal_split_c = terminal_split.clone();
        let tab_flag_c = term_prompted_tab.clone();
        let split_flag_c = term_prompted_split.clone();
        notebook.connect_switch_page(move |_nb, _page, idx| {
            // Build the command to clear screen, print prompt, then trigger sudo to launch the manager
            const LAUNCH_CMD: &[u8] = b"printf \"\\033c\\033]0;HARDN Service Console\\007\\033[38;5;48m>>> Enter password to launch HARDN Service Manager...\\033[0m\\n\"; sudo -k; sudo -S bash -lc hardn-service-manager\n";
            if idx == 1 {
                if !*tab_flag_c.borrow() {
                    terminal_tab_c.feed_child(LAUNCH_CMD);
                    *tab_flag_c.borrow_mut() = true;
                }
            } else if idx == 2 && !*split_flag_c.borrow() {
                terminal_split_c.feed_child(LAUNCH_CMD);
                *split_flag_c.borrow_mut() = true;
            }
        });

        // If current page is already Terminal or Split at startup, fire once
        {
            const LAUNCH_CMD: &[u8] = b"printf \"\\033c\\033]0;HARDN Service Console\\007\\033[38;5;48m>>> Enter password to launch HARDN Service Manager...\\033[0m\\n\"; sudo -k; sudo -S bash -lc hardn-service-manager\n";
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
        let title_label = Label::new(Some("HARDN Monitor (Read-Only)"));
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

        // Root container: header + badges + tabs
        let root = GtkBox::new(Orientation::Vertical, 0);
        root.set_hexpand(true);
        root.set_vexpand(true);
        root.append(&header_box);
        root.append(&badge_box);
        root.append(&notebook);

        let window = ApplicationWindow::builder()
            .application(app)
            .title("HARDN Monitor (Read-Only)")
            .default_width(980)
            .default_height(640)
            .child(&root)
            .build();
        window.maximize();

        // Note: VTE already supports Ctrl+Shift+C / Ctrl+Shift+V in many environments.

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

        // Auto-follow flags for each log view: follow only when at bottom
        let auto_follow_tab = Arc::new(Mutex::new(true));
        let auto_follow_split = Arc::new(Mutex::new(true));
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

        // Periodic UI refresh (pull model)
        let rb_c = rb.clone();
        let buf_for_ui_c = buf_for_ui.clone();
        let alerts_ref_c = alerts_ref.clone();
        let health_ref_c = health_ref.clone();
        let badge_hardn_c = badge_hardn.clone();
        let badge_api_c = badge_api.clone();
        let badge_legion_c = badge_legion.clone();
        let badge_monitor_c = badge_monitor.clone();
        let text_view_tab_c = text_view_tab.clone();
        let text_view_split_c = text_view_split.clone();
        let auto_follow_tab_c = auto_follow_tab.clone();
        let auto_follow_split_c = auto_follow_split.clone();
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
            let should_update = len != *last_len_c.borrow() && (auto_follow_tab_c.lock().map(|v| *v).unwrap_or(false) || auto_follow_split_c.lock().map(|v| *v).unwrap_or(false));
            if should_update {
                *last_len_c.borrow_mut() = len;
                buf_for_ui_c.set_text(&(header + &alerts + &body));
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
                            if let Some(h) = parse_service_status(&line) {
                                if let Ok(mut hs) = service_health_ref.lock() {
                                    // merge
                                    if h.hardn.is_some() { hs.hardn = h.hardn; }
                                    if h.api.is_some() { hs.api = h.api; }
                                    if h.legion.is_some() { hs.legion = h.legion; }
                                    if h.monitor.is_some() { hs.monitor = h.monitor; }
                                }
                            }
                            if let Some(core) = parse_core_services(&line) {
                                if let Ok(mut a) = alerts_local.lock() { a.core_services = Some(core); }
                            }
                            if let Some(sys) = parse_systemd_metrics(&line) {
                                if let Ok(mut a) = alerts_local.lock() { a.systemd_metrics = Some(sys); }
                            }
                            if let Some(journal) = parse_journal_metrics(&line) {
                                if let Ok(mut a) = alerts_local.lock() { a.journal_metrics = Some(journal); }
                            }
                            if let Some(network) = parse_networkd_metrics(&line) {
                                if let Ok(mut a) = alerts_local.lock() { a.network_metrics = Some(network); }
                            }
                            if let Some(m) = parse_metrics(&line) {
                                if let Ok(mut a) = alerts_local.lock() { a.metrics = Some(m); }
                            }
                            if let Some(db) = parse_database_metrics(&line) {
                                if let Ok(mut a) = alerts_local.lock() { a.database_metrics = Some(db); }
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
