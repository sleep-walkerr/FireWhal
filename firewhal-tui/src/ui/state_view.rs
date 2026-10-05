use ratatui::{prelude::*, widgets::*};
use crate::ui::app::App;
use firewhal_core::{Action, ConfigHealthView, Protocol, Rule, StateSnapshot};
use std::net::IpAddr;
use std::time::Instant;

// ---------------------------------------------------------------------------
// State introspection screen (#182)
//
// Answers "what does the firewall believe right now?": a point-in-time dump
// of the in-kernel maps (from the kernel loader), the per-interface TC
// attach state (the #181 enforcement signal), and the daemon's C1 config
// health. Pull-based: a StateRequest goes out when the screen opens / on
// `r`; optional 1 Hz auto-refresh while open. No background polling.
//
// Semantics notes (documented on the screen):
//   - CONNECTION_MAP is an LRU: the view is a window of what is tracked
//     *now*, not history.
//   - A dump is point-in-time; entries can change mid-dump.
// ---------------------------------------------------------------------------

#[derive(Debug, Default)]
pub struct StateViewState {
    pub snapshot: Option<StateSnapshot>,
    pub health: Option<ConfigHealthView>,
    pub list_state: ListState,
    pub row_count: usize,
    pub last_refresh: Option<Instant>,
    pub auto_refresh: bool,
    pub request_pending: bool,
    pub last_error: Option<String>,
}

impl StateViewState {
    pub fn apply_snapshot(&mut self, snapshot: StateSnapshot) {
        self.snapshot = Some(snapshot);
        self.last_refresh = Some(Instant::now());
        self.request_pending = false;
    }

    pub fn apply_health(&mut self, view: ConfigHealthView) {
        self.health = Some(view);
    }

    pub fn mark_refresh_sent(&mut self) {
        self.request_pending = true;
    }
}

/// (action, protocol, src_ip, src_port, dst_ip, dst_port) — the fields the
/// kernel key actually stores, used for the kernel-vs-on-disk divergence
/// check (app_id/description live only in the config file, so they are
/// ignored by design).
fn rule_sig(r: &Rule) -> (Action, Option<Protocol>, Option<IpAddr>, Option<u16>, Option<IpAddr>, Option<u16>) {
    (r.action, r.protocol, r.source_ip, r.source_port, r.dest_ip, r.dest_port)
}

type RuleSig = (Action, Option<Protocol>, Option<IpAddr>, Option<u16>, Option<IpAddr>, Option<u16>);

fn compare_rules(kernel_rules: &[Rule], ondisk_rules: &[Rule]) -> String {
    if ondisk_rules.is_empty() && kernel_rules.is_empty() {
        return "in sync (no rules)".to_string();
    }
    let mut a: Vec<_> = kernel_rules.iter().map(rule_sig).collect();
    let mut b: Vec<_> = ondisk_rules.iter().map(rule_sig).collect();
    a.sort_by(|x, y| cmp_sigs(x, y));
    b.sort_by(|x, y| cmp_sigs(x, y));
    if a == b {
        return format!("in sync ({} rules)", kernel_rules.len());
    }
    let mut ka = a.clone();
    let mut kb = b.clone();
    ka.retain(|x| !b.contains(x));
    kb.retain(|x| !a.contains(x));
    format!(
        "DIVERGED — kernel-only: {}, config-only: {}",
        ka.len(),
        kb.len()
    )
}

fn cmp_sigs(x: &RuleSig, y: &RuleSig) -> std::cmp::Ordering {
    let key = |t: &RuleSig| {
        (
            match t.0 { Action::Allow => 0, Action::Deny => 1 },
            t.1.as_ref().map(|p| format!("{p:?}")).unwrap_or_default(),
            t.2.map(|ip| ip.to_string()).unwrap_or_default(),
            t.3.unwrap_or(0),
            t.4.map(|ip| ip.to_string()).unwrap_or_default(),
            t.5.unwrap_or(0),
        )
    };
    key(x).cmp(&key(y))
}

fn conn_line(src: &str, dst: &str, proto: &str, tgid: u32, process: &str) -> Line<'static> {
    Line::from(vec![
        Span::raw(format!("  {src} -> {dst}  {proto}  ")),
        Span::styled(format!("tgid {tgid}"), Style::default().fg(Color::Yellow)),
        Span::raw(format!("  {process}")),
    ])
}

fn header_line(title: &str, count: Option<usize>) -> Line<'static> {
    let count_span = match count {
        Some(n) => vec![Span::styled(format!(" ({n})"), Style::default().fg(Color::DarkGray))],
        None => vec![],
    };
    Line::from(vec![
        Span::styled(format!("== {title} =="), Style::default().fg(Color::LightCyan).bold()),
    ].into_iter().chain(count_span).collect::<Vec<_>>())
}

fn build_items(app: &App) -> Vec<ListItem<'static>> {
    let mut items: Vec<ListItem> = Vec::new();

    let add_header = |items: &mut Vec<ListItem>, title: &str, count: Option<usize>| {
        items.push(ListItem::new(header_line(title, count)));
    };
    let add = |items: &mut Vec<ListItem>, line: Line<'static>| items.push(ListItem::new(line));

    let snapshot = match &app.state_view.snapshot {
        Some(s) => s,
        None => {
            add(&mut items, Line::from(vec![
                Span::styled("No state received yet — waiting for the kernel's snapshot", Style::default().fg(Color::Yellow)),
            ]));
            if let Some(err) = &app.state_view.last_error {
                add(&mut items, Line::styled(err.clone(), Style::default().fg(Color::Red)));
            }
            return items;
        }
    };

    // --- Stateful ---
    add_header(&mut items, "STATEFUL  (CONNECTION_MAP — LRU window, not history)", Some(snapshot.connections.len()));
    for c in &snapshot.connections {
        add(&mut items, conn_line(&c.src, &c.dst, &c.protocol, c.tgid, &c.process));
    }

    add_header(&mut items, "PENDING  (app-gate verdict in flight)", Some(snapshot.pending_connections.len()));
    for c in &snapshot.pending_connections {
        add(&mut items, conn_line(&c.src, &c.dst, &c.protocol, c.tgid, &c.process));
    }

    add_header(&mut items, "TRUSTED CONNECTIONS  (per-connection app-gate trust)", Some(snapshot.trusted_connections.len()));
    for c in &snapshot.trusted_connections {
        add(&mut items, conn_line(&c.src, &c.dst, &c.protocol, c.tgid, &c.process));
    }

    add_header(&mut items, "HANDSHAKE  (in-flight TCP SYNs — the #180 invariant)", Some(snapshot.handshake_allowed.len()));
    for c in &snapshot.handshake_allowed {
        add(&mut items, conn_line(&c.src, &c.dst, &c.protocol, c.tgid, &c.process));
    }

    // --- Trust tables ---
    add_header(&mut items, "TRUST: PIDs  (allowlisted or explicitly denied)", Some(snapshot.trusted_pids.len()));
    for p in &snapshot.trusted_pids {
        let action_style = match p.action {
            Action::Allow => Style::default().fg(Color::Green),
            Action::Deny => Style::default().fg(Color::Red),
        };
        add(&mut items, Line::from(vec![
            Span::raw(format!("  tgid {}", p.tgid)),
            Span::styled(format!("{:7}", match p.action { Action::Allow => "Allow", Action::Deny => "Deny" }), action_style),
            Span::raw(format!("  {}", p.process)),
        ]));
    }

    add_header(&mut items, "TRUST: LISTENING PORTS  (pending vs trusted)", Some(snapshot.pending_listeners.len() + snapshot.trusted_listeners.len()));
    for l in &snapshot.pending_listeners {
        add(&mut items, Line::from(vec![
            Span::styled(format!("  :{}  PENDING", l.port), Style::default().fg(Color::Yellow)),
            Span::raw(format!("  tgid {}  {}", l.tgid, l.process)),
        ]));
    }
    for l in &snapshot.trusted_listeners {
        add(&mut items, Line::from(vec![
            Span::styled(format!("  :{}  TRUSTED", l.port), Style::default().fg(Color::Green)),
            Span::raw(format!("  tgid {}  {}", l.tgid, l.process)),
        ]));
    }

    add(&mut items, Line::from(vec![
        Span::raw(format!(
            "  cookie trust: {} trusted-cookies, {} socket-cookie entries (counts only)",
            snapshot.trusted_cookies_count, snapshot.socket_cookie_trust_count
        ))
    ]));

    // --- Rules + divergence ---
    add_header(&mut items, "RULES  (as loaded in the kernel)", Some(snapshot.outgoing_rules.len() + snapshot.incoming_rules.len()));
    for r in &snapshot.outgoing_rules {
        add(&mut items, rule_line(r, "out"));
    }
    for r in &snapshot.incoming_rules {
        add(&mut items, rule_line(r, "in"));
    }
    let div_out = compare_rules(&snapshot.outgoing_rules, &app.rules);
    let div_in = compare_rules(&snapshot.incoming_rules, &app.incoming_rules);
    for (dir, div) in [("outgoing", &div_out), ("incoming", &div_in)] {
        let style = if div.starts_with("DIVERGED") {
            Style::default().fg(Color::Red).bold()
        } else {
            Style::default().fg(Color::DarkGray)
        };
        add(&mut items, Line::from(vec![
            Span::styled(format!("  {dir}: "), Style::default().fg(Color::LightCyan)),
            Span::styled(div.clone(), style),
        ]));
    }

    // --- Defaults + permissive ---
    add_header(&mut items, "DEFAULTS  (no-rule-match verdict — the allow/deny-all toggle)", None);
    let verdict_line = |label: &str, v: &firewhal_core::DefaultVerdict| {
        let (text, style) = match v {
            firewhal_core::DefaultVerdict::Allow => ("Allow", Style::default().fg(Color::Red).bold()),
            firewhal_core::DefaultVerdict::Block => ("Block (fail-closed)", Style::default().fg(Color::Green)),
        };
        Line::from(vec![
            Span::raw(format!("  {label}: ")),
            Span::styled(text.to_string(), style),
        ])
    };
    add(&mut items, verdict_line("incoming", &snapshot.default_incoming));
    add(&mut items, verdict_line("outgoing", &snapshot.default_outgoing));
    let perm = if snapshot.permissive_mode { "ON (permissive)" } else { "off" };
    let perm_style = if snapshot.permissive_mode { Style::default().fg(Color::Yellow).bold() } else { Style::default() };
    add(&mut items, Line::from(vec![Span::styled(format!("  permissive mode: {perm}"), perm_style)]));

    // --- Attach state (loader-owned; the #181 enforcement signal) ---
    add_header(&mut items, "ATTACH  (loader-owned TCX attach state)", Some(snapshot.attach.len()));
    if snapshot.attach.is_empty() {
        add(&mut items, Line::styled(
            "  NOT ATTACHED — no interfaces carry the enforcement TC programs (nothing is being enforced)",
            Style::default().fg(Color::Red).bold(),
        ));
    }
    for a in &snapshot.attach {
        add(&mut items, Line::from(vec![
            Span::styled(format!("  {}", a.interface), Style::default().fg(Color::Green).bold()),
            Span::raw(format!("  ingress {}  egress {}", a.ingress, a.egress)),
        ]));
    }

    // --- Config health (daemon / C1) ---
    add_header(&mut items, "CONFIG HEALTH  (daemon / C1)", None);
    match &app.state_view.health {
        Some(h) => {
            for f in &h.files {
                let (icon, style) = if f.healthy {
                    ("OK", Style::default().fg(Color::Green))
                } else {
                    ("DEGRADED", Style::default().fg(Color::Red).bold())
                };
                let note = if f.note.is_empty() { " ".to_string() } else { f.note.clone() };
                add(&mut items, Line::from(vec![
                    Span::styled(format!("  {icon}  {}", f.file), style),
                    Span::raw(format!("  {note}")),
                ]));
            }
        }
        None => add(&mut items, Line::styled("  not received yet", Style::default().fg(Color::Yellow))),
    }

    items
}

fn rule_line(r: &Rule, dir: &str) -> Line<'static> {
    let action_style = match r.action {
        Action::Allow => Style::default().fg(Color::Green),
        Action::Deny => Style::default().fg(Color::Red),
    };
    let proto = r.protocol.map_or("any".to_string(), |p| format!("{p:?}"));
    let sip = r.source_ip.map_or("any".to_string(), |ip| ip.to_string());
    let sp = r.source_port.map_or("any".to_string(), |p| p.to_string());
    let dip = r.dest_ip.map_or("any".to_string(), |ip| ip.to_string());
    let dp = r.dest_port.map_or("any".to_string(), |p| p.to_string());
    Line::from(vec![
        Span::styled(format!("{:5} ", dir), Style::default().fg(Color::DarkGray)),
        Span::styled(format!("{:6}", match r.action { Action::Allow => "Allow", Action::Deny => "Deny" }), action_style),
        Span::raw(format!("  {proto:5}  {sip}:{sp} -> {dip}:{dp}")),
    ])
}

fn refresh_line(app: &App) -> Line<'static> {
    let when = app
        .state_view
        .last_refresh
        .map(|t| format!("last refresh {:.1}s ago", t.elapsed().as_secs_f64()))
        .unwrap_or_else(|| "no data yet".to_string());
    let auto = if app.state_view.auto_refresh { "auto-refresh: ON" } else { "auto-refresh: off" };
    Line::from(vec![
        Span::styled("r: refresh   a: auto-refresh(1 Hz)   ", Style::default().fg(Color::Rgb(255, 165, 0))),
        Span::styled(when, Style::default().fg(Color::DarkGray)),
        Span::raw("  "),
        Span::styled(auto, Style::default().fg(Color::DarkGray)),
    ])
}

pub fn handle_key_event(key_code: crossterm::event::KeyCode, app: &mut App) {
    match key_code {
        crossterm::event::KeyCode::Char('r') => {
            app.state_view.mark_refresh_sent();
            app.request_state();
        }
        crossterm::event::KeyCode::Char('a') => {
            app.state_view.auto_refresh = !app.state_view.auto_refresh;
        }
        crossterm::event::KeyCode::Down => {
            if app.state_view.row_count > 0 {
                let sel = app.state_view.list_state.selected().unwrap_or(0);
                let next = if sel >= app.state_view.row_count.saturating_sub(1) { 0 } else { sel + 1 };
                app.state_view.list_state.select(Some(next));
            }
        }
        crossterm::event::KeyCode::Up => {
            if app.state_view.row_count > 0 {
                let sel = app.state_view.list_state.selected().unwrap_or(0);
                let prev = if sel == 0 { app.state_view.row_count.saturating_sub(1) } else { sel - 1 };
                app.state_view.list_state.select(Some(prev));
            }
        }
        _ => {}
    }
}

pub fn render(f: &mut Frame, app: &mut App, area: Rect) {
    let auto_tag = if app.state_view.auto_refresh { " [auto 1 Hz]" } else { "" };
    let block = Block::default()
        .title(format!("Firewall State (in-kernel){auto_tag}"))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan));
    let inner = block.inner(area);
    f.render_widget(block, area);

    // Content (scrollable) + a 1-line footer with the key hints.
    let chunks = Layout::vertical([Constraint::Min(0), Constraint::Length(1)]).split(inner);
    let items = build_items(app);
    app.state_view.row_count = items.len();
    let list = List::new(items).highlight_style(Style::default().fg(Color::LightCyan));
    f.render_stateful_widget(list, chunks[0], &mut app.state_view.list_state);
    f.render_widget(Paragraph::new(refresh_line(app)), chunks[1]);
}
