//! Interactive TUI mode (ratatui + crossterm).
use crate::types::*;
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Clear, Paragraph, Row, Table, TableState, Tabs, Wrap},
    Frame, Terminal,
};
use std::{
    io,
    time::{Duration, Instant},
};

// ─── colours ─────────────────────────────────────────────────────────────────

fn proto_col(p: &Protocol) -> Color {
    match p {
        Protocol::Tcp => Color::Cyan,
        Protocol::Tcp6 => Color::LightCyan,
        Protocol::Udp => Color::Yellow,
        Protocol::Udp6 => Color::LightYellow,
    }
}

fn state_col(s: &str) -> Color {
    match s {
        "ESTABLISHED" => Color::Green,
        "LISTEN" => Color::Blue,
        "TIME_WAIT" => Color::Yellow,
        "CLOSE_WAIT" | "CLOSE" | "FIN_WAIT1" | "FIN_WAIT2" => Color::Red,
        "SYN_SENT" | "SYN_RECV" => Color::Magenta,
        _ => Color::Gray,
    }
}

fn rate_col(bps: u64) -> Color {
    if bps > 10 * 1024 * 1024 {
        Color::Red
    } else if bps > 1024 * 1024 {
        Color::Yellow
    } else if bps > 0 {
        Color::Green
    } else {
        Color::DarkGray
    }
}

fn fmt_bytes(b: u64) -> String {
    if b == 0 {
        return "0 B".into();
    }
    if b < 1024 {
        format!("{b} B")
    } else if b < 1_048_576 {
        format!("{:.1} KB", b as f64 / 1024.0)
    } else if b < 1_073_741_824 {
        format!("{:.1} MB", b as f64 / 1_048_576.0)
    } else {
        format!("{:.2} GB", b as f64 / 1_073_741_824.0)
    }
}

fn fmt_rate(b: u64) -> String {
    if b == 0 {
        return "-".into();
    }
    if b < 1024 {
        format!("{b} B/s")
    } else if b < 1_048_576 {
        format!("{:.1} KB/s", b as f64 / 1024.0)
    } else {
        format!("{:.1} MB/s", b as f64 / 1_048_576.0)
    }
}

// ─── sort ────────────────────────────────────────────────────────────────────

#[derive(PartialEq, Clone)]
enum Sort {
    Pid,
    Proto,
    LocalAddr,
    RemoteAddr,
    State,
    Process,
    RxQ,
    TxQ,
}

impl Sort {
    fn next(&self) -> Self {
        match self {
            Sort::Pid => Sort::Proto,
            Sort::Proto => Sort::Process,
            Sort::Process => Sort::LocalAddr,
            Sort::LocalAddr => Sort::RemoteAddr,
            Sort::RemoteAddr => Sort::State,
            Sort::State => Sort::RxQ,
            Sort::RxQ => Sort::TxQ,
            Sort::TxQ => Sort::Pid,
        }
    }
    fn label(&self) -> &'static str {
        match self {
            Sort::Pid => "PID",
            Sort::Proto => "PROTO",
            Sort::Process => "PROCESS",
            Sort::LocalAddr => "LOCAL",
            Sort::RemoteAddr => "REMOTE",
            Sort::State => "STATE",
            Sort::RxQ => "RX_Q",
            Sort::TxQ => "TX_Q",
        }
    }
}

// ─── app ─────────────────────────────────────────────────────────────────────

struct App {
    snap: Snapshot,
    filtered: Vec<Connection>,
    tab: usize,
    conn_state: TableState,
    proc_state: TableState,
    filter: String,
    filter_mode: bool,
    sort: Sort,
    sort_asc: bool,
    show_help: bool,
    detail: Option<Connection>,
    paused: bool,
    last_tick: Instant,
    interval: Duration,
    pid_filter: Option<u32>,
    port_filter: Option<u16>,
    listen_only: bool,
}

impl App {
    fn new(
        interval: Duration,
        pid_filter: Option<u32>,
        port_filter: Option<u16>,
        listen_only: bool,
    ) -> Self {
        App {
            snap: Snapshot::empty(),
            filtered: vec![],
            tab: 0,
            conn_state: TableState::default(),
            proc_state: TableState::default(),
            filter: String::new(),
            filter_mode: false,
            sort: Sort::State,
            sort_asc: true,
            show_help: false,
            detail: None,
            paused: false,
            last_tick: Instant::now(),
            interval,
            pid_filter,
            port_filter,
            listen_only,
        }
    }

    fn apply(&mut self) {
        let f = self.filter.to_lowercase();
        self.filtered = self
            .snap
            .connections
            .iter()
            .filter(|c| {
                if self.listen_only && c.state != "LISTEN" {
                    return false;
                }
                if let Some(pid) = self.pid_filter {
                    if c.pid != Some(pid) {
                        return false;
                    }
                }
                if let Some(port) = self.port_filter {
                    if c.local_port != port && c.remote_port != port {
                        return false;
                    }
                }
                if !f.is_empty() {
                    let hay = format!(
                        "{} {} {} {} {} {} {} {}",
                        c.local_addr,
                        c.local_port,
                        c.remote_addr,
                        c.remote_port,
                        c.state,
                        c.protocol.as_str(),
                        c.pid.map(|p| p.to_string()).unwrap_or_default(),
                        c.process_name.as_deref().unwrap_or("")
                    )
                    .to_lowercase();
                    if !hay.contains(&f) {
                        return false;
                    }
                }
                true
            })
            .cloned()
            .collect();

        let asc = self.sort_asc;
        self.filtered.sort_by(|a, b| {
            let o = match &self.sort {
                Sort::Pid => a.pid.cmp(&b.pid),
                Sort::Proto => a.protocol.as_str().cmp(b.protocol.as_str()),
                Sort::Process => a
                    .process_name
                    .as_deref()
                    .unwrap_or("")
                    .cmp(b.process_name.as_deref().unwrap_or("")),
                Sort::LocalAddr => a
                    .local_addr
                    .cmp(&b.local_addr)
                    .then(a.local_port.cmp(&b.local_port)),
                Sort::RemoteAddr => a
                    .remote_addr
                    .cmp(&b.remote_addr)
                    .then(a.remote_port.cmp(&b.remote_port)),
                Sort::State => a.state.cmp(&b.state),
                Sort::RxQ => a.rx_queue.cmp(&b.rx_queue),
                Sort::TxQ => a.tx_queue.cmp(&b.tx_queue),
            };
            if asc {
                o
            } else {
                o.reverse()
            }
        });
    }

    fn next(&mut self) {
        let n = if self.tab == 0 {
            self.filtered.len()
        } else {
            self.snap.procs.len()
        };
        if n == 0 {
            return;
        }
        let i = self
            .conn_state
            .selected()
            .map(|i| (i + 1).min(n - 1))
            .unwrap_or(0);
        self.conn_state.select(Some(i));
    }
    fn prev(&mut self) {
        let i = self
            .conn_state
            .selected()
            .map(|i| i.saturating_sub(1))
            .unwrap_or(0);
        self.conn_state.select(Some(i));
    }
    fn pgdn(&mut self) {
        let n = self.filtered.len();
        if n == 0 {
            return;
        }
        let i = self.conn_state.selected().unwrap_or(0);
        self.conn_state.select(Some((i + 20).min(n - 1)));
    }
    fn pgup(&mut self) {
        let i = self.conn_state.selected().unwrap_or(0);
        self.conn_state.select(Some(i.saturating_sub(20)));
    }
}

// ─── draw ────────────────────────────────────────────────────────────────────

fn draw(f: &mut Frame, app: &mut App) {
    let area = f.area();
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Min(0),
            Constraint::Length(1),
        ])
        .split(area);

    // tabs
    let tabs = Tabs::new(vec![" Connections ", " Interfaces ", " Processes "])
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(Span::styled(
                    " ◉ netmon v0.2 ",
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                ))
                .border_style(Style::default().fg(Color::DarkGray)),
        )
        .select(app.tab)
        .style(Style::default().fg(Color::Gray))
        .highlight_style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        );
    f.render_widget(tabs, chunks[0]);

    // stats bar
    let s = &app.snap.stats;
    let pause_span = if app.paused {
        Span::styled(
            " ⏸ PAUSED ",
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        )
    } else {
        Span::styled(" ▶ LIVE ", Style::default().fg(Color::Green))
    };
    let filt_span = if !app.filter.is_empty() {
        Span::styled(
            format!(" 🔍\"{}\" ", app.filter),
            Style::default().fg(Color::Magenta),
        )
    } else {
        Span::raw("")
    };

    let bar = Line::from(vec![
        pause_span,
        Span::raw(" │ "),
        Span::styled(
            format!(" Total:{} ", s.total),
            Style::default().fg(Color::White),
        ),
        Span::raw("│ "),
        Span::styled(
            format!(" ESTAB:{} ", s.established),
            Style::default().fg(Color::Green),
        ),
        Span::raw("│ "),
        Span::styled(
            format!(" LISTEN:{} ", s.listen),
            Style::default().fg(Color::Blue),
        ),
        Span::raw("│ "),
        Span::styled(
            format!(" T_WAIT:{} ", s.time_wait),
            Style::default().fg(Color::Yellow),
        ),
        Span::raw("│ "),
        Span::styled(
            format!(" C_WAIT:{} ", s.close_wait),
            Style::default().fg(Color::Red),
        ),
        Span::raw("│ "),
        Span::styled(
            format!(" UDP:{} ", s.udp),
            Style::default().fg(Color::Yellow),
        ),
        Span::raw("│ "),
        Span::styled(
            format!(" RX:{} ", fmt_rate(s.total_rx_bps)),
            Style::default().fg(rate_col(s.total_rx_bps)),
        ),
        Span::raw("│ "),
        Span::styled(
            format!(" TX:{} ", fmt_rate(s.total_tx_bps)),
            Style::default().fg(rate_col(s.total_tx_bps)),
        ),
        Span::raw("│ "),
        filt_span,
        Span::styled(
            format!(" {} ", app.snap.timestamp.format("%H:%M:%S")),
            Style::default().fg(Color::DarkGray),
        ),
    ]);
    f.render_widget(
        Paragraph::new(bar).block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::DarkGray)),
        ),
        chunks[1],
    );

    match app.tab {
        0 => draw_conns(f, app, chunks[2]),
        1 => draw_ifaces(f, app, chunks[2]),
        2 => draw_procs(f, app, chunks[2]),
        _ => {}
    }

    let status = format!(
        " [q]quit [Tab]tab [↑↓jk]nav [PgUp/Dn]page [g/G]top/bot [Enter]detail [/]filter [Esc]clear [s]sort:{} [S]dir [p]pause [r]refresh [?]help ",
        app.sort.label()
    );
    f.render_widget(
        Paragraph::new(status).style(Style::default().fg(Color::DarkGray)),
        chunks[3],
    );

    if app.show_help {
        draw_help(f, area);
    }
    if let Some(c) = app.detail.clone() {
        draw_detail(f, area, &c);
    }
}

fn hdr(label: &str, active: bool, asc: bool) -> Cell<'static> {
    let text = if active {
        format!("{} {}", label, if asc { "↑" } else { "↓" })
    } else {
        label.to_string()
    };
    Cell::from(text).style(
        Style::default()
            .fg(if active { Color::Yellow } else { Color::Cyan })
            .add_modifier(Modifier::BOLD),
    )
}

fn trunc(s: &str, n: usize) -> String {
    if s.len() <= n {
        s.to_string()
    } else {
        format!("{}…", &s[..n.saturating_sub(1)])
    }
}

fn draw_conns(f: &mut Frame, app: &mut App, area: Rect) {
    let (main, farea) = if app.filter_mode {
        let c = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(3), Constraint::Min(0)])
            .split(area);
        (c[1], Some(c[0]))
    } else {
        (area, None)
    };

    if let Some(fa) = farea {
        f.render_widget(
            Paragraph::new(format!(" Filter: {}|", app.filter))
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .title(" Search ")
                        .border_style(Style::default().fg(Color::Magenta)),
                )
                .style(Style::default().fg(Color::White)),
            fa,
        );
    }

    let is = |s: Sort| s == app.sort;
    let asc = app.sort_asc;

    let header = Row::new(vec![
        hdr("PID", is(Sort::Pid), asc),
        hdr("PROCESS", is(Sort::Process), asc),
        hdr("CMDLINE", false, asc),
        hdr("PROTO", is(Sort::Proto), asc),
        hdr("LOCAL ADDR", is(Sort::LocalAddr), asc),
        hdr("L.PORT", false, asc),
        hdr("REMOTE ADDR", is(Sort::RemoteAddr), asc),
        hdr("R.PORT", false, asc),
        hdr("STATE", is(Sort::State), asc),
        hdr("USER", false, asc),
        hdr("UID", false, asc),
        hdr("INODE", false, asc),
        hdr("RX_Q", is(Sort::RxQ), asc),
        hdr("TX_Q", is(Sort::TxQ), asc),
    ])
    .style(Style::default().bg(Color::DarkGray))
    .height(1);

    let rows: Vec<Row> = app
        .filtered
        .iter()
        .map(|c| {
            let remote = if c.remote_addr == "0.0.0.0" || c.remote_addr == "::" {
                "*".into()
            } else {
                c.remote_addr.clone()
            };
            let rport = if c.remote_port == 0 {
                "*".into()
            } else {
                c.remote_port.to_string()
            };
            let cmd = trunc(c.cmdline.as_deref().unwrap_or("-"), 34);
            Row::new(vec![
                Cell::from(c.pid.map(|p| p.to_string()).unwrap_or("-".into()))
                    .style(Style::default().fg(Color::Magenta)),
                Cell::from(trunc(c.process_name.as_deref().unwrap_or("-"), 14)).style(
                    Style::default()
                        .fg(Color::White)
                        .add_modifier(Modifier::BOLD),
                ),
                Cell::from(cmd).style(Style::default().fg(Color::Gray)),
                Cell::from(c.protocol.as_str()).style(Style::default().fg(proto_col(&c.protocol))),
                Cell::from(c.local_addr.clone()).style(Style::default().fg(Color::Gray)),
                Cell::from(c.local_port.to_string()).style(Style::default().fg(Color::LightBlue)),
                Cell::from(remote).style(Style::default().fg(Color::Gray)),
                Cell::from(rport).style(Style::default().fg(Color::LightBlue)),
                Cell::from(c.state.clone()).style(Style::default().fg(state_col(&c.state))),
                Cell::from(trunc(c.username.as_deref().unwrap_or("-"), 9))
                    .style(Style::default().fg(Color::DarkGray)),
                Cell::from(c.uid.to_string()).style(Style::default().fg(Color::DarkGray)),
                Cell::from(c.inode.to_string()).style(Style::default().fg(Color::DarkGray)),
                Cell::from(c.rx_queue.to_string()).style(Style::default().fg(if c.rx_queue > 0 {
                    Color::Yellow
                } else {
                    Color::DarkGray
                })),
                Cell::from(c.tx_queue.to_string()).style(Style::default().fg(if c.tx_queue > 0 {
                    Color::Yellow
                } else {
                    Color::DarkGray
                })),
            ])
        })
        .collect();

    let t = Table::new(
        rows,
        [
            Constraint::Length(7),  // PID
            Constraint::Length(14), // PROCESS
            Constraint::Length(35), // CMDLINE
            Constraint::Length(6),  // PROTO
            Constraint::Length(16), // LOCAL ADDR
            Constraint::Length(6),  // L.PORT
            Constraint::Length(16), // REMOTE ADDR
            Constraint::Length(6),  // R.PORT
            Constraint::Length(12), // STATE
            Constraint::Length(9),  // USER
            Constraint::Length(6),  // UID
            Constraint::Length(9),  // INODE
            Constraint::Length(5),  // RXQ
            Constraint::Length(5),  // TXQ
        ],
    )
    .header(header)
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(format!(
                " Connections ({}) — sort: {} {} ",
                app.filtered.len(),
                app.sort.label(),
                if app.sort_asc { "↑" } else { "↓" }
            ))
            .border_style(Style::default().fg(Color::DarkGray)),
    )
    .highlight_style(
        Style::default()
            .bg(Color::DarkGray)
            .add_modifier(Modifier::BOLD),
    )
    .highlight_symbol(">> ");

    f.render_stateful_widget(t, main, &mut app.conn_state);
}

fn draw_ifaces(f: &mut Frame, app: &App, area: Rect) {
    let header = Row::new(
        [
            "INTERFACE",
            "RX TOTAL",
            "TX TOTAL",
            "RX PKTS",
            "TX PKTS",
            "RX/s",
            "TX/s",
            "RX ERR",
            "TX ERR",
        ]
        .iter()
        .map(|h| {
            Cell::from(*h).style(
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            )
        }),
    )
    .style(Style::default().bg(Color::DarkGray))
    .height(1);

    let rows: Vec<Row> = app
        .snap
        .ifaces
        .iter()
        .map(|i| {
            Row::new(vec![
                Cell::from(i.name.clone()).style(
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                ),
                Cell::from(fmt_bytes(i.rx_bytes)).style(Style::default().fg(Color::Gray)),
                Cell::from(fmt_bytes(i.tx_bytes)).style(Style::default().fg(Color::Gray)),
                Cell::from(i.rx_packets.to_string()).style(Style::default().fg(Color::DarkGray)),
                Cell::from(i.tx_packets.to_string()).style(Style::default().fg(Color::DarkGray)),
                Cell::from(fmt_rate(i.rx_rate_bps))
                    .style(Style::default().fg(rate_col(i.rx_rate_bps))),
                Cell::from(fmt_rate(i.tx_rate_bps))
                    .style(Style::default().fg(rate_col(i.tx_rate_bps))),
                Cell::from(i.rx_errors.to_string()).style(Style::default().fg(
                    if i.rx_errors > 0 {
                        Color::Red
                    } else {
                        Color::DarkGray
                    },
                )),
                Cell::from(i.tx_errors.to_string()).style(Style::default().fg(
                    if i.tx_errors > 0 {
                        Color::Red
                    } else {
                        Color::DarkGray
                    },
                )),
            ])
        })
        .collect();

    let mut st = TableState::default();
    let t = Table::new(
        rows,
        [
            Constraint::Length(14),
            Constraint::Length(12),
            Constraint::Length(12),
            Constraint::Length(10),
            Constraint::Length(10),
            Constraint::Length(12),
            Constraint::Length(12),
            Constraint::Length(8),
            Constraint::Length(8),
        ],
    )
    .header(header)
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Network Interfaces ")
            .border_style(Style::default().fg(Color::DarkGray)),
    );
    f.render_stateful_widget(t, area, &mut st);
}

fn draw_procs(f: &mut Frame, app: &mut App, area: Rect) {
    let header = Row::new(
        [
            "PID",
            "PROCESS",
            "CONNS",
            "CPU%",
            "MEM",
            "RX/s",
            "TX/s",
            "RX TOTAL",
            "TX TOTAL",
            "FULL CMDLINE",
        ]
        .iter()
        .map(|h| {
            Cell::from(*h).style(
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            )
        }),
    )
    .style(Style::default().bg(Color::DarkGray))
    .height(1);

    let rows: Vec<Row> = app
        .snap
        .procs
        .iter()
        .map(|p| {
            let cc = if p.cpu_pct > 50.0 {
                Color::Red
            } else if p.cpu_pct > 10.0 {
                Color::Yellow
            } else {
                Color::Green
            };
            Row::new(vec![
                Cell::from(p.pid.to_string()).style(Style::default().fg(Color::Magenta)),
                Cell::from(trunc(&p.name, 16)).style(
                    Style::default()
                        .fg(Color::White)
                        .add_modifier(Modifier::BOLD),
                ),
                Cell::from(p.connections.to_string()).style(
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                ),
                Cell::from(format!("{:.1}%", p.cpu_pct)).style(Style::default().fg(cc)),
                Cell::from(fmt_bytes(p.mem_bytes)).style(Style::default().fg(Color::Gray)),
                Cell::from(fmt_rate(p.rx_bytes_delta))
                    .style(Style::default().fg(rate_col(p.rx_bytes_delta))),
                Cell::from(fmt_rate(p.tx_bytes_delta))
                    .style(Style::default().fg(rate_col(p.tx_bytes_delta))),
                Cell::from(fmt_bytes(p.rx_bytes)).style(Style::default().fg(Color::DarkGray)),
                Cell::from(fmt_bytes(p.tx_bytes)).style(Style::default().fg(Color::DarkGray)),
                Cell::from(trunc(&p.cmdline, 60)).style(Style::default().fg(Color::Gray)),
            ])
        })
        .collect();

    let t = Table::new(
        rows,
        [
            Constraint::Length(7),
            Constraint::Length(16),
            Constraint::Length(6),
            Constraint::Length(7),
            Constraint::Length(9),
            Constraint::Length(11),
            Constraint::Length(11),
            Constraint::Length(10),
            Constraint::Length(10),
            Constraint::Min(30),
        ],
    )
    .header(header)
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Processes with Network Activity (sorted by traffic) ")
            .border_style(Style::default().fg(Color::DarkGray)),
    )
    .highlight_style(
        Style::default()
            .bg(Color::DarkGray)
            .add_modifier(Modifier::BOLD),
    )
    .highlight_symbol(">> ");
    f.render_stateful_widget(t, area, &mut app.proc_state);
}

fn draw_help(f: &mut Frame, area: Rect) {
    let popup = centered(56, 70, area);
    f.render_widget(Clear, popup);
    let text = vec![
        Line::from(Span::styled(
            "  Keyboard Shortcuts",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(Span::styled(
            "  Navigation",
            Style::default().fg(Color::Yellow),
        )),
        Line::from("  ↑↓ / j k          Move up/down"),
        Line::from("  PgUp / PgDn        Page navigation"),
        Line::from("  g / G              First / Last row"),
        Line::from("  Tab / BackTab      Switch tabs"),
        Line::from(""),
        Line::from(Span::styled(
            "  Filter & Sort",
            Style::default().fg(Color::Yellow),
        )),
        Line::from("  /                  Open filter bar"),
        Line::from("  Esc                Clear filter / close"),
        Line::from("  s                  Cycle sort column"),
        Line::from("  S                  Toggle sort direction"),
        Line::from(""),
        Line::from(Span::styled(
            "  Actions",
            Style::default().fg(Color::Yellow),
        )),
        Line::from("  Enter              Full connection detail"),
        Line::from("  p                  Pause / resume"),
        Line::from("  r                  Force refresh"),
        Line::from("  ?                  This help"),
        Line::from("  q / Ctrl-c         Quit"),
        Line::from(""),
        Line::from(Span::styled(
            "  Press ? or Esc to close",
            Style::default().fg(Color::DarkGray),
        )),
    ];
    f.render_widget(
        Paragraph::new(text)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(" Help ")
                    .border_style(Style::default().fg(Color::Cyan)),
            )
            .wrap(Wrap { trim: false }),
        popup,
    );
}

fn kv<'a>(label: &'a str, value: &str, vc: Color) -> Line<'a> {
    Line::from(vec![
        Span::styled(
            format!("{:<18}", label),
            Style::default().fg(Color::DarkGray),
        ),
        Span::styled(
            value.to_string(),
            Style::default().fg(vc).add_modifier(Modifier::BOLD),
        ),
    ])
}

fn draw_detail(f: &mut Frame, area: Rect, c: &Connection) {
    let popup = centered(66, 64, area);
    f.render_widget(Clear, popup);
    let text = vec![
        Line::from(Span::styled(
            "  Connection Detail",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        kv("  Protocol", c.protocol.as_str(), proto_col(&c.protocol)),
        kv("  State", &c.state, state_col(&c.state)),
        Line::from(""),
        kv("  Local IP", &c.local_addr, Color::White),
        kv("  Local Port", &c.local_port.to_string(), Color::LightBlue),
        kv("  Remote IP", &c.remote_addr, Color::White),
        kv(
            "  Remote Port",
            &c.remote_port.to_string(),
            Color::LightBlue,
        ),
        Line::from(""),
        kv(
            "  PID",
            &c.pid.map(|p| p.to_string()).unwrap_or("N/A".into()),
            Color::Magenta,
        ),
        kv(
            "  Process",
            c.process_name.as_deref().unwrap_or("N/A"),
            Color::Green,
        ),
        kv(
            "  User",
            c.username.as_deref().unwrap_or("N/A"),
            Color::Cyan,
        ),
        kv("  UID", &c.uid.to_string(), Color::DarkGray),
        Line::from(""),
        kv(
            "  Full cmdline",
            c.cmdline.as_deref().unwrap_or("N/A"),
            Color::Gray,
        ),
        kv(
            "  Exe path",
            c.exe_path.as_deref().unwrap_or("N/A"),
            Color::Gray,
        ),
        kv(
            "  Working dir",
            c.working_dir.as_deref().unwrap_or("N/A"),
            Color::Gray,
        ),
        Line::from(""),
        kv("  Inode", &c.inode.to_string(), Color::DarkGray),
        kv(
            "  RX queue",
            &c.rx_queue.to_string(),
            if c.rx_queue > 0 {
                Color::Yellow
            } else {
                Color::DarkGray
            },
        ),
        kv(
            "  TX queue",
            &c.tx_queue.to_string(),
            if c.tx_queue > 0 {
                Color::Yellow
            } else {
                Color::DarkGray
            },
        ),
        Line::from(""),
        Line::from(Span::styled(
            "  Esc / Enter to close",
            Style::default().fg(Color::DarkGray),
        )),
    ];
    f.render_widget(
        Paragraph::new(text)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(" Detail ")
                    .border_style(Style::default().fg(Color::Yellow)),
            )
            .wrap(Wrap { trim: false }),
        popup,
    );
}

fn centered(px: u16, py: u16, r: Rect) -> Rect {
    let v = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - py) / 2),
            Constraint::Percentage(py),
            Constraint::Percentage((100 - py) / 2),
        ])
        .split(r);
    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - px) / 2),
            Constraint::Percentage(px),
            Constraint::Percentage((100 - px) / 2),
        ])
        .split(v[1])[1]
}

// ─── entry point ─────────────────────────────────────────────────────────────

pub fn run(
    interval_ms: u64,
    pid_filter: Option<u32>,
    port_filter: Option<u16>,
    listen_only: bool,
    use_ebpf: bool,
) -> anyhow::Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let mut terminal = Terminal::new(CrosstermBackend::new(stdout))?;

    let mut collector = {
        let mut c = crate::collector::Collector::new();
        if use_ebpf {
            c.ebpf_table = crate::ebpf_loader::start(std::time::Duration::from_millis(interval_ms));
        }
        c
    };
    let mut app = App::new(
        Duration::from_millis(interval_ms),
        pid_filter,
        port_filter,
        listen_only,
    );
    app.snap = collector.collect();
    app.apply();

    loop {
        terminal.draw(|f| draw(f, &mut app))?;

        let timeout = app
            .interval
            .checked_sub(app.last_tick.elapsed())
            .unwrap_or(Duration::from_millis(10));

        if event::poll(timeout)? {
            if let Event::Key(key) = event::read()? {
                if app.filter_mode {
                    match key.code {
                        KeyCode::Esc => {
                            app.filter_mode = false;
                        }
                        KeyCode::Enter => {
                            app.filter_mode = false;
                            app.apply();
                        }
                        KeyCode::Backspace => {
                            app.filter.pop();
                            app.apply();
                        }
                        KeyCode::Char(c) => {
                            app.filter.push(c);
                            app.apply();
                        }
                        _ => {}
                    }
                    continue;
                }
                if app.show_help {
                    match key.code {
                        KeyCode::Esc | KeyCode::Char('?') | KeyCode::Char('q') => {
                            app.show_help = false
                        }
                        _ => {}
                    }
                    continue;
                }
                if app.detail.is_some() {
                    match key.code {
                        KeyCode::Esc | KeyCode::Enter | KeyCode::Char('q') => app.detail = None,
                        _ => {}
                    }
                    continue;
                }
                match key.code {
                    KeyCode::Char('q') => break,
                    KeyCode::Char('c') if key.modifiers == KeyModifiers::CONTROL => break,
                    KeyCode::Tab => {
                        app.tab = (app.tab + 1) % 3;
                        app.conn_state.select(Some(0));
                    }
                    KeyCode::BackTab => {
                        app.tab = app.tab.checked_sub(1).unwrap_or(2);
                    }
                    KeyCode::Down | KeyCode::Char('j') => app.next(),
                    KeyCode::Up | KeyCode::Char('k') => app.prev(),
                    KeyCode::PageDown => app.pgdn(),
                    KeyCode::PageUp => app.pgup(),
                    KeyCode::Char('g') => app.conn_state.select(Some(0)),
                    KeyCode::Char('G') => {
                        let n = app.filtered.len();
                        if n > 0 {
                            app.conn_state.select(Some(n - 1));
                        }
                    }
                    KeyCode::Enter => {
                        if app.tab == 0 {
                            if let Some(i) = app.conn_state.selected() {
                                app.detail = app.filtered.get(i).cloned();
                            }
                        }
                    }
                    KeyCode::Char('/') => app.filter_mode = true,
                    KeyCode::Esc => {
                        app.filter.clear();
                        app.apply();
                    }
                    KeyCode::Char('s') => {
                        app.sort = app.sort.next();
                        app.apply();
                    }
                    KeyCode::Char('S') => {
                        app.sort_asc = !app.sort_asc;
                        app.apply();
                    }
                    KeyCode::Char('p') => app.paused = !app.paused,
                    KeyCode::Char('r') => {
                        app.paused = false;
                        app.snap = collector.collect();
                        app.apply();
                        app.last_tick = Instant::now();
                    }
                    KeyCode::Char('?') => app.show_help = !app.show_help,
                    _ => {}
                }
            }
        }

        if !app.paused && app.last_tick.elapsed() >= app.interval {
            app.snap = collector.collect();
            app.apply();
            app.last_tick = Instant::now();
        }
    }

    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;
    Ok(())
}
