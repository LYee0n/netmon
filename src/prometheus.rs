//! Prometheus exporter: serves /metrics, /health, / over plain HTTP.
//! No external HTTP crate — uses std::net::TcpListener directly.
use crate::collector::Collector;
use crate::types::*;
use anyhow::Result;
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

// ─── Metric rendering ─────────────────────────────────────────────────────────

fn esc(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

fn epoch_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

pub fn render(snap: &Snapshot, scrapes: u64) -> String {
    let mut o = String::with_capacity(16384);

    macro_rules! meta {
        ($name:expr, $help:literal, $typ:literal) => {
            o.push_str(&format!(
                "# HELP {} {}\n# TYPE {} {}\n",
                $name, $help, $name, $typ
            ));
        };
    }
    macro_rules! g {
        ($name:expr, $val:expr) => {
            o.push_str(&format!("{} {}\n", $name, $val));
        };
        ($name:expr, $labels:expr, $val:expr) => {
            o.push_str(&format!("{}{{{}}} {}\n", $name, $labels, $val));
        };
    }
    macro_rules! c {
        ($name:expr, $val:expr) => {
            o.push_str(&format!("{}_total {}\n", $name, $val));
        };
        ($name:expr, $labels:expr, $val:expr) => {
            o.push_str(&format!("{}_total{{{}}} {}\n", $name, $labels, $val));
        };
    }

    // ── scrape meta ──
    meta!(
        "netmon_scrape_count",
        "Total Prometheus scrapes served",
        "counter"
    );
    c!("netmon_scrape_count", scrapes);
    meta!(
        "netmon_collection_timestamp_ms",
        "Unix ms of last data collection",
        "gauge"
    );
    g!("netmon_collection_timestamp_ms", epoch_ms());

    // ── global connection stats ──
    let s = &snap.stats;
    meta!(
        "netmon_connections_total",
        "Total socket entries in /proc/net",
        "gauge"
    );
    g!("netmon_connections_total", s.total);
    meta!(
        "netmon_connections_established",
        "Sockets in ESTABLISHED state",
        "gauge"
    );
    g!("netmon_connections_established", s.established);
    meta!(
        "netmon_connections_listen",
        "Sockets in LISTEN state",
        "gauge"
    );
    g!("netmon_connections_listen", s.listen);
    meta!(
        "netmon_connections_time_wait",
        "Sockets in TIME_WAIT state",
        "gauge"
    );
    g!("netmon_connections_time_wait", s.time_wait);
    meta!(
        "netmon_connections_close_wait",
        "Sockets in CLOSE_WAIT state",
        "gauge"
    );
    g!("netmon_connections_close_wait", s.close_wait);
    meta!(
        "netmon_connections_syn_sent",
        "Sockets in SYN_SENT state",
        "gauge"
    );
    g!("netmon_connections_syn_sent", s.syn_sent);
    meta!("netmon_connections_udp", "UDP socket entries", "gauge");
    g!("netmon_connections_udp", s.udp);

    // ── aggregate throughput ──
    meta!(
        "netmon_rx_bytes_per_second",
        "Aggregate inbound throughput across all interfaces",
        "gauge"
    );
    g!("netmon_rx_bytes_per_second", s.total_rx_bps);
    meta!(
        "netmon_tx_bytes_per_second",
        "Aggregate outbound throughput across all interfaces",
        "gauge"
    );
    g!("netmon_tx_bytes_per_second", s.total_tx_bps);

    // ── per-state connection count ──
    let mut state_map: HashMap<String, usize> = HashMap::new();
    for c in &snap.connections {
        *state_map.entry(c.state.clone()).or_insert(0) += 1;
    }
    meta!(
        "netmon_connection_state_count",
        "Number of connections by state",
        "gauge"
    );
    let mut states: Vec<_> = state_map.iter().collect();
    states.sort_by_key(|(k, _)| k.as_str());
    for (state, count) in states {
        g!(
            "netmon_connection_state_count",
            format!("state=\"{}\"", esc(state)),
            count
        );
    }

    // ── per-protocol count ──
    let mut proto_map: HashMap<String, usize> = HashMap::new();
    for c in &snap.connections {
        *proto_map
            .entry(c.protocol.as_str().to_string())
            .or_insert(0) += 1;
    }
    meta!(
        "netmon_connection_protocol_count",
        "Number of connections by protocol",
        "gauge"
    );
    for (proto, count) in &proto_map {
        g!(
            "netmon_connection_protocol_count",
            format!("protocol=\"{}\"", esc(proto)),
            count
        );
    }

    // ── listen ports ──
    meta!(
        "netmon_listen_port",
        "1 if the port is being listened on, labelled by protocol+port",
        "gauge"
    );
    let mut ports: Vec<_> = snap
        .connections
        .iter()
        .filter(|c| c.state == "LISTEN")
        .map(|c| (c.protocol.as_str(), c.local_port))
        .collect::<std::collections::HashSet<_>>()
        .into_iter()
        .collect();
    ports.sort();
    for (proto, port) in ports {
        g!(
            "netmon_listen_port",
            format!("protocol=\"{proto}\",port=\"{port}\""),
            1
        );
    }

    // ── interface metrics ──
    macro_rules! iface_counter {
        ($name:literal, $help:literal, $field:ident) => {
            meta!(
                concat!("netmon_interface_", $name, "_total"),
                $help,
                "counter"
            );
            for i in &snap.ifaces {
                c!(
                    concat!("netmon_interface_", $name),
                    format!("interface=\"{}\"", esc(&i.name)),
                    i.$field
                );
            }
        };
    }
    macro_rules! iface_gauge {
        ($name:literal, $help:literal, $field:ident) => {
            meta!(concat!("netmon_interface_", $name), $help, "gauge");
            for i in &snap.ifaces {
                g!(
                    concat!("netmon_interface_", $name),
                    format!("interface=\"{}\"", esc(&i.name)),
                    i.$field
                );
            }
        };
    }
    iface_counter!("rx_bytes", "Cumulative bytes received", rx_bytes);
    iface_counter!("tx_bytes", "Cumulative bytes transmitted", tx_bytes);
    iface_counter!("rx_packets", "Cumulative packets received", rx_packets);
    iface_counter!("tx_packets", "Cumulative packets sent", tx_packets);
    iface_counter!("rx_errors", "Cumulative receive errors", rx_errors);
    iface_counter!("tx_errors", "Cumulative transmit errors", tx_errors);
    iface_gauge!(
        "rx_bytes_per_second",
        "Current RX rate bytes/s",
        rx_rate_bps
    );
    iface_gauge!(
        "tx_bytes_per_second",
        "Current TX rate bytes/s",
        tx_rate_bps
    );

    // ── per-process metrics ──
    macro_rules! proc_metric {
        ($name:literal, $help:literal, $typ:literal, $field:ident) => {
            meta!(concat!("netmon_process_", $name), $help, $typ);
            for p in &snap.procs {
                let lbl = format!("pid=\"{}\",process=\"{}\"", p.pid, esc(&p.name));
                if $typ == "counter" {
                    c!(concat!("netmon_process_", $name), lbl, p.$field);
                } else {
                    g!(concat!("netmon_process_", $name), lbl, p.$field);
                }
            }
        };
    }
    proc_metric!(
        "connection_count",
        "Active connections per process",
        "gauge",
        connections
    );
    proc_metric!(
        "rx_bytes",
        "Cumulative read bytes (from /proc/PID/io)",
        "counter",
        rx_bytes
    );
    proc_metric!("tx_bytes", "Cumulative written bytes", "counter", tx_bytes);
    proc_metric!(
        "rx_bytes_per_second",
        "Current RX rate per process",
        "gauge",
        rx_bytes_delta
    );
    proc_metric!(
        "tx_bytes_per_second",
        "Current TX rate per process",
        "gauge",
        tx_bytes_delta
    );
    proc_metric!("memory_bytes", "RSS memory bytes", "gauge", mem_bytes);

    // cpu is f32 so handle separately
    meta!(
        "netmon_process_cpu_percent",
        "CPU usage % per process",
        "gauge"
    );
    for p in &snap.procs {
        let lbl = format!("pid=\"{}\",process=\"{}\"", p.pid, esc(&p.name));
        o.push_str(&format!(
            "netmon_process_cpu_percent{{{}}} {:.2}\n",
            lbl, p.cpu_pct
        ));
    }

    // ── per-process full cmdline as info metric ──
    meta!(
        "netmon_process_info",
        "Process info (cmdline label), value always 1",
        "gauge"
    );
    for p in &snap.procs {
        let cmd = p.cmdline.replace('"', "\\\"");
        let lbl = format!(
            "pid=\"{}\",process=\"{}\",cmdline=\"{}\"",
            p.pid,
            esc(&p.name),
            esc(&cmd)
        );
        g!("netmon_process_info", lbl, 1);
    }

    // ── per-process per-IP connection metrics ──
    // Build a map: (pid, process_name, remote_ip, local_ip, protocol) → connection_count
    // This lets Prometheus/Grafana correlate IP addresses with owning PIDs.
    {
        // (pid, name, local_ip, remote_ip, proto) → count
        let mut ip_pid_map: HashMap<(u32, String, String, String, String), usize> =
            HashMap::new();
        for c in &snap.connections {
            if let (Some(pid), Some(pname)) = (c.pid, c.process_name.as_deref()) {
                let key = (
                    pid,
                    pname.to_string(),
                    c.local_addr.clone(),
                    c.remote_addr.clone(),
                    c.protocol.as_str().to_string(),
                );
                *ip_pid_map.entry(key).or_insert(0) += 1;
            }
        }

        meta!(
            "netmon_process_ip_connections",
            "Active connections per process labelled with local and remote IP addresses",
            "gauge"
        );
        let mut entries: Vec<_> = ip_pid_map.iter().collect();
        entries.sort_by_key(|((pid, name, lip, rip, proto), _)| {
            (pid, name.as_str(), lip.as_str(), rip.as_str(), proto.as_str())
        });
        for ((pid, name, local_ip, remote_ip, proto), count) in entries {
            let lbl = format!(
                "pid=\"{}\",process=\"{}\",local_ip=\"{}\",remote_ip=\"{}\",protocol=\"{}\"",
                pid,
                esc(name),
                esc(local_ip),
                esc(remote_ip),
                esc(proto),
            );
            g!("netmon_process_ip_connections", lbl, count);
        }

        // rx_queue and tx_queue totals per (pid, remote_ip)
        let mut queue_map: HashMap<(u32, String, String, String), (u64, u64)> = HashMap::new();
        for c in &snap.connections {
            if let (Some(pid), Some(pname)) = (c.pid, c.process_name.as_deref()) {
                let key = (
                    pid,
                    pname.to_string(),
                    c.remote_addr.clone(),
                    c.protocol.as_str().to_string(),
                );
                let entry = queue_map.entry(key).or_insert((0, 0));
                entry.0 += c.rx_queue;
                entry.1 += c.tx_queue;
            }
        }

        meta!(
            "netmon_process_ip_rx_queue_bytes",
            "Kernel receive queue bytes per process and remote IP",
            "gauge"
        );
        meta!(
            "netmon_process_ip_tx_queue_bytes",
            "Kernel transmit queue bytes per process and remote IP",
            "gauge"
        );
        let mut qentries: Vec<_> = queue_map.iter().collect();
        qentries.sort_by_key(|((pid, name, rip, proto), _)| {
            (pid, name.as_str(), rip.as_str(), proto.as_str())
        });
        for ((pid, name, remote_ip, proto), (rx_q, tx_q)) in qentries {
            let lbl = format!(
                "pid=\"{}\",process=\"{}\",remote_ip=\"{}\",protocol=\"{}\"",
                pid,
                esc(name),
                esc(remote_ip),
                esc(proto),
            );
            g!("netmon_process_ip_rx_queue_bytes", &lbl, rx_q);
            g!("netmon_process_ip_tx_queue_bytes", &lbl, tx_q);
        }
    }

    o
}

// ─── HTTP helpers ─────────────────────────────────────────────────────────────

fn respond(stream: &mut TcpStream, status: &str, ct: &str, body: &str) {
    let _ = stream.write_all(
        format!("HTTP/1.1 {status}\r\nContent-Type: {ct}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()).as_bytes());
}

fn read_path(stream: &mut TcpStream) -> Option<String> {
    let mut buf = [0u8; 4096];
    let n = stream.read(&mut buf).ok()?;
    let req = std::str::from_utf8(&buf[..n]).ok()?;
    let line = req.lines().next()?;
    let path = line.split_whitespace().nth(1)?;
    Some(path.to_string())
}

fn index_html(port: u16) -> String {
    format!(
        r#"<!DOCTYPE html><html><head><title>netmon exporter</title>
<style>body{{font-family:monospace;background:#0d1117;color:#c9d1d9;padding:2em}}
h1{{color:#58a6ff}}a{{color:#58a6ff}}pre{{background:#161b22;padding:1em;border-radius:6px}}
table{{border-collapse:collapse;width:100%}}td,th{{border:1px solid #30363d;padding:.4em .8em;text-align:left}}
th{{background:#161b22;color:#58a6ff}}</style></head><body>
<h1>◉ netmon Prometheus Exporter</h1>
<p>Real-time network traffic metrics for Prometheus/Grafana.</p>
<table><tr><th>Endpoint</th><th>Description</th></tr>
<tr><td><a href="/metrics">/metrics</a></td><td>Prometheus text format metrics</td></tr>
<tr><td><a href="/health">/health</a></td><td>Health check — 200 OK</td></tr>
<tr><td><a href="/">/</a></td><td>This page</td></tr></table>
<h2>prometheus.yml example</h2>
<pre>scrape_configs:
  - job_name: netmon
    scrape_interval: 10s
    static_configs:
      - targets: ['localhost:{port}']</pre>
<h2>Metric families</h2>
<table><tr><th>Metric</th><th>Description</th></tr>
<tr><td>netmon_connections_*</td><td>Global connection state counts</td></tr>
<tr><td>netmon_connection_state_count</td><td>Per-state breakdown</td></tr>
<tr><td>netmon_connection_protocol_count</td><td>Per-protocol breakdown</td></tr>
<tr><td>netmon_listen_port</td><td>Active listen ports</td></tr>
<tr><td>netmon_rx/tx_bytes_per_second</td><td>Aggregate throughput</td></tr>
<tr><td>netmon_interface_*</td><td>Per-interface rx/tx bytes, packets, errors, rates</td></tr>
<tr><td>netmon_process_connection_count</td><td>Connections per process</td></tr>
<tr><td>netmon_process_rx/tx_bytes_total</td><td>Cumulative process I/O</td></tr>
<tr><td>netmon_process_rx/tx_bytes_per_second</td><td>Per-process traffic rate</td></tr>
<tr><td>netmon_process_cpu_percent</td><td>Process CPU usage</td></tr>
<tr><td>netmon_process_memory_bytes</td><td>Process RSS memory</td></tr>
<tr><td>netmon_process_info</td><td>Process info with full cmdline label</td></tr>\n<tr><td>netmon_process_ip_connections</td><td>Connection count per PID labelled with local_ip, remote_ip, protocol</td></tr>\n<tr><td>netmon_process_ip_rx/tx_queue_bytes</td><td>Kernel socket queue depth per PID and remote IP</td></tr>
</table>
</body></html>"#
    )
}

// ─── entry point ─────────────────────────────────────────────────────────────

pub fn run(port: u16, interval_ms: u64, running: Arc<AtomicBool>) -> Result<()> {
    let addr = format!("0.0.0.0:{port}");
    let listener = TcpListener::bind(&addr)?;
    listener.set_nonblocking(true)?;

    eprintln!("netmon prometheus-mode");
    eprintln!("  HTTP:     http://{addr}");
    eprintln!("  Metrics:  http://localhost:{port}/metrics");
    eprintln!("  Health:   http://localhost:{port}/health");
    eprintln!(
        "  Interval: {:.1}s  │  Ctrl-C to stop",
        interval_ms as f64 / 1000.0
    );

    // Shared snapshot, updated by collector thread
    let snap = Arc::new(Mutex::new(Snapshot::empty()));
    let scrapes = Arc::new(AtomicU64::new(0));

    // ── collector thread ──
    {
        let snap_w = snap.clone();
        let run_c = running.clone();
        let interval = Duration::from_millis(interval_ms);
        std::thread::spawn(move || {
            let mut collector = Collector::new();
            while run_c.load(Ordering::SeqCst) {
                let s = collector.collect();
                eprintln!(
                    "  [collect] conns:{} procs:{} rx:{:.1}KB/s tx:{:.1}KB/s",
                    s.stats.total,
                    s.procs.len(),
                    s.stats.total_rx_bps as f64 / 1024.0,
                    s.stats.total_tx_bps as f64 / 1024.0
                );
                if let Ok(mut g) = snap_w.lock() {
                    *g = s;
                }
                let ticks = (interval.as_millis() / 100).max(1) as u64;
                for _ in 0..ticks {
                    if !run_c.load(Ordering::SeqCst) {
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(100));
                }
            }
        });
    }

    // ── accept loop ──
    while running.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((mut stream, addr)) => {
                let snap_r = snap.clone();
                let sc = scrapes.clone();
                let port_c = port;
                std::thread::spawn(move || {
                    let _ = stream.set_read_timeout(Some(Duration::from_secs(3)));
                    let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));
                    match read_path(&mut stream).as_deref() {
                        Some(p) if p == "/metrics" || p.starts_with("/metrics?") => {
                            let n = sc.fetch_add(1, Ordering::Relaxed) + 1;
                            let body = snap_r.lock().map(|g| render(&g, n)).unwrap_or_default();
                            eprintln!("  [scrape #{n}] {addr} → /metrics ({} bytes)", body.len());
                            respond(
                                &mut stream,
                                "200 OK",
                                "text/plain; version=0.0.4; charset=utf-8",
                                &body,
                            );
                        }
                        Some("/health") => {
                            respond(
                                &mut stream,
                                "200 OK",
                                "application/json",
                                "{\"status\":\"ok\"}",
                            );
                        }
                        Some("/") | Some("/index.html") => {
                            respond(
                                &mut stream,
                                "200 OK",
                                "text/html; charset=utf-8",
                                &index_html(port_c),
                            );
                        }
                        _ => {
                            respond(
                                &mut stream,
                                "404 Not Found",
                                "text/plain",
                                "404 Not Found\nEndpoints: /metrics  /health  /\n",
                            );
                        }
                    }
                });
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(e) => eprintln!("accept: {e}"),
        }
    }
    eprintln!("netmon: prometheus exporter stopped.");
    Ok(())
}

/// Same as `run` but accepts a pre-configured `Collector` (e.g. with eBPF table attached).
/// Also emits additional `netmon_process_ebpf_*` metrics when eBPF is active.
pub fn run_with_collector(
    port: u16,
    interval_ms: u64,
    running: Arc<AtomicBool>,
    collector: Collector,
) -> Result<()> {
    let addr = format!("0.0.0.0:{port}");
    let listener = TcpListener::bind(&addr)?;
    listener.set_nonblocking(true)?;

    let ebpf_active = collector.ebpf_table.is_some();
    eprintln!("netmon prometheus-mode");
    eprintln!("  HTTP:     http://{addr}");
    eprintln!("  Metrics:  http://localhost:{port}/metrics");
    eprintln!("  Health:   http://localhost:{port}/health");
    eprintln!("  eBPF:     {}", if ebpf_active { "active" } else { "off" });
    eprintln!(
        "  Interval: {:.1}s  │  Ctrl-C to stop",
        interval_ms as f64 / 1000.0
    );

    let snap = Arc::new(Mutex::new(Snapshot::empty()));
    let scrapes = Arc::new(AtomicU64::new(0));

    // ── collector thread ──
    {
        let snap_w = snap.clone();
        let run_c = running.clone();
        let interval = Duration::from_millis(interval_ms);
        let mut col = collector;
        std::thread::spawn(move || {
            while run_c.load(Ordering::SeqCst) {
                let s = col.collect();
                eprintln!(
                    "  [collect] conns:{} procs:{} rx:{:.1}KB/s tx:{:.1}KB/s ebpf_entries:{}",
                    s.stats.total,
                    s.procs.len(),
                    s.stats.total_rx_bps as f64 / 1024.0,
                    s.stats.total_tx_bps as f64 / 1024.0,
                    s.procs.iter().map(|p| p.ip_traffic.len()).sum::<usize>(),
                );
                if let Ok(mut g) = snap_w.lock() {
                    *g = s;
                }
                let ticks = (interval.as_millis() / 100).max(1) as u64;
                for _ in 0..ticks {
                    if !run_c.load(Ordering::SeqCst) {
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(100));
                }
            }
        });
    }

    // ── accept loop ──
    while running.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((mut stream, addr)) => {
                let snap_r = snap.clone();
                let sc = scrapes.clone();
                let port_c = port;
                std::thread::spawn(move || {
                    let _ = stream.set_read_timeout(Some(Duration::from_secs(3)));
                    let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));
                    match read_path(&mut stream).as_deref() {
                        Some(p) if p == "/metrics" || p.starts_with("/metrics?") => {
                            let n = sc.fetch_add(1, Ordering::Relaxed) + 1;
                            let snap_guard = snap_r.lock().unwrap();
                            let mut body = render(&snap_guard, n);
                            // Append eBPF per-IP metrics if available.
                            body.push_str(&render_ebpf_ip_metrics(&snap_guard));
                            drop(snap_guard);
                            eprintln!("  [scrape #{n}] {addr} → /metrics ({} bytes)", body.len());
                            respond(
                                &mut stream,
                                "200 OK",
                                "text/plain; version=0.0.4; charset=utf-8",
                                &body,
                            );
                        }
                        Some("/health") => {
                            respond(
                                &mut stream,
                                "200 OK",
                                "application/json",
                                "{\"status\":\"ok\"}",
                            );
                        }
                        Some("/") | Some("/index.html") => {
                            respond(
                                &mut stream,
                                "200 OK",
                                "text/html; charset=utf-8",
                                &index_html(port_c),
                            );
                        }
                        _ => {
                            respond(
                                &mut stream,
                                "404 Not Found",
                                "text/plain",
                                "404 Not Found\nEndpoints: /metrics  /health  /\n",
                            );
                        }
                    }
                });
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(e) => eprintln!("accept: {e}"),
        }
    }
    eprintln!("netmon: prometheus exporter stopped.");
    Ok(())
}

// ─── eBPF-specific Prometheus metrics ────────────────────────────────────────

/// Renders additional metric families populated from eBPF per-IP data.
/// Only emits output when at least one process has ip_traffic entries.
fn render_ebpf_ip_metrics(snap: &Snapshot) -> String {
    let has_ip = snap.procs.iter().any(|p| !p.ip_traffic.is_empty());
    if !has_ip {
        return String::new();
    }

    let mut o = String::with_capacity(4096);

    // ── netmon_ebpf_ip_rx_bytes_total ──
    o.push_str("# HELP netmon_ebpf_ip_rx_bytes_total Cumulative bytes received per process per remote IP (eBPF)\n");
    o.push_str("# TYPE netmon_ebpf_ip_rx_bytes_total counter\n");
    for p in &snap.procs {
        for ip in &p.ip_traffic {
            o.push_str(&format!(
                "netmon_ebpf_ip_rx_bytes_total{{pid=\"{}\",process=\"{}\",remote_ip=\"{}\",remote_port=\"{}\"}} {}\n",
                p.pid, esc(&p.name), esc(&ip.remote_addr), ip.remote_port, ip.rx_bytes_total
            ));
        }
    }

    // ── netmon_ebpf_ip_tx_bytes_total ──
    o.push_str("# HELP netmon_ebpf_ip_tx_bytes_total Cumulative bytes transmitted per process per remote IP (eBPF)\n");
    o.push_str("# TYPE netmon_ebpf_ip_tx_bytes_total counter\n");
    for p in &snap.procs {
        for ip in &p.ip_traffic {
            o.push_str(&format!(
                "netmon_ebpf_ip_tx_bytes_total{{pid=\"{}\",process=\"{}\",remote_ip=\"{}\",remote_port=\"{}\"}} {}\n",
                p.pid, esc(&p.name), esc(&ip.remote_addr), ip.remote_port, ip.tx_bytes_total
            ));
        }
    }

    // ── netmon_ebpf_ip_rx_bytes_per_second ──
    o.push_str("# HELP netmon_ebpf_ip_rx_bytes_per_second RX rate per process per remote IP in the last interval (eBPF)\n");
    o.push_str("# TYPE netmon_ebpf_ip_rx_bytes_per_second gauge\n");
    for p in &snap.procs {
        for ip in &p.ip_traffic {
            o.push_str(&format!(
                "netmon_ebpf_ip_rx_bytes_per_second{{pid=\"{}\",process=\"{}\",remote_ip=\"{}\",remote_port=\"{}\"}} {}\n",
                p.pid, esc(&p.name), esc(&ip.remote_addr), ip.remote_port, ip.rx_bytes_delta
            ));
        }
    }

    // ── netmon_ebpf_ip_tx_bytes_per_second ──
    o.push_str("# HELP netmon_ebpf_ip_tx_bytes_per_second TX rate per process per remote IP in the last interval (eBPF)\n");
    o.push_str("# TYPE netmon_ebpf_ip_tx_bytes_per_second gauge\n");
    for p in &snap.procs {
        for ip in &p.ip_traffic {
            o.push_str(&format!(
                "netmon_ebpf_ip_tx_bytes_per_second{{pid=\"{}\",process=\"{}\",remote_ip=\"{}\",remote_port=\"{}\"}} {}\n",
                p.pid, esc(&p.name), esc(&ip.remote_addr), ip.remote_port, ip.tx_bytes_delta
            ));
        }
    }

    o
}
