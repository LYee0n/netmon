//! Reads /proc/net/* and /proc/PID/* to build Snapshots.
//! When the eBPF loader is active it merges per-(pid,ip) traffic data from
//! the kernel probes into `ProcTraffic`, giving true per-IP byte accounting.
use crate::ebpf_loader::EbpfTrafficTable;
use crate::types::*;
use procfs::net::TcpState;
use std::collections::HashMap;
use sysinfo::{Networks, System};

// ─── TCP state → string ───────────────────────────────────────────────────────

pub fn tcp_state_str(s: &TcpState) -> &'static str {
    match s {
        TcpState::Established => "ESTABLISHED",
        TcpState::SynSent => "SYN_SENT",
        TcpState::SynRecv => "SYN_RECV",
        TcpState::FinWait1 => "FIN_WAIT1",
        TcpState::FinWait2 => "FIN_WAIT2",
        TcpState::TimeWait => "TIME_WAIT",
        TcpState::Close => "CLOSE",
        TcpState::CloseWait => "CLOSE_WAIT",
        TcpState::LastAck => "LAST_ACK",
        TcpState::Listen => "LISTEN",
        TcpState::Closing => "CLOSING",
        _ => "UNKNOWN",
    }
}

// ─── inode → process map ──────────────────────────────────────────────────────

struct InodeMap(HashMap<u64, (u32, String, String, String, String)>);
//                              pid  comm  cmdline exe    cwd

impl InodeMap {
    fn build() -> Self {
        let mut map = HashMap::new();
        let all = match procfs::process::all_processes() {
            Ok(it) => it,
            Err(_) => return InodeMap(map),
        };
        for proc in all.flatten() {
            let pid = proc.pid() as u32;
            let comm = proc
                .stat()
                .map(|s| s.comm.clone())
                .unwrap_or_else(|_| "?".into());
            let cmdline = proc.cmdline().ok().map(|v| v.join(" ")).unwrap_or_default();
            let exe = proc
                .exe()
                .ok()
                .and_then(|p| p.to_str().map(|s| s.to_string()))
                .unwrap_or_default();
            let cwd = proc
                .cwd()
                .ok()
                .and_then(|p| p.to_str().map(|s| s.to_string()))
                .unwrap_or_default();
            if let Ok(fds) = proc.fd() {
                for fd in fds.flatten() {
                    if let procfs::process::FDTarget::Socket(inode) = fd.target {
                        map.insert(
                            inode,
                            (pid, comm.clone(), cmdline.clone(), exe.clone(), cwd.clone()),
                        );
                    }
                }
            }
        }
        InodeMap(map)
    }
    fn get(&self, inode: u64) -> Option<&(u32, String, String, String, String)> {
        self.0.get(&inode)
    }
}

// ─── /etc/passwd uid cache ────────────────────────────────────────────────────

fn uid_to_username(uid: u32) -> Option<String> {
    let text = std::fs::read_to_string("/etc/passwd").ok()?;
    for line in text.lines() {
        let parts: Vec<&str> = line.split(':').collect();
        if parts.len() >= 3 {
            if parts[2].parse::<u32>().ok() == Some(uid) {
                return Some(parts[0].to_string());
            }
        }
    }
    None
}

// ─── /proc/PID/io ─────────────────────────────────────────────────────────────

fn read_proc_io(pid: u32) -> (u64, u64) {
    let text = match std::fs::read_to_string(format!("/proc/{}/io", pid)) {
        Ok(t) => t,
        Err(_) => return (0, 0),
    };
    let (mut rx, mut tx) = (0u64, 0u64);
    for line in text.lines() {
        if let Some(v) = line.strip_prefix("read_bytes: ") {
            rx = v.trim().parse().unwrap_or(0);
        }
        if let Some(v) = line.strip_prefix("write_bytes: ") {
            tx = v.trim().parse().unwrap_or(0);
        }
    }
    (rx, tx)
}

// ─── Collector ────────────────────────────────────────────────────────────────

pub struct Collector {
    sys: System,
    networks: Networks,
    prev_iface: HashMap<String, (u64, u64)>,
    prev_proc_io: HashMap<u32, (u64, u64)>,
    uid_cache: HashMap<u32, Option<String>>,
    /// Live eBPF traffic table — `None` when eBPF is unavailable.
    pub ebpf_table: Option<EbpfTrafficTable>,
}

impl Collector {
    pub fn new() -> Self {
        let mut sys = System::new_all();
        sys.refresh_all();
        Collector {
            sys,
            networks: Networks::new_with_refreshed_list(),
            prev_iface: HashMap::new(),
            prev_proc_io: HashMap::new(),
            uid_cache: HashMap::new(),
            ebpf_table: None,
        }
    }

    pub fn collect(&mut self) -> Snapshot {
        self.sys.refresh_all();
        self.networks.refresh();

        let inode_map = InodeMap::build();

        // ── Connections ──────────────────────────────────────────────────────
        let mut conns: Vec<Connection> = Vec::new();

        // helper closure
        let mut add_conn =
            |local_ip: String,
             local_port: u16,
             remote_ip: String,
             remote_port: u16,
             state: String,
             inode: u64,
             uid: u32,
             rx_queue: u64,
             tx_queue: u64,
             proto: Protocol,
             uid_cache: &mut HashMap<u32, Option<String>>| {
                let pi = inode_map.get(inode);
                let username = uid_cache
                    .entry(uid)
                    .or_insert_with(|| uid_to_username(uid))
                    .clone();
                conns.push(Connection {
                    protocol: proto,
                    local_addr: local_ip,
                    local_port,
                    remote_addr: remote_ip,
                    remote_port,
                    state,
                    inode,
                    uid,
                    rx_queue,
                    tx_queue,
                    pid: pi.map(|(p, _, _, _, _)| *p),
                    process_name: pi.map(|(_, n, _, _, _)| n.clone()),
                    cmdline: pi.map(|(_, _, c, _, _)| c.clone()),
                    exe_path: pi.map(|(_, _, _, e, _)| e.clone()),
                    working_dir: pi.map(|(_, _, _, _, w)| w.clone()),
                    username,
                });
            };

        if let Ok(entries) = procfs::net::tcp() {
            for e in entries {
                add_conn(
                    e.local_address.ip().to_string(),
                    e.local_address.port(),
                    e.remote_address.ip().to_string(),
                    e.remote_address.port(),
                    tcp_state_str(&e.state).into(),
                    e.inode,
                    e.uid,
                    e.rx_queue.into(),
                    e.tx_queue.into(),
                    Protocol::Tcp,
                    &mut self.uid_cache,
                );
            }
        }
        if let Ok(entries) = procfs::net::tcp6() {
            for e in entries {
                add_conn(
                    e.local_address.ip().to_string(),
                    e.local_address.port(),
                    e.remote_address.ip().to_string(),
                    e.remote_address.port(),
                    tcp_state_str(&e.state).into(),
                    e.inode,
                    e.uid,
                    e.rx_queue.into(),
                    e.tx_queue.into(),
                    Protocol::Tcp6,
                    &mut self.uid_cache,
                );
            }
        }
        if let Ok(entries) = procfs::net::udp() {
            for e in entries {
                add_conn(
                    e.local_address.ip().to_string(),
                    e.local_address.port(),
                    e.remote_address.ip().to_string(),
                    e.remote_address.port(),
                    "UDP".into(),
                    e.inode,
                    e.uid,
                    e.rx_queue.into(),
                    e.tx_queue.into(),
                    Protocol::Udp,
                    &mut self.uid_cache,
                );
            }
        }
        if let Ok(entries) = procfs::net::udp6() {
            for e in entries {
                add_conn(
                    e.local_address.ip().to_string(),
                    e.local_address.port(),
                    e.remote_address.ip().to_string(),
                    e.remote_address.port(),
                    "UDP".into(),
                    e.inode,
                    e.uid,
                    e.rx_queue.into(),
                    e.tx_queue.into(),
                    Protocol::Udp6,
                    &mut self.uid_cache,
                );
            }
        }

        // ── Interfaces ───────────────────────────────────────────────────────
        let mut ifaces: Vec<IfaceSnapshot> = Vec::new();
        let mut total_rx_bps = 0u64;
        let mut total_tx_bps = 0u64;

        for (name, data) in self.networks.iter() {
            let prev = self.prev_iface.get(name).cloned().unwrap_or((0, 0));
            let rx_rate = data.received().saturating_sub(prev.0);
            let tx_rate = data.transmitted().saturating_sub(prev.1);
            self.prev_iface
                .insert(name.clone(), (data.received(), data.transmitted()));
            total_rx_bps += rx_rate;
            total_tx_bps += tx_rate;
            ifaces.push(IfaceSnapshot {
                name: name.clone(),
                rx_bytes: data.total_received(),
                tx_bytes: data.total_transmitted(),
                rx_packets: data.total_packets_received(),
                tx_packets: data.total_packets_transmitted(),
                rx_errors: data.total_errors_on_received(),
                tx_errors: data.total_errors_on_transmitted(),
                rx_rate_bps: rx_rate,
                tx_rate_bps: tx_rate,
            });
        }
        ifaces
            .sort_by(|a, b| (b.rx_rate_bps + b.tx_rate_bps).cmp(&(a.rx_rate_bps + a.tx_rate_bps)));

        // ── Per-process ──────────────────────────────────────────────────────
        let mut pid_conn_count: HashMap<u32, usize> = HashMap::new();
        for c in &conns {
            if let Some(pid) = c.pid {
                *pid_conn_count.entry(pid).or_insert(0) += 1;
            }
        }

        let mut procs: Vec<ProcTraffic> = Vec::new();
        for (pid_u, proc) in self.sys.processes() {
            let pid = pid_u.as_u32();
            let conn_count = *pid_conn_count.get(&pid).unwrap_or(&0);
            if conn_count == 0 {
                continue;
            }

            let (rx_bytes, tx_bytes) = read_proc_io(pid);
            let prev = self.prev_proc_io.get(&pid).cloned().unwrap_or((0, 0));
            let rx_delta = rx_bytes.saturating_sub(prev.0);
            let tx_delta = tx_bytes.saturating_sub(prev.1);
            self.prev_proc_io.insert(pid, (rx_bytes, tx_bytes));

            let cmdline = proc
                .cmd()
                .iter()
                .map(|s| s.to_string_lossy())
                .collect::<Vec<_>>()
                .join(" ");
            procs.push(ProcTraffic {
                pid,
                name: proc.name().to_string_lossy().into_owned(),
                cmdline: if cmdline.is_empty() {
                    "[no cmdline]".into()
                } else {
                    cmdline
                },
                rx_bytes,
                tx_bytes,
                rx_bytes_delta: rx_delta,
                tx_bytes_delta: tx_delta,
                connections: conn_count,
                cpu_pct: proc.cpu_usage(),
                mem_bytes: proc.memory(),
                ip_traffic: vec![],   // filled in by eBPF merge below if active
            });
        }
        procs.sort_by(|a, b| {
            (b.rx_bytes_delta + b.tx_bytes_delta)
                .cmp(&(a.rx_bytes_delta + a.tx_bytes_delta))
                .then(b.connections.cmp(&a.connections))
        });

        let mut stats = GlobalStats::from_connections(&conns);
        stats.total_rx_bps = total_rx_bps;
        stats.total_tx_bps = total_tx_bps;

        // ── Merge eBPF per-(pid,ip) data into ProcTraffic entries ───────────
        // When the eBPF table is active we replace the /proc/PID/io-derived
        // rx/tx deltas with the kernel-measured network-only byte counts.
        // This gives true per-IP visibility without any packet copying.
        if let Some(ref ebpf) = self.ebpf_table {
            let ebpf_snap = ebpf.snapshot();

            // Build a lookup: pid → list of (remote_addr, rx_delta, tx_delta).
            let mut pid_ip_traffic: HashMap<u32, Vec<crate::types::IpTrafficEntry>> =
                HashMap::new();

            // Also aggregate total network bytes per PID for the process row.
            let mut pid_net_rx: HashMap<u32, u64> = HashMap::new();
            let mut pid_net_tx: HashMap<u32, u64> = HashMap::new();

            for entry in &ebpf_snap {
                pid_ip_traffic
                    .entry(entry.pid)
                    .or_default()
                    .push(crate::types::IpTrafficEntry {
                        remote_addr: entry.remote_addr.to_string(),
                        remote_port: entry.remote_port,
                        rx_bytes_total: entry.rx_bytes,
                        tx_bytes_total: entry.tx_bytes,
                        rx_bytes_delta: entry.rx_delta,
                        tx_bytes_delta: entry.tx_delta,
                    });
                *pid_net_rx.entry(entry.pid).or_insert(0) += entry.rx_delta;
                *pid_net_tx.entry(entry.pid).or_insert(0) += entry.tx_delta;
            }

            for proc in &mut procs {
                // Override /proc/io deltas with kernel-measured network bytes.
                if let Some(net_rx) = pid_net_rx.get(&proc.pid) {
                    proc.rx_bytes_delta = *net_rx;
                }
                if let Some(net_tx) = pid_net_tx.get(&proc.pid) {
                    proc.tx_bytes_delta = *net_tx;
                }
                // Attach the per-IP breakdown.
                if let Some(ip_entries) = pid_ip_traffic.remove(&proc.pid) {
                    proc.ip_traffic = ip_entries;
                }
            }

            // Any PIDs tracked by eBPF but not yet in procs (e.g. short-lived
            // processes) get a synthetic entry so they appear in the output.
            for entry in &ebpf_snap {
                if !procs.iter().any(|p| p.pid == entry.pid) && entry.pid != 0 {
                    let net_rx = pid_net_rx.get(&entry.pid).cloned().unwrap_or(0);
                    let net_tx = pid_net_tx.get(&entry.pid).cloned().unwrap_or(0);
                    if net_rx + net_tx == 0 {
                        continue;
                    }
                    procs.push(ProcTraffic {
                        pid: entry.pid,
                        name: entry.comm.clone(),
                        cmdline: entry.comm.clone(),
                        rx_bytes: entry.rx_bytes,
                        tx_bytes: entry.tx_bytes,
                        rx_bytes_delta: net_rx,
                        tx_bytes_delta: net_tx,
                        connections: *pid_conn_count.get(&entry.pid).unwrap_or(&0),
                        cpu_pct: 0.0,
                        mem_bytes: 0,
                        ip_traffic: pid_ip_traffic
                            .remove(&entry.pid)
                            .unwrap_or_default(),
                    });
                }
            }

            // Re-sort after merge.
            procs.sort_by(|a, b| {
                (b.rx_bytes_delta + b.tx_bytes_delta)
                    .cmp(&(a.rx_bytes_delta + a.tx_bytes_delta))
                    .then(b.connections.cmp(&a.connections))
            });
        }

        Snapshot {
            timestamp: chrono::Local::now(),
            connections: conns,
            ifaces,
            procs,
            stats,
        }
    }
}