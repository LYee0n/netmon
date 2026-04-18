//! Shared data types used across all modes.
use chrono::{DateTime, Local};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Protocol {
    Tcp,
    Tcp6,
    Udp,
    Udp6,
}

impl Protocol {
    pub fn as_str(&self) -> &'static str {
        match self {
            Protocol::Tcp => "TCP",
            Protocol::Tcp6 => "TCP6",
            Protocol::Udp => "UDP",
            Protocol::Udp6 => "UDP6",
        }
    }
    pub fn is_udp(&self) -> bool {
        matches!(self, Protocol::Udp | Protocol::Udp6)
    }
}

impl std::fmt::Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Connection {
    pub protocol: Protocol,
    pub local_addr: String,
    pub local_port: u16,
    pub remote_addr: String,
    pub remote_port: u16,
    pub state: String,
    pub inode: u64,
    pub uid: u32,
    pub rx_queue: u64,
    pub tx_queue: u64,
    // process info
    pub pid: Option<u32>,
    pub process_name: Option<String>,
    pub cmdline: Option<String>,     // full /proc/PID/cmdline
    pub exe_path: Option<String>,    // /proc/PID/exe resolved
    pub working_dir: Option<String>, // /proc/PID/cwd
    pub username: Option<String>,    // resolved from uid
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ProcTraffic {
    pub pid: u32,
    pub name: String,
    pub cmdline: String,
    pub rx_bytes: u64,       // cumulative (from /proc/PID/io read_bytes)
    pub tx_bytes: u64,       // cumulative (write_bytes)
    pub rx_bytes_delta: u64, // since last sample
    pub tx_bytes_delta: u64,
    pub connections: usize,
    pub cpu_pct: f32,
    pub mem_bytes: u64,
    /// Per-(remote_ip, port) breakdown — populated when eBPF is active.
    #[serde(default)]
    pub ip_traffic: Vec<IpTrafficEntry>,
}

/// One row in the per-process IP breakdown table (eBPF mode only).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct IpTrafficEntry {
    /// Remote IP address as a string (IPv4 or IPv6).
    pub remote_addr: String,
    pub remote_port: u16,
    /// Cumulative bytes since netmon started.
    pub rx_bytes_total: u64,
    pub tx_bytes_total: u64,
    /// Bytes in the last collection interval.
    pub rx_bytes_delta: u64,
    pub tx_bytes_delta: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IfaceSnapshot {
    pub name: String,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_packets: u64,
    pub tx_packets: u64,
    pub rx_errors: u64,
    pub tx_errors: u64,
    pub rx_rate_bps: u64, // bytes/s since last sample
    pub tx_rate_bps: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Snapshot {
    pub timestamp: DateTime<Local>,
    pub connections: Vec<Connection>,
    pub ifaces: Vec<IfaceSnapshot>,
    pub procs: Vec<ProcTraffic>,
    pub stats: GlobalStats,
}

impl Snapshot {
    pub fn empty() -> Self {
        Snapshot {
            timestamp: Local::now(),
            connections: vec![],
            ifaces: vec![],
            procs: vec![],
            stats: GlobalStats::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GlobalStats {
    pub total: usize,
    pub established: usize,
    pub listen: usize,
    pub time_wait: usize,
    pub close_wait: usize,
    pub syn_sent: usize,
    pub udp: usize,
    pub total_rx_bps: u64,
    pub total_tx_bps: u64,
}

impl GlobalStats {
    pub fn from_connections(conns: &[Connection]) -> Self {
        GlobalStats {
            total: conns.len(),
            established: conns.iter().filter(|c| c.state == "ESTABLISHED").count(),
            listen: conns.iter().filter(|c| c.state == "LISTEN").count(),
            time_wait: conns.iter().filter(|c| c.state == "TIME_WAIT").count(),
            close_wait: conns.iter().filter(|c| c.state == "CLOSE_WAIT").count(),
            syn_sent: conns.iter().filter(|c| c.state == "SYN_SENT").count(),
            udp: conns.iter().filter(|c| c.protocol.is_udp()).count(),
            total_rx_bps: 0,
            total_tx_bps: 0,
        }
    }
}
