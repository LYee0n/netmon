//! eBPF loader and poller (`src/ebpf_loader.rs`)
//!
//! Loads the compiled eBPF object (embedded at build time), attaches kprobes,
//! and runs a background thread that drains the ring-buffer and polls the
//! TRAFFIC HashMap — giving continuous per-(pid, remote_ip) byte totals.
//!
//! Gracefully degrades to None if the .o file is absent or eBPF fails to load.

use anyhow::{Context, Result};
use aya::{
    maps::{HashMap as AyaHashMap, MapData, RingBuf},
    programs::KProbe,
    Ebpf,                       // aya 0.13 renamed Bpf → Ebpf
};
use aya_log::EbpfLogger;        // renamed BpfLogger → EbpfLogger
use netmon_common::{TrafficEvent, TrafficKey, TrafficValue};
use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

// ─── Embedded eBPF object ─────────────────────────────────────────────────────
//
// build.rs emits `cargo:rustc-cfg=ebpf_obj` when src/netmon-ebpf.o exists.
// We use a plain cfg (not a Cargo feature) to avoid the "unexpected feature"
// warning.  The static is always present; it's just empty when the .o is absent.

#[cfg(ebpf_obj)]
static NETMON_BPF_OBJ: &[u8] =
    include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/netmon-ebpf.o"));

#[cfg(not(ebpf_obj))]
static NETMON_BPF_OBJ: &[u8] = &[];

// ─── Public data types ────────────────────────────────────────────────────────

/// One (pid, remote_addr, remote_port) traffic record with running totals.
#[derive(Debug, Clone)]
pub struct EbpfTrafficEntry {
    pub pid: u32,
    pub comm: String,
    pub remote_addr: IpAddr,
    pub remote_port: u16,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    /// Bytes in the last collection interval (set by `snapshot()`).
    pub rx_delta: u64,
    pub tx_delta: u64,
    pub last_seen: Instant,
}

impl EbpfTrafficEntry {
    fn new(pid: u32, comm: String, remote_addr: IpAddr, remote_port: u16) -> Self {
        Self {
            pid,
            comm,
            remote_addr,
            remote_port,
            rx_bytes: 0,
            tx_bytes: 0,
            rx_delta: 0,
            tx_delta: 0,
            last_seen: Instant::now(),
        }
    }
}

/// Thread-safe, continuously updated traffic table.
#[derive(Clone, Default)]
pub struct EbpfTrafficTable {
    inner: Arc<Mutex<TrafficTableInner>>,
}

#[derive(Default)]
struct TrafficTableInner {
    entries: HashMap<(u32, IpAddr, u16), EbpfTrafficEntry>,
    prev_rx:  HashMap<(u32, IpAddr, u16), u64>,
    prev_tx:  HashMap<(u32, IpAddr, u16), u64>,
}

impl EbpfTrafficTable {
    /// Point-in-time snapshot with deltas computed.
    /// Avoids the borrow-checker conflict by collecting keys first.
    pub fn snapshot(&self) -> Vec<EbpfTrafficEntry> {
        let mut inner = self.inner.lock().unwrap();

        // Collect (key, rx, tx) so we can mutate prev_* without aliasing entries.
        let updates: Vec<_> = inner
            .entries
            .iter()
            .map(|(k, e)| (*k, e.rx_bytes, e.tx_bytes))
            .collect();

        let mut out = Vec::with_capacity(updates.len());
        for (k, rx, tx) in updates {
            let prev_rx = *inner.prev_rx.get(&k).unwrap_or(&0);
            let prev_tx = *inner.prev_tx.get(&k).unwrap_or(&0);
            inner.prev_rx.insert(k, rx);
            inner.prev_tx.insert(k, tx);

            if let Some(entry) = inner.entries.get_mut(&k) {
                entry.rx_delta = rx.saturating_sub(prev_rx);
                entry.tx_delta = tx.saturating_sub(prev_tx);
                out.push(entry.clone());
            }
        }

        out.sort_by(|a, b| {
            (b.rx_delta + b.tx_delta).cmp(&(a.rx_delta + a.tx_delta))
        });
        out
    }

    fn upsert(&self, key: &TrafficKey, val: &TrafficValue) {
        let remote_addr = key.remote_addr();
        let mk = (key.pid, remote_addr, key.remote_port);
        let mut inner = self.inner.lock().unwrap();
        let entry = inner.entries.entry(mk).or_insert_with(|| {
            EbpfTrafficEntry::new(
                key.pid,
                val.comm_str().to_string(),
                remote_addr,
                key.remote_port,
            )
        });
        entry.rx_bytes  = val.rx_bytes;
        entry.tx_bytes  = val.tx_bytes;
        entry.last_seen = Instant::now();
    }

    fn apply_event(&self, ev: &TrafficEvent) {
        use std::net::Ipv6Addr;
        let remote_addr: IpAddr = if ev.af == 2 {
            let b = ev.dst_ip4.to_be_bytes();
            IpAddr::V4(Ipv4Addr::new(b[0], b[1], b[2], b[3]))
        } else {
            IpAddr::V6(Ipv6Addr::from(ev.dst_ip6))
        };
        let mk = (ev.pid, remote_addr, ev.dst_port);
        let mut inner = self.inner.lock().unwrap();
        let entry = inner.entries.entry(mk).or_insert_with(|| {
            EbpfTrafficEntry::new(ev.pid, String::new(), remote_addr, ev.dst_port)
        });
        if ev.direction == 1 {
            entry.tx_bytes += ev.bytes as u64;
        } else {
            entry.rx_bytes += ev.bytes as u64;
        }
        entry.last_seen = Instant::now();
    }

    fn evict_stale(&self, ttl: Duration) {
        let mut inner = self.inner.lock().unwrap();
        let now = Instant::now();
        inner.entries.retain(|_, v| now.duration_since(v.last_seen) < ttl);
    }
}

// ─── Public entry point ───────────────────────────────────────────────────────

pub fn start(poll_interval: Duration) -> Option<EbpfTrafficTable> {
    if NETMON_BPF_OBJ.is_empty() {
        eprintln!("[ebpf] netmon-ebpf.o not found — run `cargo xtask build-ebpf` first");
        return None;
    }
    match load_and_attach(poll_interval) {
        Ok(t)  => Some(t),
        Err(e) => {
            eprintln!("[ebpf] load failed: {e:#}  →  /proc fallback");
            None
        }
    }
}

// ─── Loader ───────────────────────────────────────────────────────────────────

fn load_and_attach(poll_interval: Duration) -> Result<EbpfTrafficTable> {
    let mut ebpf = Ebpf::load(NETMON_BPF_OBJ).context("loading eBPF object")?;

    if let Err(e) = EbpfLogger::init(&mut ebpf) {
        eprintln!("[ebpf] logger init (non-fatal): {e}");
    }

    // kretprobes in aya 0.13 are attached via KProbe with offset = 0 and the
    // program type declared in the eBPF source as kretprobe.  The host-side
    // type is still `KProbe` — there is no separate `KRetProbe` struct.
    attach_prog(&mut ebpf, "netmon_tcp_sendmsg",    "tcp_sendmsg")?;
    attach_prog(&mut ebpf, "netmon_tcp_recvmsg_ret","tcp_recvmsg")?;
    attach_prog(&mut ebpf, "netmon_udp_sendmsg",    "udp_sendmsg")?;
    attach_prog(&mut ebpf, "netmon_udp_recvmsg_ret","udp_recvmsg")?;

    eprintln!("[ebpf] probes attached — capturing TCP/UDP traffic");

    let table    = EbpfTrafficTable::default();
    let table_bg = table.clone();

    std::thread::Builder::new()
        .name("ebpf-poller".into())
        .spawn(move || poller_loop(ebpf, table_bg, poll_interval))
        .context("spawn ebpf-poller")?;

    Ok(table)
}

fn attach_prog(ebpf: &mut Ebpf, prog_name: &str, fn_name: &str) -> Result<()> {
    let prog: &mut KProbe = ebpf
        .program_mut(prog_name)
        .with_context(|| format!("{prog_name} not found in eBPF object"))?
        .try_into()
        .with_context(|| format!("{prog_name}: expected KProbe"))?;
    prog.load()
        .with_context(|| format!("loading {prog_name}"))?;
    prog.attach(fn_name, 0)
        .with_context(|| format!("attaching {prog_name} → {fn_name}"))?;
    Ok(())
}

// ─── Background poller ────────────────────────────────────────────────────────

fn poller_loop(mut ebpf: Ebpf, table: EbpfTrafficTable, poll_interval: Duration) {
    // Take ownership of the ring-buffer map from the Ebpf object.
    let mut ring: RingBuf<MapData> = ebpf
        .take_map("EVENTS")
        .expect("EVENTS map missing")
        .try_into()
        .expect("EVENTS is not a RingBuf");

    let mut last_scan = Instant::now();
    let stale_ttl     = Duration::from_secs(30);

    loop {
        // Drain all available ring-buffer records.
        while let Some(item) = ring.next() {
            if item.len() == std::mem::size_of::<TrafficEvent>() {
                // SAFETY: eBPF side always writes exactly one TrafficEvent.
                let ev: TrafficEvent = unsafe {
                    std::ptr::read_unaligned(item.as_ptr() as *const TrafficEvent)
                };
                table.apply_event(&ev);
            }
        }

        // Periodic full scan of the TRAFFIC HashMap for authoritative totals.
        if last_scan.elapsed() >= poll_interval {
            // borrow as &mut to get MapData (owned ref), then convert.
            if let Some(map_ref) = ebpf.map_mut("TRAFFIC") {
                if let Ok(traffic_map) =
                    AyaHashMap::<&mut MapData, TrafficKey, TrafficValue>::try_from(map_ref)
                {
                    for item in traffic_map.iter() {
                        if let Ok((k, v)) = item {
                            table.upsert(&k, &v);
                        }
                    }
                }
            }
            table.evict_stale(stale_ttl);
            last_scan = Instant::now();
        }

        std::thread::sleep(Duration::from_millis(10));
    }
}
