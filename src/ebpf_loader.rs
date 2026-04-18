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
    /// Monotonically-increasing totals since netmon started.
    /// Never reset — surviving eviction and eBPF map resets.
    lifetime_rx: HashMap<(u32, IpAddr, u16), u64>,
    lifetime_tx: HashMap<(u32, IpAddr, u16), u64>,
    /// Last kernel-map value seen per key, used to detect eBPF-side resets.
    last_kernel_rx: HashMap<(u32, IpAddr, u16), u64>,
    last_kernel_tx: HashMap<(u32, IpAddr, u16), u64>,
    /// Comm name cache — survives eviction so dead processes are still labelled.
    comm_cache: HashMap<(u32, IpAddr, u16), String>,
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

            // Read lifetime totals into locals before the mutable entries borrow.
            let life_rx = *inner.lifetime_rx.get(&k).unwrap_or(&rx);
            let life_tx = *inner.lifetime_tx.get(&k).unwrap_or(&tx);
            if let Some(entry) = inner.entries.get_mut(&k) {
                entry.rx_delta = rx.saturating_sub(prev_rx);
                entry.tx_delta = tx.saturating_sub(prev_tx);
                // Report lifetime totals so the display is always cumulative.
                entry.rx_bytes = life_rx;
                entry.tx_bytes = life_tx;
                out.push(entry.clone());
            }
        }

        // Emit synthetic entries for keys with lifetime bytes but no live entry
        // (process finished and was evicted). These show cumulative totals only
        // (delta = 0) so the user can see what a short-lived process transferred.
        let lifetime_keys: Vec<_> = inner.lifetime_rx.keys().cloned().collect();
        for k in lifetime_keys {
            if inner.entries.contains_key(&k) {
                continue; // already in out
            }
            let life_rx = *inner.lifetime_rx.get(&k).unwrap_or(&0);
            let life_tx = *inner.lifetime_tx.get(&k).unwrap_or(&0);
            if life_rx + life_tx == 0 {
                continue;
            }
            let comm = inner.comm_cache.get(&k).cloned().unwrap_or_default();
            let mut e = EbpfTrafficEntry::new(k.0, comm, k.1, k.2);
            e.rx_bytes = life_rx;
            e.tx_bytes = life_tx;
            e.rx_delta = 0;
            e.tx_delta = 0;
            out.push(e);
        }

        out.sort_by(|a, b| {
            (b.rx_bytes + b.tx_bytes).cmp(&(a.rx_bytes + a.tx_bytes))
        });
        out
    }

    fn upsert(&self, key: &TrafficKey, val: &TrafficValue) {
        let remote_addr = key.remote_addr();
        let mk = (key.pid, remote_addr, key.remote_port);
        let mut inner = self.inner.lock().unwrap();
        // Do all lifetime bookkeeping before borrowing `entries` mutably.
        // Accumulate lifetime totals. If the kernel counter went backward
        // (eBPF reload / overflow) treat it as a fresh start from 0.
        let last_krx = *inner.last_kernel_rx.get(&mk).unwrap_or(&0);
        let last_ktx = *inner.last_kernel_tx.get(&mk).unwrap_or(&0);
        let krx_inc = val.rx_bytes.saturating_sub(last_krx);
        let ktx_inc = val.tx_bytes.saturating_sub(last_ktx);
        inner.last_kernel_rx.insert(mk, val.rx_bytes);
        inner.last_kernel_tx.insert(mk, val.tx_bytes);
        *inner.lifetime_rx.entry(mk).or_insert(0) += krx_inc;
        *inner.lifetime_tx.entry(mk).or_insert(0) += ktx_inc;
        // Now safe to mutably borrow entries.
        let comm_str = val.comm_str().to_string();
        inner.comm_cache.insert(mk, comm_str.clone());
        let entry = inner.entries.entry(mk).or_insert_with(|| {
            EbpfTrafficEntry::new(key.pid, comm_str, remote_addr, key.remote_port)
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
        let inc = ev.bytes as u64;
        let mut inner = self.inner.lock().unwrap();
        // Update lifetime accumulators before borrowing entries mutably.
        if ev.direction == 1 {
            *inner.lifetime_tx.entry(mk).or_insert(0) += inc;
        } else {
            *inner.lifetime_rx.entry(mk).or_insert(0) += inc;
        }
        // Read comm eagerly before or_insert_with so we don't borrow inner
        // inside the closure (which already mutably borrows inner.entries).
        let is_new = !inner.entries.contains_key(&mk);
        let comm = if is_new {
            let c = std::fs::read_to_string(format!("/proc/{}/comm", ev.pid))
                .map(|s| s.trim().to_string())
                .unwrap_or_default();
            inner.comm_cache.insert(mk, c.clone());
            c
        } else {
            String::new() // unused — entry already exists
        };
        let entry = inner.entries.entry(mk).or_insert_with(|| {
            EbpfTrafficEntry::new(ev.pid, comm, remote_addr, ev.dst_port)
        });
        if ev.direction == 1 {
            entry.tx_bytes += inc;
        } else {
            entry.rx_bytes += inc;
        }
        entry.last_seen = Instant::now();
    }

    fn evict_stale(&self, ttl: Duration) {
        let mut inner = self.inner.lock().unwrap();
        let now = Instant::now();
        // Only evict from the live entries table — lifetime_rx/tx are kept
        // forever so cumulative totals survive process death and quietness.
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