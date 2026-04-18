//! Log mode: continuously collect snapshots and append beautifully formatted
//! reports to a file. Each sample writes a full block with:
//!   - global summary
//!   - per-interface stats with bar graphs
//!   - per-process table with full cmdline, rx/tx bars
//!   - full connection table with exe + cmdline inline
use crate::collector::Collector;
use crate::types::*;
use anyhow::Result;
use chrono::Local;
use std::fs::OpenOptions;
use std::io::{BufWriter, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

// ─── format helpers ───────────────────────────────────────────────────────────

fn fb(b: u64) -> String {
    if b == 0 {
        return "0 B".into();
    }
    if b < 1024 {
        format!("{b} B")
    } else if b < 1_048_576 {
        format!("{:.2} KB", b as f64 / 1024.0)
    } else if b < 1_073_741_824 {
        format!("{:.2} MB", b as f64 / 1_048_576.0)
    } else {
        format!("{:.3} GB", b as f64 / 1_073_741_824.0)
    }
}

fn fr(b: u64) -> String {
    if b == 0 {
        return "0 B/s".into();
    }
    if b < 1024 {
        format!("{b} B/s")
    } else if b < 1_048_576 {
        format!("{:.2} KB/s", b as f64 / 1024.0)
    } else {
        format!("{:.2} MB/s", b as f64 / 1_048_576.0)
    }
}

fn bar(val: u64, max: u64, w: usize) -> String {
    if max == 0 {
        return "░".repeat(w);
    }
    let f = ((val as f64 / max as f64) * w as f64) as usize;
    format!(
        "{}{}",
        "█".repeat(f.min(w)),
        "░".repeat(w.saturating_sub(f))
    )
}

fn trunc(s: &str, n: usize) -> &str {
    if s.len() <= n {
        s
    } else {
        &s[..n]
    }
}

fn wrap(s: &str, w: usize) -> Vec<String> {
    if w == 0 || s.is_empty() {
        return vec![s.to_string()];
    }
    s.as_bytes()
        .chunks(w)
        .map(|c| String::from_utf8_lossy(c).into())
        .collect()
}

// ─── report writer ────────────────────────────────────────────────────────────

fn write_report(w: &mut impl Write, snap: &Snapshot, n: u64, iv: f64) -> Result<()> {
    const W: usize = 112;
    let ts = snap.timestamp.format("%Y-%m-%d %H:%M:%S%.3f");
    let s = &snap.stats;

    // ══ Header ══════════════════════════════════════════════════════════════
    writeln!(w, "\n{}", "═".repeat(W))?;
    writeln!(w, " ◉ netmon  SAMPLE #{n:<6} │ {ts}  │  interval: {iv:.1}s")?;
    writeln!(w, "{}", "═".repeat(W))?;

    // ── Global summary ──────────────────────────────────────────────────────
    writeln!(w, "\n ┌─[ GLOBAL SUMMARY ]{}", "─".repeat(W - 19))?;
    writeln!(w, " │  total:{:>5}  estab:{:>5}  listen:{:>4}  time_wait:{:>5}  close_wait:{:>4}  syn_sent:{:>3}  udp:{:>4}",
        s.total, s.established, s.listen, s.time_wait, s.close_wait, s.syn_sent, s.udp)?;
    writeln!(
        w,
        " │  RX: {:>16}   TX: {:>16}",
        fr(s.total_rx_bps),
        fr(s.total_tx_bps)
    )?;
    writeln!(w, " └{}", "─".repeat(W - 1))?;

    // ── Interfaces ──────────────────────────────────────────────────────────
    writeln!(
        w,
        "\n ┌─[ NETWORK INTERFACES  count:{} ]{}",
        snap.ifaces.len(),
        "─".repeat(W.saturating_sub(33))
    )?;
    writeln!(
        w,
        " │  {:<14}  {:>13}  {:>13}  {:>13}  {:>13}  {:>9}  {:>9}",
        "INTERFACE", "RX TOTAL", "TX TOTAL", "RX/s", "TX/s", "RX ERR", "TX ERR"
    )?;
    writeln!(w, " │  {}", "·".repeat(W - 4))?;

    let max_r = snap
        .ifaces
        .iter()
        .map(|i| i.rx_rate_bps.max(i.tx_rate_bps))
        .max()
        .unwrap_or(1)
        .max(1);
    for i in &snap.ifaces {
        writeln!(
            w,
            " │  {:<14}  {:>13}  {:>13}  {:>13}  {:>13}  {:>9}  {:>9}",
            i.name,
            fb(i.rx_bytes),
            fb(i.tx_bytes),
            fr(i.rx_rate_bps),
            fr(i.tx_rate_bps),
            i.rx_errors,
            i.tx_errors
        )?;
        writeln!(
            w,
            " │    RX [{}] {:>13}",
            bar(i.rx_rate_bps, max_r, 42),
            fr(i.rx_rate_bps)
        )?;
        writeln!(
            w,
            " │    TX [{}] {:>13}",
            bar(i.tx_rate_bps, max_r, 42),
            fr(i.tx_rate_bps)
        )?;
    }
    writeln!(w, " └{}", "─".repeat(W - 1))?;

    // ── Per-process traffic ─────────────────────────────────────────────────
    writeln!(
        w,
        "\n ┌─[ PROCESS TRAFFIC  active:{} ]{}",
        snap.procs.len(),
        "─".repeat(W.saturating_sub(31))
    )?;
    writeln!(
        w,
        " │  {:<7}  {:<22}  {:>5}  {:>7}  {:>9}  {:>14}  {:>14}  {:>12}  {:>12}",
        "PID", "PROCESS", "CONNS", "CPU%", "MEM", "RX/s", "TX/s", "RX TOTAL", "TX TOTAL"
    )?;
    writeln!(w, " │  {}", "·".repeat(W - 4))?;

    let max_p = snap
        .procs
        .iter()
        .map(|p| p.rx_bytes_delta.max(p.tx_bytes_delta))
        .max()
        .unwrap_or(1)
        .max(1);
    for p in &snap.procs {
        writeln!(
            w,
            " │  {:<7}  {:<22}  {:>5}  {:>6.1}%  {:>9}  {:>14}  {:>14}  {:>12}  {:>12}",
            p.pid,
            trunc(&p.name, 22),
            p.connections,
            p.cpu_pct,
            fb(p.mem_bytes),
            fr(p.rx_bytes_delta),
            fr(p.tx_bytes_delta),
            fb(p.rx_bytes),
            fb(p.tx_bytes)
        )?;
        writeln!(
            w,
            " │     RX [{}] {:>13}",
            bar(p.rx_bytes_delta, max_p, 38),
            fr(p.rx_bytes_delta)
        )?;
        writeln!(
            w,
            " │     TX [{}] {:>13}",
            bar(p.tx_bytes_delta, max_p, 38),
            fr(p.tx_bytes_delta)
        )?;
        // Full command line, wrapped
        if !p.cmdline.is_empty() {
            for (i, chunk) in wrap(&p.cmdline, W - 18).iter().enumerate() {
                if i == 0 {
                    writeln!(w, " │     cmdline: {chunk}")?;
                } else {
                    writeln!(w, " │              {chunk}")?;
                }
            }
        }
        writeln!(w, " │")?;
    }
    writeln!(w, " └{}", "─".repeat(W - 1))?;

    // ── Full connection table ───────────────────────────────────────────────
    writeln!(
        w,
        "\n ┌─[ ALL CONNECTIONS  total:{} ]{}",
        snap.connections.len(),
        "─".repeat(W.saturating_sub(30))
    )?;
    writeln!(w, " │  {:<6}  {:<17}  {:<5}  {:<20}  {:<6}  {:<20}  {:<6}  {:<12}  {:<9}  {:<9}  {:<4}  {:<4}",
        "PID","PROCESS","PROTO","LOCAL ADDR","L.PORT","REMOTE ADDR","R.PORT",
        "STATE","USER","UID","RXQ","TXQ")?;
    writeln!(w, " │  {}", "·".repeat(W - 4))?;

    for c in &snap.connections {
        let pid = c.pid.map(|p| p.to_string()).unwrap_or("-".into());
        let proc = c.process_name.as_deref().unwrap_or("-");
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
        let user = c.username.as_deref().unwrap_or("-");
        writeln!(w, " │  {:<6}  {:<17}  {:<5}  {:<20}  {:<6}  {:<20}  {:<6}  {:<12}  {:<9}  {:<9}  {:<4}  {:<4}",
            pid, trunc(proc,17), c.protocol.as_str(),
            c.local_addr, c.local_port, remote, rport,
            c.state, user, c.uid, c.rx_queue, c.tx_queue)?;
        if let Some(exe) = &c.exe_path {
            if !exe.is_empty() {
                writeln!(w, " │       exe: {exe}")?;
            }
        }
        if let Some(cmd) = &c.cmdline {
            if !cmd.is_empty() && cmd.as_str() != proc {
                for (i, chunk) in wrap(cmd, W - 16).iter().enumerate() {
                    if i == 0 {
                        writeln!(w, " │       cmd: {chunk}")?;
                    } else {
                        writeln!(w, " │            {chunk}")?;
                    }
                }
            }
        }
    }
    writeln!(w, " └{}", "─".repeat(W - 1))?;

    writeln!(w, "\n  end-of-sample #{n}  │  {ts}")?;
    writeln!(w, "{}\n", "─".repeat(W))?;
    w.flush()?;
    Ok(())
}

// ─── entry point ─────────────────────────────────────────────────────────────

pub fn run(output_path: &str, interval_ms: u64, running: Arc<AtomicBool>) -> Result<()> {
    let interval = Duration::from_millis(interval_ms);
    let interval_s = interval_ms as f64 / 1000.0;

    eprintln!(
        "netmon log-mode  →  '{output_path}'  │  interval={interval_s:.1}s  │  Ctrl-C to stop"
    );

    let mut collector = Collector::new();
    let mut sample = 0u64;

    // Write file header
    {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(output_path)?;
        let mut bw = BufWriter::new(file);
        writeln!(bw, "# netmon monitoring log")?;
        writeln!(
            bw,
            "# started  : {}",
            Local::now().format("%Y-%m-%d %H:%M:%S %Z")
        )?;
        writeln!(bw, "# output   : {output_path}")?;
        writeln!(bw, "# interval : {interval_s:.1}s")?;
        writeln!(bw, "# host     : {}", hostname())?;
        bw.flush()?;
    }

    while running.load(Ordering::SeqCst) {
        sample += 1;
        let snap = collector.collect();

        {
            let file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(output_path)?;
            let mut bw = BufWriter::new(file);
            write_report(&mut bw, &snap, sample, interval_s)?;
        }

        eprintln!(
            "[#{sample:>4}] conns:{:>5}  procs:{:>4}  rx:{:>14}  tx:{:>14}",
            snap.stats.total,
            snap.procs.len(),
            fr(snap.stats.total_rx_bps),
            fr(snap.stats.total_tx_bps)
        );

        // sleep in 100ms chunks so we respond to stop quickly
        let ticks = (interval.as_millis() / 100).max(1) as u64;
        for _ in 0..ticks {
            if !running.load(Ordering::SeqCst) {
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    eprintln!("\nnetmon: stopped after {sample} samples. Log → '{output_path}'");
    Ok(())
}

fn hostname() -> String {
    std::fs::read_to_string("/etc/hostname")
        .unwrap_or_default()
        .trim()
        .to_string()
}

/// Same as `run` but accepts a pre-configured `Collector` (e.g. with eBPF table attached).
pub fn run_with_collector(
    output_path: &str,
    interval_ms: u64,
    running: Arc<AtomicBool>,
    mut collector: Collector,
) -> Result<()> {
    let interval = Duration::from_millis(interval_ms);
    let interval_s = interval_ms as f64 / 1000.0;

    eprintln!(
        "netmon log-mode  →  '{output_path}'  │  interval={interval_s:.1}s  │  Ctrl-C to stop"
    );

    let mut sample = 0u64;

    {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(output_path)?;
        let mut bw = BufWriter::new(file);
        writeln!(bw, "# netmon monitoring log")?;
        writeln!(
            bw,
            "# started  : {}",
            Local::now().format("%Y-%m-%d %H:%M:%S %Z")
        )?;
        writeln!(bw, "# output   : {output_path}")?;
        writeln!(bw, "# interval : {interval_s:.1}s")?;
        writeln!(bw, "# ebpf     : {}", if collector.ebpf_table.is_some() { "yes" } else { "no" })?;
        writeln!(bw, "# host     : {}", hostname())?;
        bw.flush()?;
    }

    while running.load(Ordering::SeqCst) {
        sample += 1;
        let snap = collector.collect();

        {
            let file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(output_path)?;
            let mut bw = BufWriter::new(file);
            write_report(&mut bw, &snap, sample, interval_s)?;

            // If eBPF is active, append a per-process IP breakdown table.
            if snap.procs.iter().any(|p| !p.ip_traffic.is_empty()) {
                writeln!(bw, "\n  ── eBPF per-process IP traffic ──")?;
                for proc in &snap.procs {
                    if proc.ip_traffic.is_empty() {
                        continue;
                    }
                    writeln!(
                        bw,
                        "  pid={:<6} {}",
                        proc.pid, proc.name
                    )?;
                    for ip in &proc.ip_traffic {
                        writeln!(
                            bw,
                            "    {:>42}:{:<5}  rx/s={:>10}  tx/s={:>10}  total_rx={:>12}  total_tx={:>12}",
                            ip.remote_addr,
                            ip.remote_port,
                            fb(ip.rx_bytes_delta),
                            fb(ip.tx_bytes_delta),
                            fb(ip.rx_bytes_total),
                            fb(ip.tx_bytes_total),
                        )?;
                    }
                }
                writeln!(bw)?;
            }
        }

        eprintln!(
            "[#{sample:>4}] conns:{:>5}  procs:{:>4}  rx:{:>14}  tx:{:>14}",
            snap.stats.total,
            snap.procs.len(),
            fr(snap.stats.total_rx_bps),
            fr(snap.stats.total_tx_bps)
        );

        let ticks = (interval.as_millis() / 100).max(1) as u64;
        for _ in 0..ticks {
            if !running.load(Ordering::SeqCst) {
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    eprintln!("\nnetmon: stopped after {sample} samples. Log → '{output_path}'");
    Ok(())
}
