//! netmon — Network Traffic Monitor
//!
//! Three modes:
//!   tui          Interactive full-screen TUI (default)
//!   log          Continuously append beautified reports to a file
//!   prometheus   Export Prometheus metrics over HTTP
//!
//! eBPF mode (requires root + kernel 4.9+):
//!   Pass `--ebpf` to any subcommand to enable kernel-level per-(pid,ip)
//!   traffic capture via kprobes.  Falls back silently to /proc mode if
//!   eBPF is unavailable.
mod collector;
mod ebpf_loader;
mod logger;
mod prometheus;
mod tui;
mod types;

use anyhow::Result;
use clap::{Parser, Subcommand};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

#[derive(Parser, Debug)]
#[command(
    name = "netmon",
    version = "0.3.0",
    about = "Network traffic monitor: TUI • log-file • Prometheus exporter\n\
             Add --ebpf to any subcommand for kernel-level per-IP traffic capture."
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Cmd>,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Interactive TUI (default when no subcommand given)
    Tui {
        /// Refresh interval ms
        #[arg(short, long, default_value = "1000")]
        interval: u64,
        /// Filter display to PID
        #[arg(short, long)]
        pid: Option<u32>,
        /// Filter display to port
        #[arg(long)]
        port: Option<u16>,
        /// Show only LISTEN sockets
        #[arg(short, long)]
        listen: bool,
        /// Enable eBPF kernel-level per-IP traffic capture (requires root)
        #[arg(long)]
        ebpf: bool,
    },
    /// Append formatted monitoring reports to a file continuously
    Log {
        /// Output file (appended)
        #[arg(short, long, default_value = "netmon.log")]
        output: String,
        /// Collection interval ms
        #[arg(short, long, default_value = "5000")]
        interval: u64,
        /// Enable eBPF kernel-level per-IP traffic capture (requires root)
        #[arg(long)]
        ebpf: bool,
    },
    /// Serve Prometheus /metrics endpoint over HTTP
    Prometheus {
        /// HTTP listen port
        #[arg(short, long, default_value = "9090")]
        port: u16,
        /// Collection interval ms
        #[arg(short, long, default_value = "5000")]
        interval: u64,
        /// Enable eBPF kernel-level per-IP traffic capture (requires root)
        #[arg(long)]
        ebpf: bool,
    },
}

fn make_collector(use_ebpf: bool, poll_interval_ms: u64) -> collector::Collector {
    let mut c = collector::Collector::new();
    if use_ebpf {
        c.ebpf_table = ebpf_loader::start(Duration::from_millis(poll_interval_ms));
        if c.ebpf_table.is_some() {
            eprintln!("netmon: eBPF traffic capture active");
        } else {
            eprintln!("netmon: eBPF unavailable, using /proc fallback");
        }
    }
    c
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    let running = Arc::new(AtomicBool::new(true));
    install_signal_handler(running.clone());

    match cli.command.unwrap_or(Cmd::Tui {
        interval: 1000,
        pid: None,
        port: None,
        listen: false,
        ebpf: false,
    }) {
        Cmd::Tui { interval, pid, port, listen, ebpf } => {
            tui::run(interval, pid, port, listen, ebpf)?;
        }
        Cmd::Log { output, interval, ebpf } => {
            let collector = make_collector(ebpf, interval);
            logger::run_with_collector(&output, interval, running, collector)?;
        }
        Cmd::Prometheus { port, interval, ebpf } => {
            let collector = make_collector(ebpf, interval);
            prometheus::run_with_collector(port, interval, running, collector)?;
        }
    }
    Ok(())
}

fn install_signal_handler(running: Arc<AtomicBool>) {
    std::thread::Builder::new()
        .name("signal-handler".into())
        .spawn(move || {
            #[cfg(unix)]
            unsafe {
                let mut set: libc::sigset_t = std::mem::zeroed();
                libc::sigemptyset(&mut set);
                libc::sigaddset(&mut set, libc::SIGINT);
                libc::sigaddset(&mut set, libc::SIGTERM);
                libc::pthread_sigmask(libc::SIG_BLOCK, &set, std::ptr::null_mut());
                let mut sig = 0i32;
                libc::sigwait(&set, &mut sig);
                eprintln!("\nnetmon: caught signal {sig}, shutting down…");
                running.store(false, Ordering::SeqCst);
            }
            #[cfg(not(unix))]
            {
                loop {
                    std::thread::sleep(std::time::Duration::from_secs(3600));
                }
            }
        })
        .expect("failed to spawn signal handler thread");
}
