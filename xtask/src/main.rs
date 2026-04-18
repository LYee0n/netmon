//! xtask — project build automation
//!
//! Usage:
//!   cargo xtask build-ebpf [--release]
//!   cargo xtask build       [--release]   # builds both eBPF + host
//!   cargo xtask run         [--release]   # build + run (requires root)
//!
//! The eBPF crate must be compiled for `bpfel-unknown-none` which requires
//! nightly Rust and the `rust-src` component:
//!   rustup toolchain install nightly
//!   rustup component add rust-src --toolchain nightly

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use std::{
    env,
    path::PathBuf,
    process::{Command, ExitStatus},
};

#[derive(Parser)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Compile only the eBPF kernel program to target/bpfel-unknown-none/
    BuildEbpf {
        #[arg(long)]
        release: bool,
    },
    /// Compile eBPF program then the host binary
    Build {
        #[arg(long)]
        release: bool,
    },
    /// Build everything then run netmon (needs root for eBPF loading)
    Run {
        #[arg(long)]
        release: bool,
        /// Extra args forwarded to `netmon`
        #[arg(last = true)]
        args: Vec<String>,
    },
}

fn workspace_root() -> PathBuf {
    // xtask lives in <workspace>/xtask — go up one level.
    let mut p = env::current_exe().unwrap();
    // target/{debug|release}/xtask  →  workspace
    for _ in 0..3 {
        p.pop();
    }
    p
}

fn run_cmd(mut cmd: Command) -> Result<ExitStatus> {
    println!("$ {:?}", cmd);
    let status = cmd.status().context("failed to spawn command")?;
    if !status.success() {
        bail!("command failed with status: {status}");
    }
    Ok(status)
}

fn build_ebpf(release: bool) -> Result<()> {
    let root = workspace_root();
    let mut cmd = Command::new("cargo");
    cmd.current_dir(&root)
        .args(["+nightly", "build", "-p", "netmon-ebpf"])
        .args(["--target", "bpfel-unknown-none"])
        .args(["-Z", "build-std=core"])
        .env("CARGO_CFG_BPF_TARGET", "1");
    if release {
        cmd.arg("--release");
    }
    run_cmd(cmd)?;

    // Copy the compiled object to a well-known path that build.rs embeds.
    let profile = if release { "release" } else { "debug" };
    let src = root
        .join("target")
        .join("bpfel-unknown-none")
        .join(profile)
        .join("netmon-ebpf");
    let dst = root.join("src").join("netmon-ebpf.o");
    std::fs::copy(&src, &dst)
        .with_context(|| format!("copy {src:?} → {dst:?}"))?;
    println!("eBPF object written to {dst:?}");
    Ok(())
}

fn build_host(release: bool) -> Result<()> {
    let root = workspace_root();
    let mut cmd = Command::new("cargo");
    cmd.current_dir(&root)
        .args(["build", "-p", "netmon"]);
    if release {
        cmd.arg("--release");
    }
    run_cmd(cmd)?;
    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::BuildEbpf { release } => build_ebpf(release),
        Cmd::Build { release } => {
            build_ebpf(release)?;
            build_host(release)
        }
        Cmd::Run { release, args } => {
            build_ebpf(release)?;
            build_host(release)?;
            let root = workspace_root();
            let profile = if release { "release" } else { "debug" };
            let bin = root.join("target").join(profile).join("netmon");
            let mut cmd = Command::new("sudo");
            cmd.arg(bin).args(args);
            run_cmd(cmd)?;
            Ok(())
        }
    }
}
