//! build.rs
//!
//! Checks whether src/netmon-ebpf.o exists and sets a cfg flag so
//! ebpf_loader.rs can conditionally include_bytes! it.
//!
//! We use `cargo:rustc-cfg=ebpf_obj` (a plain cfg, not a Cargo feature) to
//! avoid the "unexpected cfg condition value" warning that Cargo emits for
//! unknown feature names.

use std::path::Path;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=src/netmon-ebpf.o");

    if Path::new("src/netmon-ebpf.o").exists() {
        // Activate include_bytes! branch in ebpf_loader.rs
        println!("cargo:rustc-cfg=ebpf_obj");
        println!("cargo:warning=eBPF object found — building with full eBPF support");
    } else {
        println!(
            "cargo:warning=src/netmon-ebpf.o not found — \
             run `cargo xtask build-ebpf` then rebuild to enable eBPF capture."
        );
    }
}
