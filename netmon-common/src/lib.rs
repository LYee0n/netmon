//! Types shared between the eBPF kernel program (`netmon-ebpf`) and the
//! userspace host (`netmon`).  Must compile under both `std` and `no_std`
//! (the eBPF target has no std).
//!
//! All structs are `#[repr(C)]` so the layout is identical on both sides
//! when they communicate through BPF maps.

#![cfg_attr(not(feature = "user"), no_std)]

// ─── Traffic event emitted per syscall from the eBPF probe ───────────────────

/// Direction of a traffic event.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    Rx = 0,
    Tx = 1,
}

/// Raw event written into the `EVENTS` perf/ring-buffer map by the eBPF side
/// and consumed by the userspace side.
///
/// Size: 4 + 4 + 4*4 + 4*4 + 2 + 2 + 1 + 3 pad = 48 bytes — fits easily in
/// one perf-event record.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct TrafficEvent {
    /// PID of the process that triggered the syscall.
    pub pid: u32,
    /// Number of bytes sent or received in this call.
    pub bytes: u32,
    /// IPv4 source address (network byte order), 0 for IPv6.
    pub src_ip4: u32,
    /// IPv4 destination address (network byte order), 0 for IPv6.
    pub dst_ip4: u32,
    /// IPv6 source address (16 bytes), zeroed for IPv4.
    pub src_ip6: [u8; 16],
    /// IPv6 destination address (16 bytes), zeroed for IPv4.
    pub dst_ip6: [u8; 16],
    /// Source port (host byte order).
    pub src_port: u16,
    /// Destination port (host byte order).
    pub dst_port: u16,
    /// Direction: 0 = Rx (inbound), 1 = Tx (outbound).
    pub direction: u8,
    /// Address family: 2 = AF_INET, 10 = AF_INET6.
    pub af: u8,
    pub _pad: [u8; 2],
}

// ─── Per-process aggregate stored in a BPF HashMap ───────────────────────────

/// Key for the `TRAFFIC` per-process summary map.
/// Keyed on (pid, remote_ip4 or remote_ip6, remote_port, af).
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TrafficKey {
    pub pid: u32,
    /// For AF_INET: last 4 bytes hold the IPv4 address, rest zeroed.
    /// For AF_INET6: full 16-byte address.
    pub remote_ip: [u8; 16],
    pub remote_port: u16,
    pub af: u8,
    pub _pad: u8,
}

/// Value stored in the `TRAFFIC` map — running byte totals per key.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct TrafficValue {
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    /// Process name (comm), null-terminated, max 15 chars + NUL.
    pub comm: [u8; 16],
}

// ─── std-only helpers ─────────────────────────────────────────────────────────

#[cfg(feature = "user")]
mod user_impls {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    impl TrafficKey {
        /// Decode the remote IP into a [`std::net::IpAddr`].
        pub fn remote_addr(&self) -> IpAddr {
            if self.af == 2 {
                // AF_INET — last 4 bytes
                let b = &self.remote_ip[12..16];
                IpAddr::V4(Ipv4Addr::new(b[0], b[1], b[2], b[3]))
            } else {
                IpAddr::V6(Ipv6Addr::from(self.remote_ip))
            }
        }
    }

    impl TrafficValue {
        /// Decode comm as a UTF-8 string, trimming the NUL terminator.
        pub fn comm_str(&self) -> &str {
            let end = self.comm.iter().position(|&b| b == 0).unwrap_or(16);
            std::str::from_utf8(&self.comm[..end]).unwrap_or("?")
        }
    }

    // SAFETY: Both structs are #[repr(C)], Copy, and contain only primitive
    // fields with no padding that could hold uninitialised bytes — they are
    // valid for any bit-pattern, satisfying aya's Pod contract.
    unsafe impl aya::Pod for TrafficKey {}
    unsafe impl aya::Pod for TrafficValue {}

    // Make TrafficKey usable as a HashMap key on the host side.
    impl std::hash::Hash for TrafficKey {
        fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
            self.pid.hash(state);
            self.remote_ip.hash(state);
            self.remote_port.hash(state);
            self.af.hash(state);
        }
    }
}