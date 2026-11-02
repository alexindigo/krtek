//! Local TCP and UDP delivery from raw application IP packets.
//!
//! Policy and physical-network selection belong to the consumer's injected
//! authority. This library must never select a network or fall back to an
//! unprepared socket. It has no Android or daemon dependencies.
//!
//! Only complete, unfragmented IPv4/IPv6 TCP and UDP packets are accepted.
//! Fragments, IPv6 extension headers, ICMP and other protocols are refused.

pub mod packet;

pub use packet::{Flow, Transport};
