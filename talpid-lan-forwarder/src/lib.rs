//! Local TCP and UDP delivery from raw application IP packets.
//!
//! Policy and physical-network selection belong to the consumer's injected
//! authority. This library must never select a network or fall back to an
//! unprepared socket. It has no Android or daemon dependencies.
//!
//! Only complete, unfragmented IPv4/IPv6 TCP and UDP packets are accepted.
//! Fragments, IPv6 extension headers, ICMP and other protocols are refused.
//!
//! The authority triages `Local` or `Drop`, authorizes the original tuple and
//! prepares every physical socket off the owner task. Preparation failure never
//! connects an unbound socket. Grants accompany queued data through the final
//! synchronous `Forwarder::write_output` sink write, including WouldBlock
//! retries. `Forwarder::wait` observes internal progress only; select sink
//! writability separately while `Forwarder::has_output` is true.
//! Update authority inputs before signalling revalidation; join
//! `Forwarder::close_all` before acknowledging shutdown to the consumer.

pub mod authority;
mod forwarder;
pub mod packet;

pub use authority::{Disposition, LocalAuthority, Refused};
pub use forwarder::{Forwarder, Stats};
pub use packet::{Flow, Transport};
