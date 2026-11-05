//! An ICMP socket backed by a smoltcp ICMP socket.

use smoltcp::wire::IpAddress;
use std::{io, net::Ipv4Addr, sync::Arc};
use tokio::sync::{Notify, mpsc};

/// An ICMP socket backed by a smoltcp ICMP socket.
///
/// Send raw ICMP packets (type, code, checksum, id, seq, payload) and
/// receive matching replies.
pub struct SmoltcpIcmpSocket {
    send_tx: Option<mpsc::Sender<(Vec<u8>, IpAddress)>>,
    notify: Arc<Notify>,
    pub(super) storage: super::Storage,
}

impl SmoltcpIcmpSocket {
    /// Create a socket over the channel wired to an active smoltcp ICMP socket.
    pub(super) fn new(send_tx: mpsc::Sender<(Vec<u8>, IpAddress)>, notify: Arc<Notify>) -> Self {
        Self {
            send_tx: Some(send_tx),
            notify,
            storage: None,
        }
    }

    /// Send a raw ICMP packet to the given IPv4 destination.
    pub async fn send_to_v4(&self, data: &[u8], dest: Ipv4Addr) -> io::Result<()> {
        self.send_raw(data, IpAddress::Ipv4(dest)).await
    }

    /// Send a raw ICMP packet to the given destination.
    pub async fn send_raw(&self, data: &[u8], dest: IpAddress) -> io::Result<()> {
        self.send_tx
            .as_ref()
            .expect("live ICMP socket")
            .send((data.to_vec(), dest))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "socket closed"))?;
        self.notify.notify_one();
        Ok(())
    }
}

impl Drop for SmoltcpIcmpSocket {
    fn drop(&mut self) {
        // Close before waking, including on a multithreaded runtime.
        self.send_tx.take();
        self.notify.notify_one();
    }
}
