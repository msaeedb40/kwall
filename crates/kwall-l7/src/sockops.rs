//! eBPF Socket Operations (`sockops`) controller and `sk_msg` zero-copy redirection manager.
//!
//! Provides userspace tracking of socket lifecycle transitions, TCP connection RTT metrics,
//! and socket map redirection coordination for zero-copy proxying.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::RwLock;

use serde::{Deserialize, Serialize};

/// 4-tuple key identifying a TCP flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SockFlowKey {
    pub src_ip: Ipv4Addr,
    pub src_port: u16,
    pub dst_ip: Ipv4Addr,
    pub dst_port: u16,
}

impl SockFlowKey {
    #[must_use]
    pub fn new(src_ip: Ipv4Addr, src_port: u16, dst_ip: Ipv4Addr, dst_port: u16) -> Self {
        Self {
            src_ip,
            src_port,
            dst_ip,
            dst_port,
        }
    }

    /// Returns the reverse flow key (for reply direction).
    #[must_use]
    pub fn reverse(&self) -> Self {
        Self {
            src_ip: self.dst_ip,
            src_port: self.dst_port,
            dst_ip: self.src_ip,
            dst_port: self.src_port,
        }
    }
}

/// TCP connection state transition monitored via `sockops`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SockOpsOpcode {
    /// Server accepted connection (BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB).
    PassiveEstablished,
    /// Client completed three-way handshake (BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB).
    ActiveEstablished,
    /// TCP RTT estimate updated (BPF_SOCK_OPS_RTT_CB).
    RttUpdate,
    /// Connection state changed (BPF_SOCK_OPS_STATE_CB).
    StateChange,
}

/// State metadata associated with an established socket.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SocketFlowEntry {
    pub flow_key: SockFlowKey,
    pub established_timestamp_ns: u64,
    pub last_activity_timestamp_ns: u64,
    pub rtt_us: u32,
    pub redirected: bool,
    pub peer_flow: Option<SockFlowKey>,
}

/// Statistics for sockops acceleration and sk_msg redirection.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct SockOpsStats {
    pub total_connections_monitored: u64,
    pub active_connections: usize,
    pub redirected_pairs: usize,
    pub total_redirected_bytes: u64,
}

/// Userspace controller managing BPF sockops state transitions and sk_msg redirection maps.
pub struct SockOpsController {
    flows: RwLock<HashMap<SockFlowKey, SocketFlowEntry>>,
    redirect_map: RwLock<HashMap<SockFlowKey, SockFlowKey>>,
    total_connections: AtomicU64,
    total_redirected_bytes: AtomicU64,
}

impl Default for SockOpsController {
    fn default() -> Self {
        Self::new()
    }
}

impl SockOpsController {
    /// Creates a new SockOpsController.
    #[must_use]
    pub fn new() -> Self {
        Self {
            flows: RwLock::new(HashMap::new()),
            redirect_map: RwLock::new(HashMap::new()),
            total_connections: AtomicU64::new(0),
            total_redirected_bytes: AtomicU64::new(0),
        }
    }

    /// Handles a connection establishment event reported by the eBPF `sockops` hook.
    pub fn on_connection_established(
        &self,
        flow: SockFlowKey,
        op: SockOpsOpcode,
        rtt_us: u32,
        timestamp_ns: u64,
    ) {
        self.total_connections.fetch_add(1, Ordering::Relaxed);
        let mut flows = self.flows.write().unwrap();
        flows.insert(
            flow,
            SocketFlowEntry {
                flow_key: flow,
                established_timestamp_ns: timestamp_ns,
                last_activity_timestamp_ns: timestamp_ns,
                rtt_us,
                redirected: false,
                peer_flow: None,
            },
        );
        let _ = op;
    }

    /// Configures zero-copy socket redirection (`sk_msg`) between two paired flows.
    pub fn configure_redirection(&self, flow_a: SockFlowKey, flow_b: SockFlowKey) {
        let mut redirects = self.redirect_map.write().unwrap();
        redirects.insert(flow_a, flow_b);
        redirects.insert(flow_b, flow_a);

        let mut flows = self.flows.write().unwrap();
        if let Some(entry) = flows.get_mut(&flow_a) {
            entry.redirected = true;
            entry.peer_flow = Some(flow_b);
        }
        if let Some(entry) = flows.get_mut(&flow_b) {
            entry.redirected = true;
            entry.peer_flow = Some(flow_a);
        }
    }

    /// Records forwarded payload bytes across redirected sockets.
    pub fn record_redirected_bytes(&self, bytes: u64) {
        self.total_redirected_bytes
            .fetch_add(bytes, Ordering::Relaxed);
    }

    /// Removes a closed connection.
    pub fn on_connection_closed(&self, flow: &SockFlowKey) {
        let mut flows = self.flows.write().unwrap();
        flows.remove(flow);

        let mut redirects = self.redirect_map.write().unwrap();
        if let Some(peer) = redirects.remove(flow) {
            redirects.remove(&peer);
        }
    }

    /// Updates RTT metrics for an active connection.
    pub fn update_rtt(&self, flow: &SockFlowKey, rtt_us: u32, timestamp_ns: u64) {
        let mut flows = self.flows.write().unwrap();
        if let Some(entry) = flows.get_mut(flow) {
            entry.rtt_us = rtt_us;
            entry.last_activity_timestamp_ns = timestamp_ns;
        }
    }

    /// Retrieves aggregate runtime statistics.
    #[must_use]
    pub fn get_stats(&self) -> SockOpsStats {
        let flows = self.flows.read().unwrap();
        let redirects = self.redirect_map.read().unwrap();

        SockOpsStats {
            total_connections_monitored: self.total_connections.load(Ordering::Relaxed),
            active_connections: flows.len(),
            redirected_pairs: redirects.len() / 2,
            total_redirected_bytes: self.total_redirected_bytes.load(Ordering::Relaxed),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sockops_connection_lifecycle() {
        let controller = SockOpsController::new();
        let flow1 = SockFlowKey::new(
            Ipv4Addr::new(10, 244, 1, 10),
            45000,
            Ipv4Addr::new(10, 244, 2, 20),
            8080,
        );
        let flow2 = flow1.reverse();

        // 1. Connection established
        controller.on_connection_established(
            flow1,
            SockOpsOpcode::ActiveEstablished,
            150,
            1_000_000_000,
        );
        controller.on_connection_established(
            flow2,
            SockOpsOpcode::PassiveEstablished,
            150,
            1_000_000_000,
        );

        let stats = controller.get_stats();
        assert_eq!(stats.active_connections, 2);
        assert_eq!(stats.total_connections_monitored, 2);

        // 2. Configure zero-copy redirection
        controller.configure_redirection(flow1, flow2);
        let stats_after_redir = controller.get_stats();
        assert_eq!(stats_after_redir.redirected_pairs, 1);

        // 3. Record bytes
        controller.record_redirected_bytes(4096);
        assert_eq!(controller.get_stats().total_redirected_bytes, 4096);

        // 4. Close connection
        controller.on_connection_closed(&flow1);
        let stats_after_close = controller.get_stats();
        assert_eq!(stats_after_close.active_connections, 1);
        assert_eq!(stats_after_close.redirected_pairs, 0);
    }
}
