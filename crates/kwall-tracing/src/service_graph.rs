//! Automated service topology graph construction, edge latency metrics, and error tracking.
//!
//! Reconstructs a real-time directed service dependency graph from L4/L7 flow observations,
//! tracking p50, p95, and p99 round-trip latencies, throughput, and error rates.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::RwLock;

use serde::{Deserialize, Serialize};

/// Discrete node in the service graph representing a microservice workload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceNode {
    pub id: String,
    pub name: String,
    pub namespace: String,
    pub ips: Vec<Ipv4Addr>,
}

/// Dynamic communication metrics recorded on a directed communication edge.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EdgeMetrics {
    pub request_count: u64,
    pub error_count: u64,
    pub total_bytes: u64,
    #[serde(skip_serializing)]
    latencies_us: Vec<u64>,
}

impl EdgeMetrics {
    /// Computes latency percentiles (p50, p95, p99) in microseconds.
    #[must_use]
    pub fn percentiles(&self) -> (u64, u64, u64) {
        if self.latencies_us.is_empty() {
            return (0, 0, 0);
        }

        let mut sorted = self.latencies_us.clone();
        sorted.sort_unstable();

        let len = sorted.len();
        let p50 = sorted[((len * 50) / 100).min(len - 1)];
        let p95 = sorted[((len * 95) / 100).min(len - 1)];
        let p99 = sorted[((len * 99) / 100).min(len - 1)];

        (p50, p95, p99)
    }

    /// Records a new request sample on this edge.
    pub fn record(&mut self, latency_us: u64, bytes: u64, is_error: bool) {
        self.request_count += 1;
        self.total_bytes += bytes;
        if is_error {
            self.error_count += 1;
        }

        // Keep a bounded sliding window of the latest 500 samples for percentile calculations
        if self.latencies_us.len() >= 500 {
            self.latencies_us.remove(0);
        }
        self.latencies_us.push(latency_us);
    }
}

/// Directed communication edge representing traffic from a source service to a target service.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceEdge {
    pub source_id: String,
    pub target_id: String,
    pub target_port: u16,
    pub protocol: String,
    pub metrics: EdgeMetrics,
    pub p50_us: u64,
    pub p95_us: u64,
    pub p99_us: u64,
}

/// Directed graph representation of the cluster service communication topology.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ServiceTopology {
    pub nodes: HashMap<String, ServiceNode>,
    pub edges: Vec<ServiceEdge>,
}

pub type EdgeKey = (String, String, u16);
pub type EdgeValue = (String, EdgeMetrics);

/// Thread-safe builder constructing and updating the cluster service communication graph.
pub struct ServiceGraphBuilder {
    nodes: RwLock<HashMap<String, ServiceNode>>,
    ip_to_service: RwLock<HashMap<Ipv4Addr, String>>,
    edges: RwLock<HashMap<EdgeKey, EdgeValue>>,
}

impl Default for ServiceGraphBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl ServiceGraphBuilder {
    /// Creates a new empty ServiceGraphBuilder.
    #[must_use]
    pub fn new() -> Self {
        Self {
            nodes: RwLock::new(HashMap::new()),
            ip_to_service: RwLock::new(HashMap::new()),
            edges: RwLock::new(HashMap::new()),
        }
    }

    /// Registers or updates a service workload node.
    pub fn register_service(&self, name: &str, namespace: &str, ips: &[Ipv4Addr]) {
        let id = format!("{namespace}/{name}");
        let node = ServiceNode {
            id: id.clone(),
            name: name.to_string(),
            namespace: namespace.to_string(),
            ips: ips.to_vec(),
        };

        {
            let mut nodes = self.nodes.write().unwrap();
            nodes.insert(id.clone(), node);
        }

        {
            let mut ip_map = self.ip_to_service.write().unwrap();
            for &ip in ips {
                ip_map.insert(ip, id.clone());
            }
        }
    }

    /// Records an observed network interaction between two endpoints.
    pub fn record_flow(
        &self,
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        dst_port: u16,
        protocol: &str,
        latency_us: u64,
        bytes: u64,
        is_error: bool,
    ) {
        let ip_map = self.ip_to_service.read().unwrap();
        let src_id = ip_map
            .get(&src_ip)
            .cloned()
            .unwrap_or_else(|| format!("external/{src_ip}"));
        let dst_id = ip_map
            .get(&dst_ip)
            .cloned()
            .unwrap_or_else(|| format!("external/{dst_ip}"));
        drop(ip_map);

        let mut edges = self.edges.write().unwrap();
        let key = (src_id, dst_id, dst_port);
        let entry = edges
            .entry(key)
            .or_insert_with(|| (protocol.to_string(), EdgeMetrics::default()));
        entry.1.record(latency_us, bytes, is_error);
    }

    /// Exports the current complete service dependency topology snapshot.
    #[must_use]
    pub fn get_topology(&self) -> ServiceTopology {
        let nodes = self.nodes.read().unwrap().clone();
        let edges_map = self.edges.read().unwrap();

        let mut edges = Vec::with_capacity(edges_map.len());
        for ((src, dst, port), (proto, metrics)) in edges_map.iter() {
            let (p50, p95, p99) = metrics.percentiles();
            edges.push(ServiceEdge {
                source_id: src.clone(),
                target_id: dst.clone(),
                target_port: *port,
                protocol: proto.clone(),
                metrics: metrics.clone(),
                p50_us: p50,
                p95_us: p95,
                p99_us: p99,
            });
        }

        ServiceTopology { nodes, edges }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_service_graph_construction_and_percentiles() {
        let builder = ServiceGraphBuilder::new();

        let frontend_ip = Ipv4Addr::new(10, 244, 1, 10);
        let backend_ip = Ipv4Addr::new(10, 244, 2, 20);

        builder.register_service("frontend", "prod", &[frontend_ip]);
        builder.register_service("backend", "prod", &[backend_ip]);

        // Record a series of latency samples
        builder.record_flow(frontend_ip, backend_ip, 8080, "HTTP", 100, 1024, false);
        builder.record_flow(frontend_ip, backend_ip, 8080, "HTTP", 200, 2048, false);
        builder.record_flow(frontend_ip, backend_ip, 8080, "HTTP", 500, 512, true);

        let topo = builder.get_topology();
        assert_eq!(topo.nodes.len(), 2);
        assert_eq!(topo.edges.len(), 1);

        let edge = &topo.edges[0];
        assert_eq!(edge.source_id, "prod/frontend");
        assert_eq!(edge.target_id, "prod/backend");
        assert_eq!(edge.metrics.request_count, 3);
        assert_eq!(edge.metrics.error_count, 1);
        assert_eq!(edge.metrics.total_bytes, 3584);
        assert!(edge.p50_us > 0);
    }
}
