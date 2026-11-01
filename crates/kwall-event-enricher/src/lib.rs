//! # kwall-event-enricher
//!
//! Enriches kernel-level security telemetry with Kubernetes workloads, metadata, and SPIFFE IDs.

pub mod enricher;

pub use enricher::{EnrichedEvent, EnrichedWorkloadContext, EventEnricher};

#[cfg(test)]
mod tests {
    use super::*;
    use kwall_core::types::{ContainerId, EventSource, NodeId, PodUid, Severity};
    use kwall_event_router::event::{EventPayload, KwallEvent, NetworkEventData};
    use kwall_kubernetes::cache::{KubernetesCache, PodMetadata};
    use std::collections::HashMap;
    use std::sync::Arc;

    #[test]
    fn test_network_event_enrichment() {
        let cache = Arc::new(KubernetesCache::new());

        let pod = PodMetadata {
            pod_uid: PodUid::new("uid-payment"),
            pod_name: "payment-api-7b8f".to_string(),
            namespace: "finance".to_string(),
            node_name: "node-1".to_string(),
            service_account: "payment-sa".to_string(),
            pod_ip: Some("10.244.2.15".to_string()),
            host_ip: Some("192.168.1.50".to_string()),
            labels: HashMap::new(),
            workload_owner: Some("Deployment/payment-api".to_string()),
            container_ids: vec![ContainerId::new("cid-pay-1")],
        };
        cache.insert_pod(pod);

        let enricher = EventEnricher::new(cache, "cluster.local");

        let raw_event = KwallEvent {
            version: 1,
            event_id: 101,
            timestamp_ns: 2000000,
            node_id: NodeId(1),
            severity: Severity::Info,
            source: EventSource::Xdp,
            payload: EventPayload::Network(NetworkEventData {
                src_ip: "10.244.2.15".to_string(),
                dst_ip: "1.1.1.1".to_string(),
                src_port: 48990,
                dst_port: 53,
                protocol: 17,
                action: "allow".to_string(),
                packet_len: 74,
                ifindex: 2,
            }),
        };

        let enriched = enricher.enrich(raw_event);

        assert!(enriched.src_workload.is_some());
        let src = enriched.src_workload.unwrap();
        assert_eq!(src.pod_name, "payment-api-7b8f");
        assert_eq!(src.namespace, "finance");
        assert_eq!(
            src.workload_owner,
            Some("Deployment/payment-api".to_string())
        );
        assert_eq!(
            src.spiffe_id,
            "spiffe://cluster.local/ns/finance/sa/payment-sa"
        );

        // External IP destination should not match cluster pods
        assert!(enriched.dst_workload.is_none());
    }
}
