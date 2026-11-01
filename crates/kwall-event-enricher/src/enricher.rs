//! Workload and network context enricher.

use kwall_event_router::event::{EventPayload, KwallEvent};
use kwall_identity::SpiffeId;
use kwall_kubernetes::cache::{KubernetesCache, PodMetadata};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;

/// Enriched contextual workload details attached to security telemetry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnrichedWorkloadContext {
    pub pod_name: String,
    pub namespace: String,
    pub workload_owner: Option<String>,
    pub service_account: String,
    pub spiffe_id: String,
    pub labels: HashMap<String, String>,
}

/// Fully enriched security event containing both kernel telemetry and Kubernetes context.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrichedEvent {
    pub base_event: KwallEvent,
    pub src_workload: Option<EnrichedWorkloadContext>,
    pub dst_workload: Option<EnrichedWorkloadContext>,
}

/// Dynamic event enricher.
pub struct EventEnricher {
    cache: Arc<KubernetesCache>,
    trust_domain: String,
}

impl EventEnricher {
    pub fn new(cache: Arc<KubernetesCache>, trust_domain: impl Into<String>) -> Self {
        Self {
            cache,
            trust_domain: trust_domain.into(),
        }
    }

    /// Enriches a KwallEvent using cached Kubernetes state.
    pub fn enrich(&self, event: KwallEvent) -> EnrichedEvent {
        let mut src_workload = None;
        let mut dst_workload = None;

        match &event.payload {
            EventPayload::Network(net) => {
                // Enrich source pod by IP
                if let Some(src_pod) = self.cache.get_by_ip(&net.src_ip) {
                    src_workload = Some(self.build_context(&src_pod));
                }

                // Enrich destination pod by IP
                if let Some(dst_pod) = self.cache.get_by_ip(&net.dst_ip) {
                    dst_workload = Some(self.build_context(&dst_pod));
                }
            }
            EventPayload::Process(proc) => {
                // Enrich process event by container ID or pod UID if mapped
                let cid = kwall_core::types::ContainerId::new(&proc.comm);
                if let Some(pod) = self.cache.get_by_container_id(&cid) {
                    src_workload = Some(self.build_context(&pod));
                }
            }
            _ => {}
        }

        EnrichedEvent {
            base_event: event,
            src_workload,
            dst_workload,
        }
    }

    fn build_context(&self, pod: &PodMetadata) -> EnrichedWorkloadContext {
        let spiffe = SpiffeId::new(&self.trust_domain, &pod.namespace, &pod.service_account);
        EnrichedWorkloadContext {
            pod_name: pod.pod_name.clone(),
            namespace: pod.namespace.clone(),
            workload_owner: pod.workload_owner.clone(),
            service_account: pod.service_account.clone(),
            spiffe_id: spiffe.to_string(),
            labels: pod.labels.clone(),
        }
    }
}
