use kwall_ebpf_common::{SecurityEvent, SecurityEventType, Severity};
use std::collections::HashMap;
use tracing::warn;

pub struct DnsThreatDetector {
    max_subdomain_length: usize,
    max_queries_per_window: usize,
    query_counts: HashMap<u32, usize>,
}

impl DnsThreatDetector {
    pub fn new(max_subdomain_length: usize, max_queries_per_window: usize) -> Self {
        Self {
            max_subdomain_length,
            max_queries_per_window,
            query_counts: HashMap::new(),
        }
    }

    pub fn inspect_query(
        &mut self,
        src_identity: u32,
        query_domain: &str,
    ) -> Option<SecurityEvent> {
        let count = self.query_counts.entry(src_identity).or_insert(0);
        *count += 1;

        // Check for DNS Tunneling (unusually long labels/subdomains encoding data)
        let has_long_subdomain = query_domain
            .split('.')
            .any(|part| part.len() >= self.max_subdomain_length);

        if has_long_subdomain {
            warn!(
                "DNS Threat: Suspected DNS tunneling in domain '{}' from identity {}",
                query_domain, src_identity
            );
            return Some(SecurityEvent {
                identity_id: src_identity,
                event_type: SecurityEventType::DnsTunneling as u32,
                severity: Severity::Critical as u32,
                ..Default::default()
            });
        }

        // Check for cryptomining pool domains
        if query_domain.contains("supportxmr")
            || query_domain.contains("xmrpool")
            || query_domain.contains("nanopool")
            || query_domain.contains("minexmr")
        {
            warn!(
                "DNS Threat: Cryptomining pool resolution '{}' from identity {}",
                query_domain, src_identity
            );
            return Some(SecurityEvent {
                identity_id: src_identity,
                event_type: SecurityEventType::Cryptomining as u32,
                severity: Severity::Critical as u32,
                ..Default::default()
            });
        }

        // Check for high-volume DNS flood
        if *count > self.max_queries_per_window {
            warn!(
                "DNS Threat: Excessive DNS query rate ({} queries) from identity {}",
                *count, src_identity
            );
            return Some(SecurityEvent {
                identity_id: src_identity,
                event_type: SecurityEventType::VolumetricDDoS as u32,
                severity: Severity::High as u32,
                ..Default::default()
            });
        }

        None
    }

    pub fn reset_window(&mut self) {
        self.query_counts.clear();
    }
}
