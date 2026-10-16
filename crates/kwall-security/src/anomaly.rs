use std::collections::{HashMap, HashSet};
use kwall_ebpf_common::{SecurityEvent, SecurityEventType, Severity};
use tracing::warn;

pub struct PortScanDetector {
    threshold_distinct_ports: usize,
    probes_by_src: HashMap<u32, HashSet<u16>>,
}

impl PortScanDetector {
    pub fn new(threshold_distinct_ports: usize) -> Self {
        Self {
            threshold_distinct_ports,
            probes_by_src: HashMap::new(),
        }
    }

    pub fn record_connection(&mut self, src_identity: u32, dst_port: u16) -> Option<SecurityEvent> {
        let ports = self.probes_by_src.entry(src_identity).or_default();
        ports.insert(dst_port);

        if ports.len() >= self.threshold_distinct_ports {
            warn!(
                "Reconnaissance: Port scan detected from identity {} across {} distinct ports",
                src_identity,
                ports.len()
            );

            let mut event = SecurityEvent::default();
            event.identity_id = src_identity;
            event.event_type = SecurityEventType::PortScan as u32;
            event.severity = Severity::Medium as u32;
            event.extra_data[0] = ports.len() as u64;

            ports.clear();
            return Some(event);
        }
        None
    }
}
