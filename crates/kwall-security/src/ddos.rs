use kwall_ebpf_common::{SecurityEvent, SecurityEventType, Severity};
use std::collections::HashMap;
use tracing::warn;

pub struct DdosMitigator {
    max_syn_per_sec: u32,
    max_udp_per_sec: u32,
    syn_counters: HashMap<u32, u32>,
    udp_counters: HashMap<u32, u32>,
    blacklisted_ips: Vec<u32>,
}

impl DdosMitigator {
    pub fn new(max_syn_per_sec: u32, max_udp_per_sec: u32) -> Self {
        Self {
            max_syn_per_sec,
            max_udp_per_sec,
            syn_counters: HashMap::new(),
            udp_counters: HashMap::new(),
            blacklisted_ips: Vec::new(),
        }
    }

    pub fn record_syn(&mut self, src_ip: u32) -> Option<SecurityEvent> {
        let count = self.syn_counters.entry(src_ip).or_insert(0);
        *count += 1;

        if *count > self.max_syn_per_sec && !self.blacklisted_ips.contains(&src_ip) {
            warn!(
                "DDoS: SYN flood detected from IP {:x} (count: {} > max: {})",
                src_ip, *count, self.max_syn_per_sec
            );
            self.blacklisted_ips.push(src_ip);

            let mut extra_data = [0u64; 8];
            extra_data[0] = src_ip as u64;
            let event = SecurityEvent {
                event_type: SecurityEventType::SynFlood as u32,
                severity: Severity::High as u32,
                extra_data,
                ..Default::default()
            };
            return Some(event);
        }
        None
    }

    pub fn record_udp(&mut self, src_ip: u32) -> Option<SecurityEvent> {
        let count = self.udp_counters.entry(src_ip).or_insert(0);
        *count += 1;

        if *count > self.max_udp_per_sec && !self.blacklisted_ips.contains(&src_ip) {
            warn!(
                "DDoS: UDP flood detected from IP {:x} (count: {} > max: {})",
                src_ip, *count, self.max_udp_per_sec
            );
            self.blacklisted_ips.push(src_ip);

            let mut extra_data = [0u64; 8];
            extra_data[0] = src_ip as u64;
            let event = SecurityEvent {
                event_type: SecurityEventType::UdpFlood as u32,
                severity: Severity::High as u32,
                extra_data,
                ..Default::default()
            };
            return Some(event);
        }
        None
    }

    pub fn reset_window(&mut self) {
        self.syn_counters.clear();
        self.udp_counters.clear();
    }

    pub fn blacklisted_ips(&self) -> &[u32] {
        &self.blacklisted_ips
    }
}
