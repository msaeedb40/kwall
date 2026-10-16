pub mod anomaly;
pub mod ddos;
pub mod supply_chain;

pub use anomaly::PortScanDetector;
pub use ddos::DdosMitigator;
pub use supply_chain::WorkloadIntegrityGuard;

pub struct SecurityEngine {
    pub ddos: DdosMitigator,
    pub port_scan: PortScanDetector,
    pub integrity: WorkloadIntegrityGuard,
}

impl SecurityEngine {
    pub fn new(max_syn: u32, max_udp: u32, port_threshold: usize, allowed_binaries: Vec<String>) -> Self {
        Self {
            ddos: DdosMitigator::new(max_syn, max_udp),
            port_scan: PortScanDetector::new(port_threshold),
            integrity: WorkloadIntegrityGuard::new(allowed_binaries),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kwall_ebpf_common::SecurityEventType;

    #[test]
    fn test_ddos_syn_flood_detection() {
        let mut ddos = DdosMitigator::new(3, 100);
        let src_ip = 0xC0A8010A; // 192.168.1.10

        assert!(ddos.record_syn(src_ip).is_none());
        assert!(ddos.record_syn(src_ip).is_none());
        assert!(ddos.record_syn(src_ip).is_none());

        // 4th SYN exceeds threshold of 3
        let alert = ddos.record_syn(src_ip).expect("Expected SYN flood alert");
        assert_eq!(alert.event_type, SecurityEventType::SynFlood as u32);
        assert!(ddos.blacklisted_ips().contains(&src_ip));
    }

    #[test]
    fn test_port_scan_detection() {
        let mut scanner = PortScanDetector::new(3);
        let identity = 1042;

        assert!(scanner.record_connection(identity, 80).is_none());
        assert!(scanner.record_connection(identity, 443).is_none());

        let alert = scanner.record_connection(identity, 8080).expect("Expected port scan alert");
        assert_eq!(alert.event_type, SecurityEventType::PortScan as u32);
        assert_eq!(alert.identity_id, identity);
    }

    #[test]
    fn test_workload_binary_verification() {
        let guard = WorkloadIntegrityGuard::new(vec!["allowed-app".into()]);
        assert!(guard.verify_executable("/usr/bin/allowed-app", 100).is_none());

        let alert = guard
            .verify_executable("/tmp/xmrig-miner", 101)
            .expect("Expected untrusted binary alert");
        assert_eq!(alert.event_type, SecurityEventType::MaliciousProcessExec as u32);
        assert_eq!(alert.pid, 101);
    }
}
