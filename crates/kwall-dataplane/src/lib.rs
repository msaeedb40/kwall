pub mod events;
pub mod manager;
pub mod maps;

pub use events::EventHub;
pub use manager::DataplaneManager;
pub use maps::DataplaneState;

#[cfg(test)]
mod tests {
    use super::*;
    use kwall_ebpf_common::{
        EndpointIdentity, PacketAction, PolicyKey, PolicyValue, SecurityEvent, SecurityEventType,
    };

    #[test]
    fn test_dataplane_manager_lifecycle() {
        let mut dm = DataplaneManager::new();
        assert!(!dm.is_initialized());
        dm.init().expect("Initialization failed");
        assert!(dm.is_initialized());

        dm.attach_interface("eth0").expect("Attach failed");
        dm.attach_interface("kw_pri0").expect("Attach failed");
        assert_eq!(dm.attached_interfaces().len(), 2);

        dm.detach_interface("eth0").expect("Detach failed");
        assert_eq!(dm.attached_interfaces().len(), 1);
        assert_eq!(dm.attached_interfaces()[0], "kw_pri0");
    }

    #[test]
    fn test_dataplane_state_maps() {
        let mut state = DataplaneState::new();

        // Register pod endpoint
        let ep = EndpointIdentity {
            identity_id: 1042,
            namespace_id: 1,
            pod_uid_hash: 0xDEADBEEF,
            ifindex: 4,
            ipv4: 0x0A000005, // 10.0.0.5
            ipv6: [0; 16],
            flags: 0,
        };
        state.insert_endpoint(0x0A000005, ep);
        assert_eq!(state.endpoint_count(), 1);
        assert_eq!(state.get_endpoint(0x0A000005).unwrap().identity_id, 1042);

        // Add firewall policy
        let pol_key = PolicyKey {
            src_identity: 1042,
            dst_identity: 1043,
            dst_port: 80,
            protocol: 6,
            direction: 0,
        };
        let pol_val = PolicyValue {
            action: PacketAction::Pass as u32,
            policy_id: 501,
            priority: 10,
            rate_limit_pps: 0,
        };
        state.insert_policy(pol_key, pol_val);
        assert_eq!(state.policy_count(), 1);
        assert_eq!(state.get_policy(&pol_key).unwrap().policy_id, 501);

        // Blacklist test
        assert!(!state.is_blacklisted(0xC0A80101));
        state.add_blacklist_ip(0xC0A80101);
        assert!(state.is_blacklisted(0xC0A80101));
        assert!(state.remove_blacklist_ip(0xC0A80101));
        assert!(!state.is_blacklisted(0xC0A80101));
    }

    #[tokio::test]
    async fn test_event_hub_streaming() {
        let hub = EventHub::new(16);
        let mut flow_rx = hub.subscribe_flows();
        let mut sec_rx = hub.subscribe_security_events();

        // Test flow event dispatch & reception
        let flow_event = kwall_ebpf_common::FlowEvent::default();
        hub.dispatch_flow(flow_event);
        let received_flow = flow_rx.recv().await.expect("Failed to receive flow event");
        assert_eq!(received_flow.protocol, 0);

        // Test security event dispatch & reception
        let sec_event = SecurityEvent {
            timestamp_ns: 1000,
            event_type: SecurityEventType::PortScan as u32,
            severity: 3,
            identity_id: 1042,
            pid: 1234,
            uid: 0,
            gid: 0,
            comm: [0; 16],
            extra_data: [0; 8],
        };

        hub.dispatch_security_event(sec_event);
        let received = sec_rx.recv().await.expect("Failed to receive security event");
        assert_eq!(received.event_type, SecurityEventType::PortScan as u32);
        assert_eq!(received.identity_id, 1042);
    }
}
