use kwall_ebpf_common::{
    ConntrackKey, ConntrackValue, EndpointIdentity, MetricsCounter, PolicyKey, PolicyValue,
    RateLimitKey, RateLimitValue,
};
use std::collections::HashMap;
use tracing::info;

#[derive(Debug, Default)]
pub struct DataplaneState {
    endpoints: HashMap<u32, EndpointIdentity>,
    policies: HashMap<PolicyKey, PolicyValue>,
    conntrack: HashMap<ConntrackKey, ConntrackValue>,
    blacklist: HashMap<u32, u8>,
    rate_limits: HashMap<RateLimitKey, RateLimitValue>,
    metrics: MetricsCounter,
}

impl DataplaneState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert_endpoint(&mut self, ip: u32, identity: EndpointIdentity) {
        info!(
            "Registering endpoint IP {:x} with identity {}",
            ip, identity.identity_id
        );
        self.endpoints.insert(ip, identity);
    }

    pub fn get_endpoint(&self, ip: u32) -> Option<&EndpointIdentity> {
        self.endpoints.get(&ip)
    }

    pub fn remove_endpoint(&mut self, ip: u32) -> Option<EndpointIdentity> {
        info!("Unregistering endpoint IP {:x}", ip);
        self.endpoints.remove(&ip)
    }

    pub fn endpoint_count(&self) -> usize {
        self.endpoints.len()
    }

    pub fn all_endpoints(&self) -> Vec<EndpointIdentity> {
        self.endpoints.values().copied().collect()
    }

    pub fn insert_policy(&mut self, key: PolicyKey, value: PolicyValue) {
        info!(
            "Inserting policy rule src={} dst={} port={} action={}",
            key.src_identity, key.dst_identity, key.dst_port, value.action
        );
        self.policies.insert(key, value);
    }

    pub fn get_policy(&self, key: &PolicyKey) -> Option<&PolicyValue> {
        self.policies.get(key)
    }

    pub fn remove_policy(&mut self, key: &PolicyKey) -> Option<PolicyValue> {
        self.policies.remove(key)
    }

    pub fn policy_count(&self) -> usize {
        self.policies.len()
    }

    pub fn all_policy_keys(&self) -> Vec<PolicyKey> {
        self.policies.keys().copied().collect()
    }

    pub fn add_blacklist_ip(&mut self, ip: u32) {
        info!("Adding IP {:x} to early-drop blacklist", ip);
        self.blacklist.insert(ip, 1);
    }

    pub fn remove_blacklist_ip(&mut self, ip: u32) -> bool {
        self.blacklist.remove(&ip).is_some()
    }

    pub fn is_blacklisted(&self, ip: u32) -> bool {
        self.blacklist.contains_key(&ip)
    }

    pub fn get_metrics(&self) -> MetricsCounter {
        self.metrics
    }

    pub fn clear_conntrack(&mut self) {
        info!("Flushing conntrack table");
        self.conntrack.clear();
    }

    pub fn insert_rate_limit(&mut self, key: RateLimitKey, value: RateLimitValue) {
        info!(
            "Setting rate limit for IP: {:?} max_tokens={} refill_rate={}",
            key.ip, value.max_tokens, value.refill_rate_per_sec
        );
        self.rate_limits.insert(key, value);
    }

    pub fn get_rate_limit(&self, key: &RateLimitKey) -> Option<&RateLimitValue> {
        self.rate_limits.get(key)
    }

    pub fn remove_rate_limit(&mut self, key: &RateLimitKey) -> Option<RateLimitValue> {
        self.rate_limits.remove(key)
    }

    pub fn rate_limit_count(&self) -> usize {
        self.rate_limits.len()
    }
}
