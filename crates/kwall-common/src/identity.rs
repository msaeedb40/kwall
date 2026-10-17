use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkloadIdentity {
    pub identity_id: u32,
    pub namespace: String,
    pub pod_name: String,
    pub pod_uid: String,
    pub service_account: String,
    pub labels: BTreeMap<String, String>,
    pub node_name: String,
    pub ips: Vec<String>,
}

impl WorkloadIdentity {
    pub fn new(
        identity_id: u32,
        namespace: impl Into<String>,
        pod_name: impl Into<String>,
        pod_uid: impl Into<String>,
        service_account: impl Into<String>,
        labels: BTreeMap<String, String>,
        node_name: impl Into<String>,
        ips: Vec<String>,
    ) -> Self {
        Self {
            identity_id,
            namespace: namespace.into(),
            pod_name: pod_name.into(),
            pod_uid: pod_uid.into(),
            service_account: service_account.into(),
            labels,
            node_name: node_name.into(),
            ips,
        }
    }
}
