use kwall_api::{KWALLNetworkPolicy, KWALLSecurityPolicy, PolicyStatus};
use kwall_common::time::current_time_ns;
use kwall_common::Result;
use tracing::info;

pub struct PolicyReconciler;

impl PolicyReconciler {
    pub fn reconcile_network_policy(policy: &KWALLNetworkPolicy) -> Result<PolicyStatus> {
        let name = policy.metadata.name.as_deref().unwrap_or("unnamed");
        let ns = policy.metadata.namespace.as_deref().unwrap_or("default");

        info!("Reconciling KWALLNetworkPolicy: {}/{}", ns, name);

        let ingress_count = policy.spec.ingress.len();
        let egress_count = policy.spec.egress.len();

        info!(
            "Policy {}/{}: parsed {} ingress rules and {} egress rules",
            ns, name, ingress_count, egress_count
        );

        Ok(PolicyStatus {
            state: "Active".to_string(),
            active_nodes: 1,
            last_applied_time: Some(format!("{}", current_time_ns())),
            error_message: None,
        })
    }

    pub fn reconcile_security_policy(policy: &KWALLSecurityPolicy) -> Result<PolicyStatus> {
        let name = policy.metadata.name.as_deref().unwrap_or("unnamed");
        let ns = policy.metadata.namespace.as_deref().unwrap_or("default");

        info!("Reconciling KWALLSecurityPolicy: {}/{}", ns, name);

        Ok(PolicyStatus {
            state: "Enforced".to_string(),
            active_nodes: 1,
            last_applied_time: Some(format!("{}", current_time_ns())),
            error_message: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kwall_api::{EndpointSelector, KWALLNetworkPolicySpec};
    use kube::core::ObjectMeta;
    use std::collections::BTreeMap;

    #[test]
    fn test_network_policy_reconciliation() {
        let mut labels = BTreeMap::new();
        labels.insert("app".into(), "web".into());

        let policy = KWALLNetworkPolicy {
            metadata: ObjectMeta {
                name: Some("web-policy".into()),
                namespace: Some("default".into()),
                ..Default::default()
            },
            spec: KWALLNetworkPolicySpec {
                endpoint_selector: EndpointSelector {
                    match_labels: labels,
                    match_namespaces: vec!["default".into()],
                },
                ingress: Vec::new(),
                egress: Vec::new(),
            },
            status: None,
        };

        let status = PolicyReconciler::reconcile_network_policy(&policy).unwrap();
        assert_eq!(status.state, "Active");
        assert_eq!(status.active_nodes, 1);
        assert!(status.last_applied_time.is_some());
    }
}
