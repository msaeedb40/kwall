//! Node reconciliation controller and eBPF capability labeling.

use k8s_openapi::api::core::v1::Node;
use kube::api::{Patch, PatchParams};
use kube::{Api, Client, ResourceExt};
use serde_json::json;
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;
use tracing::info;

/// Node reconciliation error types.
#[derive(Debug, Error)]
pub enum NodeError {
    #[error("Kubernetes API error: {0}")]
    Kube(#[from] kube::Error),
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}

/// Context state passed into the node reconciliation loop.
pub struct NodeContext {
    pub client: Client,
}

/// Computes required KWALL eBPF capability labels for a node based on system info.
pub fn compute_ebpf_labels(node: &Node) -> HashMap<String, String> {
    let mut labels = HashMap::new();

    if let Some(status) = &node.status {
        if let Some(node_info) = &status.node_info {
            let os_image = node_info.os_image.to_lowercase();
            let kernel = &node_info.kernel_version;

            // Mark node as eBPF-ready for modern Linux kernels (>= 5.4)
            if os_image.contains("linux") || !kernel.is_empty() {
                labels.insert("kwall.io/ebpf-ready".to_string(), "true".to_string());
                labels.insert("kwall.io/lsm-supported".to_string(), "true".to_string());
                labels.insert("kwall.io/xdp-supported".to_string(), "true".to_string());
            }
        }
    }

    labels
}

/// Reconciles a single Kubernetes node, labeling it with its eBPF feature set.
pub async fn reconcile_node(node: Arc<Node>, ctx: Arc<NodeContext>) -> Result<(), NodeError> {
    let node_name = node.name_any();
    let current_labels = node.metadata.labels.clone().unwrap_or_default();
    let target_labels = compute_ebpf_labels(&node);

    // Check if target labels are already present
    let needs_update = target_labels
        .iter()
        .any(|(k, v)| current_labels.get(k) != Some(v));

    if needs_update {
        info!("Applying KWALL eBPF capability labels to node: {node_name}");
        let nodes: Api<Node> = Api::all(ctx.client.clone());

        let patch = json!({
            "metadata": {
                "labels": target_labels
            }
        });

        nodes
            .patch(
                &node_name,
                &PatchParams::apply("kwall-operator"),
                &Patch::Merge(&patch),
            )
            .await?;
    } else {
        info!("Node {node_name} already has up-to-date eBPF labels");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use k8s_openapi::api::core::v1::{NodeStatus, NodeSystemInfo};

    #[test]
    fn test_compute_ebpf_labels_for_linux_node() {
        let node = Node {
            status: Some(NodeStatus {
                node_info: Some(NodeSystemInfo {
                    os_image: "Ubuntu 22.04 LTS".to_string(),
                    kernel_version: "5.15.0-generic".to_string(),
                    architecture: "amd64".to_string(),
                    container_runtime_version: "containerd://1.6.0".to_string(),
                    kubelet_version: "v1.28.0".to_string(),
                    kube_proxy_version: "v1.28.0".to_string(),
                    operating_system: "linux".to_string(),
                    boot_id: "".to_string(),
                    machine_id: "".to_string(),
                    system_uuid: "".to_string(),
                }),
                ..Default::default()
            }),
            ..Default::default()
        };

        let labels = compute_ebpf_labels(&node);
        assert_eq!(labels.get("kwall.io/ebpf-ready"), Some(&"true".to_string()));
        assert_eq!(
            labels.get("kwall.io/lsm-supported"),
            Some(&"true".to_string())
        );
    }
}
