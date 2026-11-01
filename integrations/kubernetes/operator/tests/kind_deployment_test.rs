//! Automated integration tests validating 3-node KinD cluster deployment manifests and scenario configurations.

use serde::Deserialize;
use std::fs;
use std::path::Path;

#[derive(Debug, Deserialize)]
struct KindClusterConfig {
    kind: String,
    name: String,
    nodes: Vec<KindNodeConfig>,
}

#[derive(Debug, Deserialize)]
struct KindNodeConfig {
    role: String,
    #[serde(rename = "extraMounts")]
    extra_mounts: Option<Vec<KindExtraMount>>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct KindExtraMount {
    #[serde(rename = "hostPath")]
    host_path: String,
    #[serde(rename = "containerPath")]
    container_path: String,
}

#[test]
fn test_kind_3node_cluster_config() {
    let manifest_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("deployments/kind/kind-cluster.yaml");

    assert!(
        manifest_path.exists(),
        "kind-cluster.yaml should exist at {manifest_path:?}"
    );

    let content = fs::read_to_string(&manifest_path).expect("Failed to read kind-cluster.yaml");
    let config: KindClusterConfig =
        serde_yaml::from_str(&content).expect("Failed to parse kind-cluster.yaml");

    assert_eq!(config.kind, "Cluster");
    assert_eq!(config.name, "kwall-cluster");

    // Must have exactly 3 nodes: 1 control-plane and 2 workers
    assert_eq!(
        config.nodes.len(),
        3,
        "KinD cluster must contain exactly 3 nodes"
    );

    let control_plane_nodes: Vec<_> = config
        .nodes
        .iter()
        .filter(|n| n.role == "control-plane")
        .collect();
    let worker_nodes: Vec<_> = config.nodes.iter().filter(|n| n.role == "worker").collect();

    assert_eq!(
        control_plane_nodes.len(),
        1,
        "Must have exactly 1 control-plane node"
    );
    assert_eq!(worker_nodes.len(), 2, "Must have exactly 2 worker nodes");

    // Verify eBPF mounts on every node
    for (i, node) in config.nodes.iter().enumerate() {
        let mounts = node
            .extra_mounts
            .as_ref()
            .expect("Node must have extraMounts configured");

        let has_btf = mounts.iter().any(|m| m.container_path == "/sys/kernel/btf");
        let has_bpf = mounts.iter().any(|m| m.container_path == "/sys/fs/bpf");
        let has_cgroup = mounts.iter().any(|m| m.container_path == "/sys/fs/cgroup");

        assert!(
            has_btf,
            "Node {i} ({}) must mount /sys/kernel/btf for CO-RE",
            node.role
        );
        assert!(
            has_bpf,
            "Node {i} ({}) must mount /sys/fs/bpf for map persistence",
            node.role
        );
        assert!(
            has_cgroup,
            "Node {i} ({}) must mount /sys/fs/cgroup for cgroup isolation",
            node.role
        );
    }
}

#[test]
fn test_kind_scenario_manifests_exist() {
    let base = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("deployments/kind");

    let setup_script = base.join("setup-cluster.sh");
    let build_script = base.join("build-and-load.sh");
    let deploy_script = base.join("deploy-kwall.sh");
    let teardown_script = base.join("teardown-cluster.sh");
    let workloads = base.join("scenarios/workloads.yaml");
    let policies = base.join("scenarios/policies.yaml");
    let sim_script = base.join("scenarios/simulate-threats.sh");

    assert!(setup_script.exists(), "setup-cluster.sh must exist");
    assert!(build_script.exists(), "build-and-load.sh must exist");
    assert!(deploy_script.exists(), "deploy-kwall.sh must exist");
    assert!(teardown_script.exists(), "teardown-cluster.sh must exist");
    assert!(workloads.exists(), "workloads.yaml must exist");
    assert!(policies.exists(), "policies.yaml must exist");
    assert!(sim_script.exists(), "simulate-threats.sh must exist");

    let workloads_yaml = fs::read_to_string(&workloads).unwrap();
    assert!(workloads_yaml.contains("kwall-cluster-worker"));
    assert!(workloads_yaml.contains("kwall-cluster-worker2"));

    let policies_yaml = fs::read_to_string(&policies).unwrap();
    assert!(policies_yaml.contains("KwallNetworkPolicy"));
    assert!(policies_yaml.contains("KwallRuntimePolicy"));
}
