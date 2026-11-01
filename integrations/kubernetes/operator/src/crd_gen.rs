//! Automatic CustomResourceDefinition (CRD) manifest generation for KWALL.

use kube::CustomResourceExt;
use kwall_policy::crd::{KwallNetworkPolicy, KwallRuntimePolicy};
use std::fs;
use std::path::Path;

/// Generates YAML strings for all KWALL custom resource definitions.
pub fn generate_crd_yamls() -> Result<(String, String), serde_yaml::Error> {
    let network_crd = KwallNetworkPolicy::crd();
    let runtime_crd = KwallRuntimePolicy::crd();

    let network_yaml = serde_yaml::to_string(&network_crd)?;
    let runtime_yaml = serde_yaml::to_string(&runtime_crd)?;

    Ok((network_yaml, runtime_yaml))
}

/// Writes CRD YAML files to the specified output directory.
pub fn write_crds_to_directory(output_dir: impl AsRef<Path>) -> std::io::Result<()> {
    let dir = output_dir.as_ref();
    fs::create_dir_all(dir)?;

    let (net_yaml, rt_yaml) =
        generate_crd_yamls().map_err(|e| std::io::Error::other(e.to_string()))?;

    let net_path = dir.join("kwall.io_networkpolicies.yaml");
    let rt_path = dir.join("kwall.io_runtimepolicies.yaml");

    fs::write(&net_path, net_yaml)?;
    fs::write(&rt_path, rt_yaml)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crd_generation() {
        let (net_yaml, rt_yaml) = generate_crd_yamls().expect("CRD generation should succeed");
        assert!(net_yaml.contains("kind: CustomResourceDefinition"));
        assert!(net_yaml.contains("name: kwallnetworkpolicies.kwall.io"));
        assert!(rt_yaml.contains("name: kwallruntimepolicies.kwall.io"));
    }
}
