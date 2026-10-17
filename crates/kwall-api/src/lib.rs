pub mod ddos;
pub mod flow;
pub mod policy;
pub mod runtime;
pub mod security;
pub mod types;

pub use ddos::*;
pub use flow::*;
pub use policy::*;
pub use runtime::*;
pub use security::*;
pub use types::*;

use kube::CustomResourceExt;

pub fn generate_crd_yamls() -> Result<Vec<(String, String)>, serde_yaml::Error> {
    let mut crds = Vec::new();

    let np = serde_yaml::to_string(&KWALLNetworkPolicy::crd())?;
    crds.push(("networkpolicies.yaml".to_string(), np));

    let sp = serde_yaml::to_string(&KWALLSecurityPolicy::crd())?;
    crds.push(("securitypolicies.yaml".to_string(), sp));

    let dp = serde_yaml::to_string(&KWALLDDoSPolicy::crd())?;
    crds.push(("ddospolicies.yaml".to_string(), dp));

    let rp = serde_yaml::to_string(&KWALLRuntimePolicy::crd())?;
    crds.push(("runtimepolicies.yaml".to_string(), rp));

    let fp = serde_yaml::to_string(&KWALLFlowPolicy::crd())?;
    crds.push(("flowpolicies.yaml".to_string(), fp));

    Ok(crds)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::Path;

    #[test]
    fn test_crd_generation() {
        let yamls = generate_crd_yamls().expect("Failed to generate CRD yamls");
        assert_eq!(yamls.len(), 5);
        let crd_dirs = [
            Path::new("../../api/crd/kwall.io"),
            Path::new("../../deploy/helm/kwall/crds"),
        ];
        for dir in crd_dirs {
            if dir.exists() {
                for (filename, content) in &yamls {
                    let target = dir.join(filename);
                    fs::write(&target, content).expect("Failed to write CRD yaml");
                }
            }
        }
        for (name, yaml) in yamls {
            assert!(yaml.contains("apiVersion: apiextensions.k8s.io/v1"));
            assert!(yaml.contains("kwall.io"));
            println!("Generated CRD for {}", name);
        }
    }
}
