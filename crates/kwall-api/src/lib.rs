pub mod ddos;
pub mod flow;
pub mod policy;
pub mod security;
pub mod types;

pub use ddos::*;
pub use flow::*;
pub use policy::*;
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
        assert_eq!(yamls.len(), 4);
        let crd_dir = Path::new("../../api/crd/kwall.io");
        if crd_dir.exists() {
            for (filename, content) in &yamls {
                let target = crd_dir.join(filename);
                fs::write(&target, content).expect("Failed to write CRD yaml");
            }
        }
        for (name, yaml) in yamls {
            assert!(yaml.contains("apiVersion: apiextensions.k8s.io/v1"));
            assert!(yaml.contains("kwall.io"));
            println!("Generated CRD for {}", name);
        }
    }
}
