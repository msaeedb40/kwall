//! # OCI Bundle & Cgroup Path Resolution Engine
//!
//! Parses standard OCI runtime specifications (`config.json`) and resolves cgroup v1/v2
//! filesystem hierarchies directly from container runtime bundles upon allocation.
//! Allows KWALL to bind container security contexts and cgroup identifiers before
//! Kubernetes API Informer discovery syncs.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use thiserror::Error;

/// Errors occurring during OCI bundle parsing or cgroup resolution.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum OciResolutionError {
    #[error("OCI bundle configuration '{0}' not found")]
    ConfigNotFound(PathBuf),

    #[error("Failed to parse OCI config JSON: {0}")]
    ParseError(String),

    #[error("Missing linux cgroupsPath in OCI specification")]
    MissingCgroupPath,

    #[error("Failed to resolve cgroup filesystem path: {0}")]
    CgroupPathResolutionFailed(String),
}

/// Linux capability set defined in OCI runtime spec.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OciCapabilities {
    #[serde(default)]
    pub bounding: Vec<String>,
    #[serde(default)]
    pub effective: Vec<String>,
    #[serde(default)]
    pub inheritable: Vec<String>,
    #[serde(default)]
    pub permitted: Vec<String>,
    #[serde(default)]
    pub ambient: Vec<String>,
}

/// Linux process definition inside OCI runtime spec.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OciProcessSpec {
    pub terminal: Option<bool>,
    pub user: Option<OciUserSpec>,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default)]
    pub env: Vec<String>,
    #[serde(default)]
    pub cwd: String,
    pub capabilities: Option<OciCapabilities>,
}

/// User and group UID/GID in OCI runtime spec.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OciUserSpec {
    pub uid: u32,
    pub gid: u32,
    pub additional_gids: Option<Vec<u32>>,
}

/// Linux specific runtime configuration in OCI spec.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OciLinuxSpec {
    #[serde(rename = "cgroupsPath")]
    pub cgroups_path: Option<String>,
    pub namespaces: Option<Vec<OciNamespaceSpec>>,
}

/// Linux namespace specification in OCI spec.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OciNamespaceSpec {
    #[serde(rename = "type")]
    pub ns_type: String,
    pub path: Option<String>,
}

/// Top-level OCI runtime bundle specification (`config.json`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OciBundleConfig {
    #[serde(rename = "ociVersion")]
    pub oci_version: String,
    pub process: Option<OciProcessSpec>,
    pub root: Option<OciRootSpec>,
    pub hostname: Option<String>,
    pub linux: Option<OciLinuxSpec>,
    pub annotations: Option<HashMap<String, String>>,
}

/// Root filesystem specification in OCI spec.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OciRootSpec {
    pub path: String,
    pub readonly: Option<bool>,
}

/// Resolved container cgroup and security attribution context.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolvedContainerCgroupContext {
    pub container_id: String,
    pub pod_uid: Option<String>,
    pub pod_namespace: Option<String>,
    pub pod_name: Option<String>,
    pub cgroup_id: u64,
    pub raw_cgroup_path: String,
    pub host_cgroup_dir: PathBuf,
    pub is_cgroup_v2: bool,
    pub is_rootless: bool,
    pub readonly_rootfs: bool,
    pub entrypoint_binary: Option<String>,
    pub entrypoint_args: Vec<String>,
    pub run_as_user: u32,
}

/// Standard cgroup v1 and v2 root mounts on Linux.
pub const CGROUP_V2_MOUNT: &str = "/sys/fs/cgroup";
pub const CGROUP_V1_SYSTEMD_MOUNT: &str = "/sys/fs/cgroup/systemd";

/// OCI Bundle and Cgroup Resolver.
pub struct OciCgroupResolver {
    cgroup_root: PathBuf,
    is_v2: bool,
}

impl Default for OciCgroupResolver {
    fn default() -> Self {
        // Detect cgroup v2: /sys/fs/cgroup/cgroup.controllers exists on cgroup v2 systems
        let v2_controllers = Path::new(CGROUP_V2_MOUNT).join("cgroup.controllers");
        let is_v2 = v2_controllers.exists();
        let root = if is_v2 {
            PathBuf::from(CGROUP_V2_MOUNT)
        } else {
            PathBuf::from(CGROUP_V1_SYSTEMD_MOUNT)
        };

        Self::new(root, is_v2)
    }
}

impl OciCgroupResolver {
    /// Creates a resolver with specified cgroup root and version flag.
    pub fn new(cgroup_root: impl Into<PathBuf>, is_v2: bool) -> Self {
        Self {
            cgroup_root: cgroup_root.into(),
            is_v2,
        }
    }

    /// Parses an OCI bundle `config.json` string and resolves the cgroup attribution context.
    pub fn resolve_from_config_json(
        &self,
        container_id: &str,
        config_json_content: &str,
    ) -> Result<ResolvedContainerCgroupContext, OciResolutionError> {
        let config: OciBundleConfig = serde_json::from_str(config_json_content)
            .map_err(|e| OciResolutionError::ParseError(e.to_string()))?;

        let linux = config.linux.ok_or(OciResolutionError::MissingCgroupPath)?;
        let raw_cgroup_path = linux
            .cgroups_path
            .ok_or(OciResolutionError::MissingCgroupPath)?;

        // Extract metadata from OCI annotations (standard Kubernetes containerd/CRI-O annotations)
        let mut pod_uid = None;
        let mut pod_namespace = None;
        let mut pod_name = None;

        if let Some(ref annotations) = config.annotations {
            pod_uid = annotations
                .get("io.kubernetes.pod.uid")
                .or_else(|| annotations.get("io.kubernetes.cri.pod-uid"))
                .cloned();
            pod_namespace = annotations
                .get("io.kubernetes.pod.namespace")
                .or_else(|| annotations.get("io.kubernetes.cri.pod-namespace"))
                .cloned();
            pod_name = annotations
                .get("io.kubernetes.pod.name")
                .or_else(|| annotations.get("io.kubernetes.cri.pod-name"))
                .cloned();
        }

        // If not in annotations, parse from systemd slice path
        if pod_uid.is_none() {
            let parsed = kwall_workload::parse_cgroup_path(&raw_cgroup_path);
            if let Some(uid) = parsed.pod_uid {
                pod_uid = Some(uid.to_string());
            }
        }

        // Formulate host directory path
        let relative_path = raw_cgroup_path.trim_start_matches('/');
        let host_cgroup_dir = self.cgroup_root.join(relative_path);

        // Derive cgroup ID: in production this is the directory inode; for deterministic resolution use hash
        let cgroup_id = self.derive_cgroup_id(container_id, &raw_cgroup_path);

        let readonly_rootfs = config
            .root
            .as_ref()
            .and_then(|r| r.readonly)
            .unwrap_or(false);

        let mut entrypoint_binary = None;
        let mut entrypoint_args = Vec::new();
        let mut run_as_user = 0;

        if let Some(ref proc) = config.process {
            if let Some(first) = proc.args.first() {
                entrypoint_binary = Some(first.clone());
            }
            entrypoint_args = proc.args.clone();
            if let Some(ref user) = proc.user {
                run_as_user = user.uid;
            }
        }

        Ok(ResolvedContainerCgroupContext {
            container_id: container_id.to_string(),
            pod_uid,
            pod_namespace,
            pod_name,
            cgroup_id,
            raw_cgroup_path,
            host_cgroup_dir,
            is_cgroup_v2: self.is_v2,
            is_rootless: run_as_user != 0,
            readonly_rootfs,
            entrypoint_binary,
            entrypoint_args,
            run_as_user,
        })
    }

    /// Derives a consistent, non-zero 64-bit cgroup identifier.
    fn derive_cgroup_id(&self, container_id: &str, cgroup_path: &str) -> u64 {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        container_id.hash(&mut hasher);
        cgroup_path.hash(&mut hasher);
        let id = hasher.finish();
        if id == 0 {
            1
        } else {
            id
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolve_oci_bundle_containerd_format() {
        let resolver = OciCgroupResolver::new("/sys/fs/cgroup", true);

        let oci_json = r#"{
            "ociVersion": "1.0.2-dev",
            "process": {
                "user": { "uid": 10001, "gid": 10001 },
                "args": ["/app/payment-service", "--port=8080"],
                "env": ["PATH=/usr/local/bin:/usr/bin", "PORT=8080"],
                "cwd": "/app",
                "capabilities": {
                    "bounding": ["CAP_NET_BIND_SERVICE"],
                    "effective": ["CAP_NET_BIND_SERVICE"]
                }
            },
            "root": {
                "path": "rootfs",
                "readonly": true
            },
            "linux": {
                "cgroupsPath": "/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod7b9c7b9c_1234_5678_9abc_def012345678.slice/cri-containerd-a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2.scope"
            },
            "annotations": {
                "io.kubernetes.pod.uid": "7b9c7b9c-1234-5678-9abc-def012345678",
                "io.kubernetes.pod.namespace": "production",
                "io.kubernetes.pod.name": "payment-frontend-pod"
            }
        }"#;

        let ctx = resolver
            .resolve_from_config_json("a1b2c3d4e5f6a1b2", oci_json)
            .unwrap();

        assert_eq!(ctx.container_id, "a1b2c3d4e5f6a1b2");
        assert_eq!(
            ctx.pod_uid.as_deref(),
            Some("7b9c7b9c-1234-5678-9abc-def012345678")
        );
        assert_eq!(ctx.pod_namespace.as_deref(), Some("production"));
        assert_eq!(ctx.pod_name.as_deref(), Some("payment-frontend-pod"));
        assert!(ctx.readonly_rootfs);
        assert!(ctx.is_rootless);
        assert_eq!(ctx.run_as_user, 10001);
        assert_eq!(
            ctx.entrypoint_binary.as_deref(),
            Some("/app/payment-service")
        );
        assert_eq!(ctx.entrypoint_args.len(), 2);
        assert_ne!(ctx.cgroup_id, 0);
        assert!(ctx.is_cgroup_v2);
    }

    #[test]
    fn test_missing_cgroup_path_returns_error() {
        let resolver = OciCgroupResolver::new("/sys/fs/cgroup", true);
        let invalid_json = r#"{
            "ociVersion": "1.0.2",
            "linux": {}
        }"#;

        let result = resolver.resolve_from_config_json("cnt-invalid", invalid_json);
        assert_eq!(result.unwrap_err(), OciResolutionError::MissingCgroupPath);
    }
}
