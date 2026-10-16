use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use crate::types::{EndpointSelector, PolicyStatus};

#[derive(CustomResource, Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[kube(
    group = "kwall.io",
    version = "v1alpha1",
    kind = "KWALLSecurityPolicy",
    plural = "kwallsecuritypolicies",
    namespaced,
    status = "PolicyStatus"
)]
pub struct KWALLSecurityPolicySpec {
    pub endpoint_selector: EndpointSelector,
    #[serde(default)]
    pub process_rules: Vec<ProcessRule>,
    #[serde(default)]
    pub syscall_rules: Vec<SyscallRule>,
    #[serde(default)]
    pub file_integrity_rules: Vec<FileIntegrityRule>,
    #[serde(default)]
    pub action: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ProcessRule {
    pub allowed_executables: Vec<String>,
    #[serde(default)]
    pub blocked_executables: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct SyscallRule {
    pub blocked_syscalls: Vec<String>,
    #[serde(default)]
    pub audit_syscalls: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct FileIntegrityRule {
    pub watched_paths: Vec<String>,
    #[serde(default)]
    pub read_only_paths: Vec<String>,
}
