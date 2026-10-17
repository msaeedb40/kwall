use crate::types::{EndpointSelector, PolicyStatus};
use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(CustomResource, Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[kube(
    group = "kwall.io",
    version = "v1alpha1",
    kind = "KWALLRuntimePolicy",
    plural = "kwallruntimepolicies",
    namespaced,
    status = "PolicyStatus"
)]
pub struct KWALLRuntimePolicySpec {
    pub endpoint_selector: EndpointSelector,
    #[serde(default)]
    pub process_rules: Vec<RuntimeProcessRule>,
    #[serde(default)]
    pub syscall_rules: Vec<RuntimeSyscallRule>,
    #[serde(default)]
    pub file_integrity_rules: Vec<RuntimeFileIntegrityRule>,
    #[serde(default)]
    pub privilege_rules: Option<RuntimePrivilegeRule>,
    #[serde(default = "default_runtime_action")]
    pub action: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RuntimeProcessRule {
    #[serde(default)]
    pub allowed_executables: Vec<String>,
    #[serde(default)]
    pub blocked_executables: Vec<String>,
    #[serde(default)]
    pub block_untrusted_paths: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RuntimeSyscallRule {
    #[serde(default)]
    pub blocked_syscalls: Vec<String>,
    #[serde(default)]
    pub audit_syscalls: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RuntimeFileIntegrityRule {
    pub watched_paths: Vec<String>,
    #[serde(default)]
    pub read_only_paths: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Default)]
pub struct RuntimePrivilegeRule {
    #[serde(default)]
    pub block_privilege_escalation: bool,
    #[serde(default)]
    pub allowed_capabilities: Vec<String>,
    #[serde(default)]
    pub blocked_capabilities: Vec<String>,
    #[serde(default)]
    pub block_namespace_escape: bool,
}

fn default_runtime_action() -> String {
    "Block".to_string()
}
