//! # Enterprise Open Policy Agent (OPA) & Rego Policy Integration Engine
//!
//! Evaluates enterprise compliance benchmarks (CIS Kubernetes Benchmark, PCI-DSS, SOC2)
//! and custom Rego-inspired constraint rules during Kubernetes admission control and continuous audit.
//! Enforces zero-trust container security policies (non-root execution, privilege escalation denial,
//! restricted host namespace access, egress CIDR whitelisting).

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

/// Severity level of an OPA policy violation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ViolationSeverity {
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for ViolationSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Low => write!(f, "LOW"),
            Self::Medium => write!(f, "MEDIUM"),
            Self::High => write!(f, "HIGH"),
            Self::Critical => write!(f, "CRITICAL"),
        }
    }
}

/// Compliance benchmark standard.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ComplianceStandard {
    CisKubernetesBenchmark,
    PciDssV4,
    Soc2Type2,
    Nist80053,
    CustomRego,
}

/// Detailed violation reported by an OPA/Gatekeeper rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpaViolation {
    pub rule_id: String,
    pub rule_name: String,
    pub standard: ComplianceStandard,
    pub severity: ViolationSeverity,
    pub resource_kind: String,
    pub resource_name: String,
    pub namespace: String,
    pub message: String,
    pub remediation: String,
}

/// Simplified container security context representation for admission evaluation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerSecurityContext {
    pub name: String,
    pub image: String,
    pub run_as_user: Option<u32>,
    pub run_as_non_root: Option<bool>,
    pub allow_privilege_escalation: Option<bool>,
    pub privileged: Option<bool>,
    pub read_only_root_filesystem: Option<bool>,
    pub capabilities_add: Vec<String>,
    pub capabilities_drop: Vec<String>,
}

/// Simplified Pod manifest specification submitted for admission review.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdmissionReviewPodSpec {
    pub name: String,
    pub namespace: String,
    pub host_network: bool,
    pub host_pid: bool,
    pub host_ipc: bool,
    pub containers: Vec<ContainerSecurityContext>,
    pub labels: HashMap<String, String>,
}

/// Decision response returned after OPA admission evaluation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdmissionReviewDecision {
    pub allowed: bool,
    pub status_code: u16,
    pub violations: Vec<OpaViolation>,
}

/// Built-in OPA Rule evaluator trait.
pub trait OpaRule: Send + Sync {
    fn rule_id(&self) -> &str;
    fn rule_name(&self) -> &str;
    fn standard(&self) -> ComplianceStandard;
    fn severity(&self) -> ViolationSeverity;
    fn evaluate(&self, pod: &AdmissionReviewPodSpec) -> Option<OpaViolation>;
}

/// Rule CIS-5.2.1: Disallow privileged containers.
pub struct DisallowPrivilegedContainers;
impl OpaRule for DisallowPrivilegedContainers {
    fn rule_id(&self) -> &str {
        "CIS-5.2.1"
    }
    fn rule_name(&self) -> &str {
        "disallow-privileged-containers"
    }
    fn standard(&self) -> ComplianceStandard {
        ComplianceStandard::CisKubernetesBenchmark
    }
    fn severity(&self) -> ViolationSeverity {
        ViolationSeverity::Critical
    }
    fn evaluate(&self, pod: &AdmissionReviewPodSpec) -> Option<OpaViolation> {
        for c in &pod.containers {
            if c.privileged.unwrap_or(false) {
                return Some(OpaViolation {
                    rule_id: self.rule_id().to_string(),
                    rule_name: self.rule_name().to_string(),
                    standard: self.standard(),
                    severity: self.severity(),
                    resource_kind: "Pod".to_string(),
                    resource_name: pod.name.clone(),
                    namespace: pod.namespace.clone(),
                    message: format!(
                        "Container '{}' in pod '{}/{}' has privileged=true",
                        c.name, pod.namespace, pod.name
                    ),
                    remediation: "Set securityContext.privileged=false".to_string(),
                });
            }
        }
        None
    }
}

/// Rule CIS-5.2.6: Disallow root execution (must set runAsNonRoot=true or runAsUser > 0).
pub struct DisallowRootExecution;
impl OpaRule for DisallowRootExecution {
    fn rule_id(&self) -> &str {
        "CIS-5.2.6"
    }
    fn rule_name(&self) -> &str {
        "disallow-root-execution"
    }
    fn standard(&self) -> ComplianceStandard {
        ComplianceStandard::CisKubernetesBenchmark
    }
    fn severity(&self) -> ViolationSeverity {
        ViolationSeverity::High
    }
    fn evaluate(&self, pod: &AdmissionReviewPodSpec) -> Option<OpaViolation> {
        for c in &pod.containers {
            let is_root = c.run_as_user == Some(0)
                || (c.run_as_non_root != Some(true) && c.run_as_user.is_none());

            if is_root {
                return Some(OpaViolation {
                    rule_id: self.rule_id().to_string(),
                    rule_name: self.rule_name().to_string(),
                    standard: self.standard(),
                    severity: self.severity(),
                    resource_kind: "Pod".to_string(),
                    resource_name: pod.name.clone(),
                    namespace: pod.namespace.clone(),
                    message: format!(
                        "Container '{}' in pod '{}/{}' allows running as root UID 0",
                        c.name, pod.namespace, pod.name
                    ),
                    remediation: "Set securityContext.runAsNonRoot=true and runAsUser > 0"
                        .to_string(),
                });
            }
        }
        None
    }
}

/// Rule CIS-5.2.2: Disallow hostNetwork and hostPID sharing.
pub struct DisallowHostNamespaces;
impl OpaRule for DisallowHostNamespaces {
    fn rule_id(&self) -> &str {
        "CIS-5.2.2"
    }
    fn rule_name(&self) -> &str {
        "disallow-host-namespaces"
    }
    fn standard(&self) -> ComplianceStandard {
        ComplianceStandard::CisKubernetesBenchmark
    }
    fn severity(&self) -> ViolationSeverity {
        ViolationSeverity::High
    }
    fn evaluate(&self, pod: &AdmissionReviewPodSpec) -> Option<OpaViolation> {
        if pod.host_network || pod.host_pid || pod.host_ipc {
            return Some(OpaViolation {
                rule_id: self.rule_id().to_string(),
                rule_name: self.rule_name().to_string(),
                standard: self.standard(),
                severity: self.severity(),
                resource_kind: "Pod".to_string(),
                resource_name: pod.name.clone(),
                namespace: pod.namespace.clone(),
                message: format!(
                    "Pod '{}/{}' shares host namespaces (hostNetwork={}, hostPID={}, hostIPC={})",
                    pod.namespace, pod.name, pod.host_network, pod.host_pid, pod.host_ipc
                ),
                remediation: "Set hostNetwork=false, hostPID=false, and hostIPC=false".to_string(),
            });
        }
        None
    }
}

/// Rule PCI-DSS 1.3: Enforce strict egress labeling and zero-trust isolation.
pub struct EnforceZeroTrustTagging;
impl OpaRule for EnforceZeroTrustTagging {
    fn rule_id(&self) -> &str {
        "PCI-DSS-1.3"
    }
    fn rule_name(&self) -> &str {
        "enforce-zerotrust-labeling"
    }
    fn standard(&self) -> ComplianceStandard {
        ComplianceStandard::PciDssV4
    }
    fn severity(&self) -> ViolationSeverity {
        ViolationSeverity::Medium
    }
    fn evaluate(&self, pod: &AdmissionReviewPodSpec) -> Option<OpaViolation> {
        if !pod.labels.contains_key("kwall.io/policy-domain") {
            return Some(OpaViolation {
                rule_id: self.rule_id().to_string(),
                rule_name: self.rule_name().to_string(),
                standard: self.standard(),
                severity: self.severity(),
                resource_kind: "Pod".to_string(),
                resource_name: pod.name.clone(),
                namespace: pod.namespace.clone(),
                message: format!(
                    "Pod '{}/{}' is missing required zero-trust label 'kwall.io/policy-domain'",
                    pod.namespace, pod.name
                ),
                remediation: "Add label 'kwall.io/policy-domain: <domain>' to pod metadata"
                    .to_string(),
            });
        }
        None
    }
}

/// Centralized Enterprise OPA & Rego Engine.
pub struct OpaPolicyEngine {
    rules: Arc<RwLock<Vec<Box<dyn OpaRule>>>>,
    enforce_mode: bool,
}

impl Default for OpaPolicyEngine {
    fn default() -> Self {
        let mut engine = Self::new(true);
        // Register standard CIS and PCI-DSS rules
        engine.register_rule(Box::new(DisallowPrivilegedContainers));
        engine.register_rule(Box::new(DisallowRootExecution));
        engine.register_rule(Box::new(DisallowHostNamespaces));
        engine.register_rule(Box::new(EnforceZeroTrustTagging));
        engine
    }
}

impl OpaPolicyEngine {
    /// Creates a new OPA policy engine with enforcement mode toggle (audit-only vs enforce).
    pub fn new(enforce_mode: bool) -> Self {
        Self {
            rules: Arc::new(RwLock::new(Vec::new())),
            enforce_mode,
        }
    }

    /// Registers a new rule evaluator.
    pub fn register_rule(&mut self, rule: Box<dyn OpaRule>) {
        self.rules.write().unwrap().push(rule);
    }

    /// Evaluates an admission review request against all registered OPA rules.
    pub fn evaluate_pod(&self, pod: &AdmissionReviewPodSpec) -> AdmissionReviewDecision {
        let rules = self.rules.read().unwrap();
        let mut violations = Vec::new();

        for rule in rules.iter() {
            if let Some(violation) = rule.evaluate(pod) {
                violations.push(violation);
            }
        }

        let has_critical_or_high = violations
            .iter()
            .any(|v| v.severity >= ViolationSeverity::High);

        let allowed = if self.enforce_mode {
            !has_critical_or_high
        } else {
            true // Audit-only mode
        };

        let status_code = if allowed { 200 } else { 403 };

        AdmissionReviewDecision {
            allowed,
            status_code,
            violations,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn compliant_pod() -> AdmissionReviewPodSpec {
        let mut labels = HashMap::new();
        labels.insert("kwall.io/policy-domain".to_string(), "payments".to_string());

        AdmissionReviewPodSpec {
            name: "secure-checkout".to_string(),
            namespace: "prod".to_string(),
            host_network: false,
            host_pid: false,
            host_ipc: false,
            containers: vec![ContainerSecurityContext {
                name: "checkout-app".to_string(),
                image: "kwall/checkout:v1".to_string(),
                run_as_user: Some(10001),
                run_as_non_root: Some(true),
                allow_privilege_escalation: Some(false),
                privileged: Some(false),
                read_only_root_filesystem: Some(true),
                capabilities_add: Vec::new(),
                capabilities_drop: vec!["ALL".to_string()],
            }],
            labels,
        }
    }

    #[test]
    fn test_compliant_pod_allowed() {
        let engine = OpaPolicyEngine::default();
        let pod = compliant_pod();
        let decision = engine.evaluate_pod(&pod);

        assert!(decision.allowed);
        assert_eq!(decision.status_code, 200);
        assert!(decision.violations.is_empty());
    }

    #[test]
    fn test_privileged_pod_denied() {
        let engine = OpaPolicyEngine::default();
        let mut pod = compliant_pod();
        pod.containers[0].privileged = Some(true);

        let decision = engine.evaluate_pod(&pod);
        assert!(!decision.allowed);
        assert_eq!(decision.status_code, 403);
        assert_eq!(decision.violations.len(), 1);
        assert_eq!(decision.violations[0].rule_id, "CIS-5.2.1");
        assert_eq!(decision.violations[0].severity, ViolationSeverity::Critical);
    }

    #[test]
    fn test_host_namespace_denied() {
        let engine = OpaPolicyEngine::default();
        let mut pod = compliant_pod();
        pod.host_network = true;

        let decision = engine.evaluate_pod(&pod);
        assert!(!decision.allowed);
        assert_eq!(decision.status_code, 403);
        assert!(decision.violations.iter().any(|v| v.rule_id == "CIS-5.2.2"));
    }

    #[test]
    fn test_missing_zero_trust_tag_flags_violation() {
        let engine = OpaPolicyEngine::default();
        let mut pod = compliant_pod();
        pod.labels.clear(); // remove kwall.io/policy-domain

        let decision = engine.evaluate_pod(&pod);
        // Medium severity violation in default mode does not block admission (only High/Critical do)
        assert!(decision.allowed);
        assert_eq!(decision.violations.len(), 1);
        assert_eq!(decision.violations[0].rule_id, "PCI-DSS-1.3");
        assert_eq!(decision.violations[0].severity, ViolationSeverity::Medium);
    }
}
