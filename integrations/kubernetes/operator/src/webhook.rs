//! Validating admission webhook handler for KWALL security policy CRDs.

use kwall_policy::crd::{KwallNetworkPolicySpec, KwallRuntimePolicySpec};
use kwall_policy::validator::{validate_network_policy, validate_runtime_policy};
use serde::{Deserialize, Serialize};

/// Kubernetes AdmissionReview request/response envelope.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdmissionReview {
    #[serde(rename = "apiVersion", default = "default_api_version")]
    pub api_version: String,
    #[serde(default = "default_kind")]
    pub kind: String,
    pub request: Option<AdmissionRequest>,
    pub response: Option<AdmissionResponse>,
}

fn default_api_version() -> String {
    "admission.k8s.io/v1".to_string()
}

fn default_kind() -> String {
    "AdmissionReview".to_string()
}

/// Inbound admission request from Kubernetes API server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdmissionRequest {
    pub uid: String,
    pub kind: GroupVersionKind,
    pub object: Option<serde_json::Value>,
    pub operation: String,
}

/// GVK identifier.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GroupVersionKind {
    pub group: String,
    pub version: String,
    pub kind: String,
}

/// Admission response returned to Kubernetes API server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdmissionResponse {
    pub uid: String,
    pub allowed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<AdmissionStatus>,
}

/// Diagnostic status details on rejection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdmissionStatus {
    pub code: u16,
    pub message: String,
}

/// Evaluates an admission review request against KWALL semantic policy constraints.
pub fn process_admission_review(review: AdmissionReview) -> AdmissionReview {
    let request = match review.request {
        Some(ref req) => req,
        None => {
            return AdmissionReview {
                api_version: review.api_version,
                kind: review.kind,
                request: None,
                response: Some(AdmissionResponse {
                    uid: "".to_string(),
                    allowed: false,
                    status: Some(AdmissionStatus {
                        code: 400,
                        message: "Missing admission request object".to_string(),
                    }),
                }),
            }
        }
    };

    let response = validate_request(request);

    AdmissionReview {
        api_version: review.api_version,
        kind: review.kind,
        request: review.request,
        response: Some(response),
    }
}

/// Internal validator function.
fn validate_request(request: &AdmissionRequest) -> AdmissionResponse {
    let raw_object = match &request.object {
        Some(obj) => obj,
        None => {
            return AdmissionResponse {
                uid: request.uid.clone(),
                allowed: true,
                status: None,
            }
        }
    };

    match request.kind.kind.as_str() {
        "KwallNetworkPolicy" => {
            // Extract spec from object
            if let Some(spec_val) = raw_object.get("spec") {
                match serde_json::from_value::<KwallNetworkPolicySpec>(spec_val.clone()) {
                    Ok(spec) => {
                        if let Err(e) = validate_network_policy(&spec) {
                            return AdmissionResponse {
                                uid: request.uid.clone(),
                                allowed: false,
                                status: Some(AdmissionStatus {
                                    code: 422,
                                    message: format!("Policy validation rejected: {e}"),
                                }),
                            };
                        }
                    }
                    Err(e) => {
                        return AdmissionResponse {
                            uid: request.uid.clone(),
                            allowed: false,
                            status: Some(AdmissionStatus {
                                code: 400,
                                message: format!("Failed to parse KwallNetworkPolicy spec: {e}"),
                            }),
                        };
                    }
                }
            }
        }
        "KwallRuntimePolicy" => {
            if let Some(spec_val) = raw_object.get("spec") {
                match serde_json::from_value::<KwallRuntimePolicySpec>(spec_val.clone()) {
                    Ok(spec) => {
                        if let Err(e) = validate_runtime_policy(&spec) {
                            return AdmissionResponse {
                                uid: request.uid.clone(),
                                allowed: false,
                                status: Some(AdmissionStatus {
                                    code: 422,
                                    message: format!("Runtime policy validation rejected: {e}"),
                                }),
                            };
                        }
                    }
                    Err(e) => {
                        return AdmissionResponse {
                            uid: request.uid.clone(),
                            allowed: false,
                            status: Some(AdmissionStatus {
                                code: 400,
                                message: format!("Failed to parse KwallRuntimePolicy spec: {e}"),
                            }),
                        };
                    }
                }
            }
        }
        _ => {}
    }

    AdmissionResponse {
        uid: request.uid.clone(),
        allowed: true,
        status: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_network_policy_admission() {
        let review = AdmissionReview {
            api_version: "admission.k8s.io/v1".to_string(),
            kind: "AdmissionReview".to_string(),
            request: Some(AdmissionRequest {
                uid: "req-123".to_string(),
                kind: GroupVersionKind {
                    group: "kwall.io".to_string(),
                    version: "v1alpha1".to_string(),
                    kind: "KwallNetworkPolicy".to_string(),
                },
                object: Some(serde_json::json!({
                    "spec": {
                        "pod_selector": { "app": "frontend" },
                        "ingress": [
                            {
                                "cidr": "10.0.0.0/16",
                                "port": 80,
                                "protocol": "tcp",
                                "action": "allow"
                            }
                        ]
                    }
                })),
                operation: "CREATE".to_string(),
            }),
            response: None,
        };

        let result = process_admission_review(review);
        let resp = result.response.expect("Response must be present");
        assert!(resp.allowed);
        assert_eq!(resp.uid, "req-123");
    }

    #[test]
    fn test_invalid_network_policy_rejection() {
        let review = AdmissionReview {
            api_version: "admission.k8s.io/v1".to_string(),
            kind: "AdmissionReview".to_string(),
            request: Some(AdmissionRequest {
                uid: "req-456".to_string(),
                kind: GroupVersionKind {
                    group: "kwall.io".to_string(),
                    version: "v1alpha1".to_string(),
                    kind: "KwallNetworkPolicy".to_string(),
                },
                object: Some(serde_json::json!({
                    "spec": {
                        "pod_selector": { "app": "db" },
                        "ingress": [
                            {
                                "cidr": "invalid-cidr-string",
                                "port": 5432,
                                "protocol": "tcp",
                                "action": "allow"
                            }
                        ]
                    }
                })),
                operation: "CREATE".to_string(),
            }),
            response: None,
        };

        let result = process_admission_review(review);
        let resp = result.response.expect("Response must be present");
        assert!(!resp.allowed);
        assert!(resp.status.unwrap().message.contains("Invalid"));
    }
}
