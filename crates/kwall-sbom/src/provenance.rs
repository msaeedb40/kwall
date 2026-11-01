//! Container image provenance, Cosign/Sigstore verification, and registry admission policies.
//!
//! Validates container image registries, cryptographic Cosign signatures,
//! and immutable manifest digests to prevent supply chain tampering.

use std::collections::HashSet;

use kwall_core::types::Severity;
use kwall_detection::alert::{ThreatAlert, ThreatCategory};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Errors occurring during image provenance and signature validation.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ProvenanceError {
    #[error("Invalid image reference format: {0}")]
    InvalidImageRef(String),
    #[error("Image registry '{0}' is not in approved registry list")]
    UntrustedRegistry(String),
    #[error("Image missing immutable digest (tag-only references disallowed)")]
    MissingDigest,
    #[error("Image signature verification failed: {0}")]
    SignatureVerificationFailed(String),
    #[error("Image signed by unauthorized identity: {0}")]
    UnauthorizedSigner(String),
    #[error("Digest mismatch: expected {expected}, actual {actual}")]
    DigestMismatch { expected: String, actual: String },
}

/// Structured container image reference.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ImageReference {
    pub registry: String,
    pub repository: String,
    pub tag: Option<String>,
    pub digest: Option<String>,
}

impl ImageReference {
    /// Parses an image reference string (e.g., `ghcr.io/kwall/agent:v0.1.0@sha256:...`).
    pub fn parse(raw: &str) -> Result<Self, ProvenanceError> {
        if raw.is_empty() {
            return Err(ProvenanceError::InvalidImageRef(
                "Empty image reference".to_string(),
            ));
        }

        let (remainder, digest) = match raw.split_once('@') {
            Some((rem, dig)) => (rem, Some(dig.to_string())),
            None => (raw, None),
        };

        let (rem_repo, tag) = match remainder.rsplit_once(':') {
            Some((repo, t))
                if !repo.contains('/')
                    || repo.find('/').is_some_and(|idx| idx < repo.len() - 1) =>
            {
                // Check if this colon is a port in the domain or a tag
                if t.contains('/') {
                    (remainder, None)
                } else {
                    (repo, Some(t.to_string()))
                }
            }
            _ => (remainder, None),
        };

        let (registry, repository) = match rem_repo.split_once('/') {
            Some((reg, repo)) if reg.contains('.') || reg.contains(':') || reg == "localhost" => {
                (reg.to_string(), repo.to_string())
            }
            _ => ("docker.io".to_string(), rem_repo.to_string()),
        };

        Ok(Self {
            registry,
            repository,
            tag,
            digest,
        })
    }

    /// Returns the full canonical image reference string.
    #[must_use]
    pub fn canonical(&self) -> String {
        let mut s = format!("{}/{}", self.registry, self.repository);
        if let Some(tag) = &self.tag {
            s.push(':');
            s.push_str(tag);
        }
        if let Some(digest) = &self.digest {
            s.push('@');
            s.push_str(digest);
        }
        s
    }
}

/// Cosign / Sigstore signature payload descriptor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CosignSignaturePayload {
    /// In-toto / Cosign manifest digest signed.
    pub manifest_digest: String,
    /// Issuer certificate identity (e.g. Fulcio OIDC email or GitHub Actions workflow URI).
    pub signer_identity: String,
    /// Fulcio OIDC Issuer URL.
    pub issuer: String,
    /// Optional custom annotations attached to signature.
    pub annotations: std::collections::HashMap<String, String>,
}

/// Supply chain provenance policy configuring allowed registries and signature requirements.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvenancePolicy {
    /// List of trusted registry prefixes (e.g. "ghcr.io/msaeedb40/", "myorg.azurecr.io/").
    pub allowed_registries: Vec<String>,
    /// Whether containers must specify an immutable `@sha256:...` digest.
    pub require_digest: bool,
    /// Whether cryptographic Cosign signature is required.
    pub require_signature: bool,
    /// Set of authorized Sigstore signer identities / GitHub workflow subjects.
    pub authorized_identities: HashSet<String>,
}

impl Default for ProvenancePolicy {
    fn default() -> Self {
        Self {
            allowed_registries: vec!["ghcr.io/".to_string(), "docker.io/library/".to_string()],
            require_digest: true,
            require_signature: true,
            authorized_identities: HashSet::new(),
        }
    }
}

/// Validator verifying images against admission supply chain policies.
pub struct ProvenanceValidator {
    pub policy: ProvenancePolicy,
}

impl ProvenanceValidator {
    pub fn new(policy: ProvenancePolicy) -> Self {
        Self { policy }
    }

    /// Verifies image reference and optional Cosign signature against the policy.
    #[allow(clippy::result_large_err)]
    pub fn validate(
        &self,
        image_ref: &ImageReference,
        signature: Option<&CosignSignaturePayload>,
    ) -> Result<(), ThreatAlert> {
        let canonical = image_ref.canonical();

        // 1. Check registry against allowed registry list
        let mut registry_allowed = false;
        let full_prefix = format!("{}/{}", image_ref.registry, image_ref.repository);
        for allowed in &self.policy.allowed_registries {
            if full_prefix.starts_with(allowed) || image_ref.registry.starts_with(allowed) {
                registry_allowed = true;
                break;
            }
        }

        if !registry_allowed && !self.policy.allowed_registries.is_empty() {
            let now = kwall_common::utilities::current_timestamp_ns();
            return Err(ThreatAlert::new(
                format!("prov-untrusted-reg-{}", now),
                now,
                Severity::Error,
                ThreatCategory::ImageProvenanceViolation,
                Some("T1204.003"),
                "Untrusted Container Registry Detected",
                format!(
                    "Container image '{canonical}' originates from untrusted registry '{reg}'",
                    reg = image_ref.registry
                ),
                None,
                serde_json::json!({
                    "image": canonical,
                    "registry": image_ref.registry,
                    "allowed_registries": self.policy.allowed_registries
                }),
                "Reject container admission and restrict Kubernetes deployment to authorized registries"
                    .to_string(),
            ));
        }

        // 2. Check immutable digest requirement
        if self.policy.require_digest && image_ref.digest.is_none() {
            let now = kwall_common::utilities::current_timestamp_ns();
            return Err(ThreatAlert::new(
                format!("prov-missing-digest-{}", now),
                now,
                Severity::Warning,
                ThreatCategory::ImageProvenanceViolation,
                Some("T1204.003"),
                "Container Image Missing Immutable Digest",
                format!(
                    "Container image '{canonical}' specifies mutable tag without immutable sha256 digest pin"
                ),
                None,
                serde_json::json!({
                    "image": canonical,
                    "tag": image_ref.tag
                }),
                "Enforce immutable digest pinning (@sha256:...) in deployment manifests"
                    .to_string(),
            ));
        }

        // 3. Check Cosign signature requirement
        if self.policy.require_signature {
            match signature {
                None => {
                    let now = kwall_common::utilities::current_timestamp_ns();
                    return Err(ThreatAlert::new(
                        format!("prov-unsigned-image-{}", now),
                        now,
                        Severity::Error,
                        ThreatCategory::ImageProvenanceViolation,
                        Some("T1553.002"),
                        "Unsigned Container Image Admission Rejected",
                        format!(
                            "Container image '{canonical}' lacks required Cosign cryptographic signature"
                        ),
                        None,
                        serde_json::json!({ "image": canonical }),
                        "Sign container image using Cosign / GitHub Actions OIDC before deploying"
                            .to_string(),
                    ));
                }
                Some(sig) => {
                    // Verify digest matches signature payload
                    if let Some(expected_digest) = &image_ref.digest {
                        if !sig.manifest_digest.ends_with(expected_digest)
                            && !expected_digest.ends_with(&sig.manifest_digest)
                        {
                            let now = kwall_common::utilities::current_timestamp_ns();
                            return Err(ThreatAlert::new(
                                format!("prov-digest-mismatch-{}", now),
                                now,
                                Severity::Critical,
                                ThreatCategory::ImageProvenanceViolation,
                                Some("T1553.002"),
                                "Cosign Signature Digest Mismatch",
                                format!(
                                    "Image digest '{expected_digest}' does not match signature payload '{sig_dig}'",
                                    sig_dig = sig.manifest_digest
                                ),
                                None,
                                serde_json::json!({
                                    "image": canonical,
                                    "expected_digest": expected_digest,
                                    "signature_digest": sig.manifest_digest
                                }),
                                "Quarantine container image and investigate registry compromise"
                                    .to_string(),
                            ));
                        }
                    }

                    // Verify signer identity if policy has restrictions
                    if !self.policy.authorized_identities.is_empty()
                        && !self
                            .policy
                            .authorized_identities
                            .contains(&sig.signer_identity)
                    {
                        let now = kwall_common::utilities::current_timestamp_ns();
                        return Err(ThreatAlert::new(
                            format!("prov-unauth-signer-{}", now),
                            now,
                            Severity::Error,
                            ThreatCategory::ImageProvenanceViolation,
                            Some("T1553.002"),
                            "Unauthorized Image Signer Identity",
                            format!(
                                "Image signed by '{signer}' which is not in authorized signer identity list",
                                signer = sig.signer_identity
                            ),
                            None,
                            serde_json::json!({
                                "image": canonical,
                                "signer_identity": sig.signer_identity,
                                "authorized_identities": self.policy.authorized_identities
                            }),
                            "Reject deployment and inspect signing pipeline permissions".to_string(),
                        ));
                    }
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_image_reference() {
        let raw = "ghcr.io/kwall/kwall-agent:v0.1.0@sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let parsed = ImageReference::parse(raw).expect("Should parse valid image ref");
        assert_eq!(parsed.registry, "ghcr.io");
        assert_eq!(parsed.repository, "kwall/kwall-agent");
        assert_eq!(parsed.tag.as_deref(), Some("v0.1.0"));
        assert_eq!(
            parsed.digest.as_deref(),
            Some("sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        );
        assert_eq!(parsed.canonical(), raw);
    }

    #[test]
    fn test_provenance_validation_success() {
        let policy = ProvenancePolicy {
            allowed_registries: vec!["ghcr.io/kwall/".to_string()],
            require_digest: true,
            require_signature: true,
            authorized_identities: HashSet::from(["release-bot@kwall.io".to_string()]),
        };
        let validator = ProvenanceValidator::new(policy);

        let img = ImageReference::parse(
            "ghcr.io/kwall/agent:v1@sha256:abcdef1234567890abcdef1234567890abcdef12",
        )
        .unwrap();
        let sig = CosignSignaturePayload {
            manifest_digest: "sha256:abcdef1234567890abcdef1234567890abcdef12".to_string(),
            signer_identity: "release-bot@kwall.io".to_string(),
            issuer: "https://token.actions.githubusercontent.com".to_string(),
            annotations: std::collections::HashMap::new(),
        };

        assert!(validator.validate(&img, Some(&sig)).is_ok());
    }

    #[test]
    fn test_provenance_validation_untrusted_registry() {
        let policy = ProvenancePolicy {
            allowed_registries: vec!["ghcr.io/kwall/".to_string()],
            require_digest: false,
            require_signature: false,
            authorized_identities: HashSet::new(),
        };
        let validator = ProvenanceValidator::new(policy);

        let img = ImageReference::parse("evil-registry.io/malware/miner:latest").unwrap();
        let res = validator.validate(&img, None);
        assert!(res.is_err());
        let alert = res.unwrap_err();
        assert_eq!(alert.category, ThreatCategory::ImageProvenanceViolation);
        assert_eq!(alert.mitre_attack_id.as_deref(), Some("T1204.003"));
    }
}
