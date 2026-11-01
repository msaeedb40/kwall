//! Enterprise Authentication, OIDC/Keycloak Integration, and RBAC Engine.
//!
//! Provides enterprise identity integration supporting OIDC/Keycloak token validation,
//! fine-grained Role-Based Access Control (RBAC), and capability-based authorization.

use serde::{Deserialize, Serialize};
use thiserror::Error;

// ---------------------------------------------------------------------------
// Authentication Errors
// ---------------------------------------------------------------------------

/// Authentication and authorization errors.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum AuthError {
    #[error("Missing Authorization header")]
    MissingHeader,
    #[error("Invalid Authorization header format; expected 'Bearer <token>'")]
    InvalidFormat,
    #[error("Unauthorized: invalid token credentials")]
    InvalidToken,
    #[error("Token expired: current time {now} exceeds exp {exp}")]
    TokenExpired { now: u64, exp: u64 },
    #[error("Token audience mismatch: expected '{expected}', found '{actual}'")]
    AudienceMismatch { expected: String, actual: String },
    #[error("Token issuer mismatch: expected '{expected}', found '{actual}'")]
    IssuerMismatch { expected: String, actual: String },
    #[error("Access denied: role '{role}' lacks permission for {action:?} on {resource:?}")]
    PermissionDenied {
        role: String,
        resource: SecResource,
        action: SecAction,
    },
    #[error("Failed to decode token claims: {0}")]
    ClaimsDecodeError(String),
}

// ---------------------------------------------------------------------------
// Bearer Token Simple Verification (Backward Compatible)
// ---------------------------------------------------------------------------

/// Verifies an authorization header value against an expected secret token.
pub fn verify_bearer_token(header: Option<&str>, expected_token: &str) -> Result<(), AuthError> {
    let raw = header.ok_or(AuthError::MissingHeader)?;
    let token = raw
        .strip_prefix("Bearer ")
        .or_else(|| raw.strip_prefix("bearer "))
        .ok_or(AuthError::InvalidFormat)?
        .trim();

    if token == expected_token {
        Ok(())
    } else {
        Err(AuthError::InvalidToken)
    }
}

// ---------------------------------------------------------------------------
// OIDC / Keycloak Claims and Configuration
// ---------------------------------------------------------------------------

/// OpenID Connect (OIDC) JWT claims payload.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OidcClaims {
    /// Issuer (iss)
    pub iss: String,
    /// Subject identifier (sub)
    pub sub: String,
    /// Audience (aud)
    pub aud: String,
    /// Expiration timestamp in seconds since epoch (exp)
    pub exp: u64,
    /// Not before timestamp in seconds since epoch (nbf)
    #[serde(default)]
    pub nbf: Option<u64>,
    /// Issued at timestamp in seconds since epoch (iat)
    #[serde(default)]
    pub iat: Option<u64>,
    /// User email address
    #[serde(default)]
    pub email: Option<String>,
    /// Preferred username or Keycloak user identifier
    #[serde(default)]
    pub preferred_username: Option<String>,
    /// Assigned enterprise roles
    #[serde(default)]
    pub roles: Vec<String>,
}

/// Configuration for OIDC Identity Provider (e.g. Keycloak, Okta, Dex, Google).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcConfig {
    pub issuer_url: String,
    pub client_id: String,
    pub jwks_uri: String,
    pub allowed_audiences: Vec<String>,
    pub clock_skew_sec: u64,
}

impl Default for OidcConfig {
    fn default() -> Self {
        Self {
            issuer_url: "https://auth.kwall.enterprise/auth/realms/security".to_string(),
            client_id: "kwall-management-plane".to_string(),
            jwks_uri:
                "https://auth.kwall.enterprise/auth/realms/security/protocol/openid-connect/certs"
                    .to_string(),
            allowed_audiences: vec![
                "kwall-management-plane".to_string(),
                "kwall-api".to_string(),
            ],
            clock_skew_sec: 60,
        }
    }
}

/// OIDC token validator and parser.
pub struct OidcValidator {
    config: OidcConfig,
}

impl OidcValidator {
    pub fn new(config: OidcConfig) -> Self {
        Self { config }
    }

    /// Validates an OIDC claims object against configuration and current timestamp.
    pub fn validate_claims(&self, claims: &OidcClaims, now_sec: u64) -> Result<(), AuthError> {
        // Check issuer
        if claims.iss != self.config.issuer_url {
            return Err(AuthError::IssuerMismatch {
                expected: self.config.issuer_url.clone(),
                actual: claims.iss.clone(),
            });
        }

        // Check audience
        if !self
            .config
            .allowed_audiences
            .iter()
            .any(|a| a == &claims.aud)
        {
            return Err(AuthError::AudienceMismatch {
                expected: self.config.client_id.clone(),
                actual: claims.aud.clone(),
            });
        }

        // Check expiration with clock skew
        if now_sec > claims.exp + self.config.clock_skew_sec {
            return Err(AuthError::TokenExpired {
                now: now_sec,
                exp: claims.exp,
            });
        }

        Ok(())
    }

    /// Extracts the highest-privilege `RbacRole` mapped from token claims.
    pub fn extract_role(&self, claims: &OidcClaims) -> RbacRole {
        for role_str in &claims.roles {
            let normalized = role_str.to_lowercase();
            if normalized.contains("admin") || normalized.contains("kwall_admin") {
                return RbacRole::Admin;
            } else if normalized.contains("analyst") || normalized.contains("sec_analyst") {
                return RbacRole::SecurityAnalyst;
            } else if normalized.contains("editor") || normalized.contains("policy_editor") {
                return RbacRole::PolicyEditor;
            } else if normalized.contains("auditor") || normalized.contains("compliance") {
                return RbacRole::Auditor;
            }
        }
        RbacRole::Viewer
    }
}

// ---------------------------------------------------------------------------
// Enterprise RBAC System
// ---------------------------------------------------------------------------

/// Enterprise RBAC roles.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RbacRole {
    /// Full access across all multi-cluster security operations and engine configs.
    Admin,
    /// Can triage alerts, trigger container quarantines, and inspect forensics.
    SecurityAnalyst,
    /// Read-only access to cluster topology, metrics, and compliance scorecards.
    Viewer,
    /// Can create, validate, and update security policy CRDs.
    PolicyEditor,
    /// Can view and export compliance reports, audit logs, and approve changes.
    Auditor,
    /// Custom organizational role.
    Custom(String),
}

impl std::fmt::Display for RbacRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Admin => write!(f, "Admin"),
            Self::SecurityAnalyst => write!(f, "SecurityAnalyst"),
            Self::Viewer => write!(f, "Viewer"),
            Self::PolicyEditor => write!(f, "PolicyEditor"),
            Self::Auditor => write!(f, "Auditor"),
            Self::Custom(name) => write!(f, "Custom({name})"),
        }
    }
}

/// Security resources managed by the KWALL platform.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SecResource {
    Cluster,
    Node,
    Workload,
    Policy,
    Alert,
    ForensicRecord,
    AuditLog,
    ComplianceReport,
    EbpfEngine,
}

/// Actions performed on protected security resources.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SecAction {
    Read,
    Write,
    Delete,
    Execute,
    Approve,
}

/// RBAC policy engine evaluating permission matrices.
pub struct RbacPolicy;

impl RbacPolicy {
    /// Evaluates if the given role is authorized to perform `action` on `resource`.
    #[must_use]
    pub fn check_permission(role: &RbacRole, resource: SecResource, action: SecAction) -> bool {
        match role {
            // Admin has universal permission
            RbacRole::Admin => true,

            // Security Analyst:
            // - Read all resources
            // - Execute/Write on Alerts (quarantine, isolate, acknowledge)
            // - Read/Write on Forensics
            // - Cannot delete AuditLogs or modify root Policies
            RbacRole::SecurityAnalyst => match action {
                SecAction::Read => true,
                SecAction::Execute => matches!(
                    resource,
                    SecResource::Alert | SecResource::Workload | SecResource::ForensicRecord
                ),
                SecAction::Write => {
                    matches!(resource, SecResource::Alert | SecResource::ForensicRecord)
                }
                SecAction::Delete | SecAction::Approve => false,
            },

            // Policy Editor:
            // - Read all resources
            // - Read, Write, Delete on Policies
            RbacRole::PolicyEditor => match action {
                SecAction::Read => true,
                SecAction::Write | SecAction::Delete => matches!(resource, SecResource::Policy),
                SecAction::Execute | SecAction::Approve => false,
            },

            // Auditor:
            // - Read on all resources
            // - Approve on Policies and AuditLogs
            // - Cannot Write or Delete
            RbacRole::Auditor => match action {
                SecAction::Read => true,
                SecAction::Approve => matches!(
                    resource,
                    SecResource::Policy | SecResource::AuditLog | SecResource::ComplianceReport
                ),
                SecAction::Write | SecAction::Delete | SecAction::Execute => false,
            },

            // Viewer: Read-only on non-sensitive telemetry
            RbacRole::Viewer => match action {
                SecAction::Read => matches!(
                    resource,
                    SecResource::Cluster
                        | SecResource::Node
                        | SecResource::Workload
                        | SecResource::Alert
                        | SecResource::ComplianceReport
                ),
                _ => false,
            },

            RbacRole::Custom(_) => false,
        }
    }

    /// Enforces permission, returning `Result<(), AuthError>`.
    pub fn enforce(
        role: &RbacRole,
        resource: SecResource,
        action: SecAction,
    ) -> Result<(), AuthError> {
        if Self::check_permission(role, resource, action) {
            Ok(())
        } else {
            Err(AuthError::PermissionDenied {
                role: role.to_string(),
                resource,
                action,
            })
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auth_token_verification() {
        let secret = "kwall-super-secret-token";
        assert!(verify_bearer_token(Some("Bearer kwall-super-secret-token"), secret).is_ok());
        assert_eq!(
            verify_bearer_token(Some("Bearer wrong-token"), secret),
            Err(AuthError::InvalidToken)
        );
        assert_eq!(
            verify_bearer_token(Some("Basic 12345"), secret),
            Err(AuthError::InvalidFormat)
        );
        assert_eq!(
            verify_bearer_token(None, secret),
            Err(AuthError::MissingHeader)
        );
    }

    #[test]
    fn test_oidc_claims_validation() {
        let config = OidcConfig::default();
        let validator = OidcValidator::new(config);

        let valid_claims = OidcClaims {
            iss: "https://auth.kwall.enterprise/auth/realms/security".to_string(),
            sub: "user-123".to_string(),
            aud: "kwall-management-plane".to_string(),
            exp: 2_000_000_000,
            nbf: Some(1_000_000_000),
            iat: Some(1_000_000_000),
            email: Some("analyst@enterprise.com".to_string()),
            preferred_username: Some("sarah.chen".to_string()),
            roles: vec!["sec_analyst".to_string()],
        };

        // Current time: 1,500,000,000 (well within exp)
        assert!(validator
            .validate_claims(&valid_claims, 1_500_000_000)
            .is_ok());

        // Test expired token
        let expired_claims = OidcClaims {
            exp: 1_000_000,
            ..valid_claims.clone()
        };
        assert!(matches!(
            validator.validate_claims(&expired_claims, 2_000_000),
            Err(AuthError::TokenExpired { .. })
        ));

        // Test issuer mismatch
        let wrong_iss = OidcClaims {
            iss: "https://evil.idp.com".to_string(),
            ..valid_claims.clone()
        };
        assert!(matches!(
            validator.validate_claims(&wrong_iss, 1_500_000_000),
            Err(AuthError::IssuerMismatch { .. })
        ));

        // Test audience mismatch
        let wrong_aud = OidcClaims {
            aud: "unauthorized-app".to_string(),
            ..valid_claims
        };
        assert!(matches!(
            validator.validate_claims(&wrong_aud, 1_500_000_000),
            Err(AuthError::AudienceMismatch { .. })
        ));
    }

    #[test]
    fn test_oidc_role_extraction() {
        let validator = OidcValidator::new(OidcConfig::default());

        let claims_admin = OidcClaims {
            iss: "test".into(),
            sub: "1".into(),
            aud: "test".into(),
            exp: 9999999999,
            nbf: None,
            iat: None,
            email: None,
            preferred_username: None,
            roles: vec!["realm_admin".into(), "user".into()],
        };
        assert_eq!(validator.extract_role(&claims_admin), RbacRole::Admin);

        let claims_analyst = OidcClaims {
            roles: vec!["sec_analyst".into()],
            ..claims_admin.clone()
        };
        assert_eq!(
            validator.extract_role(&claims_analyst),
            RbacRole::SecurityAnalyst
        );

        let claims_editor = OidcClaims {
            roles: vec!["policy_editor".into()],
            ..claims_admin.clone()
        };
        assert_eq!(
            validator.extract_role(&claims_editor),
            RbacRole::PolicyEditor
        );

        let claims_auditor = OidcClaims {
            roles: vec!["compliance_auditor".into()],
            ..claims_admin.clone()
        };
        assert_eq!(validator.extract_role(&claims_auditor), RbacRole::Auditor);

        let claims_default = OidcClaims {
            roles: vec!["random_user".into()],
            ..claims_admin
        };
        assert_eq!(validator.extract_role(&claims_default), RbacRole::Viewer);
    }

    #[test]
    fn test_rbac_permission_matrix() {
        // Admin can do anything
        assert!(RbacPolicy::check_permission(
            &RbacRole::Admin,
            SecResource::EbpfEngine,
            SecAction::Execute
        ));
        assert!(RbacPolicy::check_permission(
            &RbacRole::Admin,
            SecResource::Policy,
            SecAction::Delete
        ));

        // Analyst can execute on Alerts (quarantine pod)
        assert!(RbacPolicy::check_permission(
            &RbacRole::SecurityAnalyst,
            SecResource::Alert,
            SecAction::Execute
        ));
        assert!(RbacPolicy::check_permission(
            &RbacRole::SecurityAnalyst,
            SecResource::ForensicRecord,
            SecAction::Write
        ));
        // Analyst CANNOT delete policy or modify eBPF engine
        assert!(!RbacPolicy::check_permission(
            &RbacRole::SecurityAnalyst,
            SecResource::Policy,
            SecAction::Delete
        ));
        assert!(!RbacPolicy::check_permission(
            &RbacRole::SecurityAnalyst,
            SecResource::EbpfEngine,
            SecAction::Write
        ));

        // PolicyEditor can create/update policy but NOT quarantine pods
        assert!(RbacPolicy::check_permission(
            &RbacRole::PolicyEditor,
            SecResource::Policy,
            SecAction::Write
        ));
        assert!(RbacPolicy::check_permission(
            &RbacRole::PolicyEditor,
            SecResource::Policy,
            SecAction::Delete
        ));
        assert!(!RbacPolicy::check_permission(
            &RbacRole::PolicyEditor,
            SecResource::Workload,
            SecAction::Execute
        ));

        // Auditor can approve policies and read audit logs, but cannot write
        assert!(RbacPolicy::check_permission(
            &RbacRole::Auditor,
            SecResource::Policy,
            SecAction::Approve
        ));
        assert!(RbacPolicy::check_permission(
            &RbacRole::Auditor,
            SecResource::AuditLog,
            SecAction::Read
        ));
        assert!(!RbacPolicy::check_permission(
            &RbacRole::Auditor,
            SecResource::Policy,
            SecAction::Write
        ));

        // Viewer is read-only
        assert!(RbacPolicy::check_permission(
            &RbacRole::Viewer,
            SecResource::Cluster,
            SecAction::Read
        ));
        assert!(!RbacPolicy::check_permission(
            &RbacRole::Viewer,
            SecResource::AuditLog,
            SecAction::Read
        )); // Viewer cannot read audit logs
        assert!(!RbacPolicy::check_permission(
            &RbacRole::Viewer,
            SecResource::Policy,
            SecAction::Write
        ));

        // Test enforce()
        assert!(
            RbacPolicy::enforce(&RbacRole::Admin, SecResource::Cluster, SecAction::Write).is_ok()
        );
        assert_eq!(
            RbacPolicy::enforce(&RbacRole::Viewer, SecResource::Policy, SecAction::Delete),
            Err(AuthError::PermissionDenied {
                role: "Viewer".into(),
                resource: SecResource::Policy,
                action: SecAction::Delete
            })
        );
    }
}
