//! KWALL Control Plane API.
//!
//! Provides authenticated REST & gRPC endpoints for cluster status inspection,
//! policy validation, event streaming, enterprise RBAC, cryptographic audit logging,
//! and automated regulatory compliance reporting.

pub mod audit;
pub mod auth;
pub mod compliance;
pub mod server;

pub use audit::{
    AuditError, AuditLog, AuditRecord, AuditStatus, AUDIT_GENESIS_HASH,
};
pub use auth::{
    verify_bearer_token, AuthError, OidcClaims, OidcConfig, OidcValidator, RbacPolicy, RbacRole,
    SecAction, SecResource,
};
pub use compliance::{
    ComplianceEngine, ComplianceFramework, ComplianceReport, ControlEvaluation, ControlStatus,
};
pub use server::{
    start_api_server, ApiServerState, ClusterStatusReport, ValidatePolicyResponse,
};
