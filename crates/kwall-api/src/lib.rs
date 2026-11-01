//! KWALL Control Plane API.
//!
//! Provides authenticated REST & gRPC endpoints for cluster status inspection,
//! policy validation, event streaming, and security threat management.

pub mod auth;
pub mod server;

pub use auth::{verify_bearer_token, AuthError};
pub use server::{start_api_server, ApiServerState, ClusterStatusReport, ValidatePolicyResponse};
