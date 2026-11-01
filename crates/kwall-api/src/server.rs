//! Control plane HTTP REST and management server.

use crate::auth::verify_bearer_token;
use kwall_detection::alert::ThreatAlert;
use kwall_policy::crd::KwallNetworkPolicySpec;
use kwall_policy::validator::validate_network_policy;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tracing::{error, info};

/// Status report response object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterStatusReport {
    pub node_name: String,
    pub agent_version: String,
    pub status: String,
    pub btf_available: bool,
    pub bpffs_mounted: bool,
}

/// Request payload for policy validation endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatePolicyPayload {
    pub spec: KwallNetworkPolicySpec,
}

/// Response payload for policy validation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatePolicyResponse {
    pub valid: bool,
    pub message: Option<String>,
}

/// Control plane state shared across API request handlers.
pub struct ApiServerState {
    pub auth_token: Option<String>,
    pub cached_status: RwLock<ClusterStatusReport>,
    pub threats: RwLock<Vec<ThreatAlert>>,
}

impl ApiServerState {
    pub fn new(auth_token: Option<String>) -> Self {
        Self {
            auth_token,
            cached_status: RwLock::new(ClusterStatusReport {
                node_name: "cluster-control-plane".to_string(),
                agent_version: "0.1.0".to_string(),
                status: "READY".to_string(),
                btf_available: true,
                bpffs_mounted: true,
            }),
            threats: RwLock::new(Vec::new()),
        }
    }

    pub fn record_threat(&self, alert: ThreatAlert) {
        if let Ok(mut lock) = self.threats.write() {
            lock.push(alert);
        }
    }
}

/// Starts an asynchronous API server.
pub async fn start_api_server(
    addr: SocketAddr,
    state: Arc<ApiServerState>,
) -> std::io::Result<JoinHandle<()>> {
    let listener = TcpListener::bind(addr).await?;
    info!("KWALL Control Plane API server listening on http://{addr}");

    let handle = tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((mut socket, _)) => {
                    let state = state.clone();
                    tokio::spawn(async move {
                        let mut buf = vec![0u8; 4096];
                        if let Ok(n) = socket.read(&mut buf).await {
                            if n == 0 {
                                return;
                            }
                            let request = String::from_utf8_lossy(&buf[..n]);
                            let response = handle_request(&request, &state);
                            let _ = socket.write_all(response.as_bytes()).await;
                        }
                    });
                }
                Err(e) => {
                    error!("API server connection error: {e}");
                    break;
                }
            }
        }
    });

    Ok(handle)
}

/// Request dispatcher and handler.
fn handle_request(req_str: &str, state: &ApiServerState) -> String {
    // Extract first line
    let mut lines = req_str.lines();
    let first_line = lines.next().unwrap_or("");
    let mut parts = first_line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let path = parts.next().unwrap_or("");

    // Check optional bearer token
    if let Some(ref expected_token) = state.auth_token {
        let auth_header = req_str
            .lines()
            .find(|l| l.to_lowercase().starts_with("authorization:"));
        let header_val = auth_header.and_then(|h| h.split_once(':').map(|(_, v)| v.trim()));

        if verify_bearer_token(header_val, expected_token).is_err() {
            return "HTTP/1.1 401 Unauthorized\r\nContent-Type: application/json\r\n\r\n{\"error\":\"Unauthorized\"}".to_string();
        }
    }

    match (method, path) {
        ("GET", "/api/v1/status") => {
            let status = state.cached_status.read().unwrap().clone();
            let body = serde_json::to_string(&status).unwrap();
            format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                body.len(),
                body
            )
        }
        ("POST", "/api/v1/policies/validate") => {
            // Find body after double newline
            let body_str = req_str.split("\r\n\r\n").nth(1).unwrap_or("");
            let (valid, message) = match serde_json::from_str::<ValidatePolicyPayload>(body_str) {
                Ok(payload) => match validate_network_policy(&payload.spec) {
                    Ok(_) => (true, None),
                    Err(e) => (false, Some(e.to_string())),
                },
                Err(e) => (false, Some(format!("Invalid request JSON: {e}"))),
            };

            let resp = ValidatePolicyResponse { valid, message };
            let body = serde_json::to_string(&resp).unwrap();
            format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                body.len(),
                body
            )
        }
        ("GET", "/api/v1/threats") => {
            let threats = state.threats.read().unwrap().clone();
            let body = serde_json::to_string(&threats).unwrap();
            format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                body.len(),
                body
            )
        }
        _ => "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    #[tokio::test]
    async fn test_api_server_endpoints() {
        let state = Arc::new(ApiServerState::new(Some("test-secret".to_string())));
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let listener = TcpListener::bind(addr).await.unwrap();
        let bound_addr = listener.local_addr().unwrap();
        drop(listener);

        let _server = start_api_server(bound_addr, state).await.unwrap();

        // 1. Unauthorized request
        let mut stream = TcpStream::connect(bound_addr).await.unwrap();
        stream
            .write_all(b"GET /api/v1/status HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap();
        let mut res = String::new();
        stream.read_to_string(&mut res).await.unwrap();
        assert!(res.contains("401 Unauthorized"));

        // 2. Authorized status request
        let mut stream2 = TcpStream::connect(bound_addr).await.unwrap();
        stream2
            .write_all(b"GET /api/v1/status HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer test-secret\r\n\r\n")
            .await
            .unwrap();
        let mut res2 = String::new();
        stream2.read_to_string(&mut res2).await.unwrap();
        assert!(res2.contains("200 OK"));
        assert!(res2.contains("cluster-control-plane"));
    }
}
