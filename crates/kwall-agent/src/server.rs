use kwall_common::{AgentRequest, AgentResponse, NodeStatus, Result};
use kwall_dataplane::{DataplaneManager, DataplaneState};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixListener;
use tokio::sync::RwLock;
use tracing::{error, info};

pub struct AgentIpcServer {
    socket_path: String,
    state: Arc<RwLock<DataplaneState>>,
    manager: Arc<RwLock<DataplaneManager>>,
    kernel_version: String,
}

impl AgentIpcServer {
    pub fn new(
        socket_path: String,
        state: Arc<RwLock<DataplaneState>>,
        manager: Arc<RwLock<DataplaneManager>>,
        kernel_version: String,
    ) -> Self {
        Self {
            socket_path,
            state,
            manager,
            kernel_version,
        }
    }

    pub async fn run(&self) -> Result<()> {
        let _ = std::fs::remove_file(&self.socket_path);
        if let Some(parent) = std::path::Path::new(&self.socket_path).parent() {
            let _ = std::fs::create_dir_all(parent);
        }

        let listener = UnixListener::bind(&self.socket_path)?;
        info!("KWALL Agent IPC Server listening on {}", self.socket_path);

        loop {
            match listener.accept().await {
                Ok((mut stream, _)) => {
                    let state = Arc::clone(&self.state);
                    let manager = Arc::clone(&self.manager);
                    let kver = self.kernel_version.clone();

                    tokio::spawn(async move {
                        let mut buf = vec![0u8; 4096];
                        if let Ok(n) = stream.read(&mut buf).await {
                            if n == 0 {
                                return;
                            }
                            let response = match serde_json::from_slice::<AgentRequest>(&buf[..n]) {
                                Ok(req) => handle_request(req, state, manager, kver).await,
                                Err(e) => {
                                    AgentResponse::Error(format!("Invalid request JSON: {}", e))
                                }
                            };

                            if let Ok(resp_bytes) = serde_json::to_vec(&response) {
                                let _ = stream.write_all(&resp_bytes).await;
                            }
                        }
                    });
                }
                Err(e) => {
                    error!("IPC accept error: {}", e);
                    break;
                }
            }
        }

        Ok(())
    }
}

pub async fn handle_request(
    req: AgentRequest,
    state: Arc<RwLock<DataplaneState>>,
    manager: Arc<RwLock<DataplaneManager>>,
    kernel_version: String,
) -> AgentResponse {
    match req {
        AgentRequest::GetStatus => {
            let st = state.read().await;
            let mgr = manager.read().await;
            let status = NodeStatus {
                node_name: std::env::var("NODE_NAME").unwrap_or_else(|_| "localhost".into()),
                kernel_version,
                ebpf_ready: mgr.is_initialized(),
                active_interfaces: mgr.attached_interfaces().to_vec(),
                endpoints_count: st.endpoint_count(),
                policies_count: st.policy_count(),
                drops_count: st.get_metrics().drops,
            };
            AgentResponse::Status(status)
        }
        AgentRequest::ListEndpoints => {
            let st = state.read().await;
            AgentResponse::Endpoints(st.all_endpoints())
        }
        AgentRequest::ListPolicies => {
            let st = state.read().await;
            AgentResponse::Policies(st.all_policy_keys())
        }
        AgentRequest::GetMetrics => {
            let st = state.read().await;
            AgentResponse::Metrics(st.get_metrics())
        }
        AgentRequest::AddBlacklist { ip } => {
            let mut st = state.write().await;
            st.add_blacklist_ip(ip);
            AgentResponse::Success
        }
        AgentRequest::RemoveBlacklist { ip } => {
            let mut st = state.write().await;
            let _ = st.remove_blacklist_ip(ip);
            AgentResponse::Success
        }
        AgentRequest::RegisterEndpoint {
            ip,
            identity_id,
            namespace_id,
            pod_uid_hash,
            ifindex,
        } => {
            let mut st = state.write().await;
            let ep = kwall_ebpf_common::EndpointIdentity {
                identity_id,
                namespace_id,
                pod_uid_hash,
                ifindex,
                ipv4: ip,
                ipv6: [0; 16],
                flags: 0,
                _pad: 0,
            };
            st.insert_endpoint(ip, ep);
            AgentResponse::Success
        }
        AgentRequest::UnregisterEndpoint { ip } => {
            let mut st = state.write().await;
            st.remove_endpoint(ip);
            AgentResponse::Success
        }
    }
}
