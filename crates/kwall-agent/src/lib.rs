pub mod kernel;
pub mod orchestrator;
pub mod server;

pub use kernel::check_kernel_compatibility;
pub use orchestrator::NodeAgent;
pub use server::AgentIpcServer;

use anyhow::Result;
use kwall_common::KwallConfig;

pub async fn run_agent() -> Result<()> {
    let config = KwallConfig::default();
    let agent = NodeAgent::new(config);
    agent.start().await?;

    // Keep running
    tokio::signal::ctrl_c().await?;
    tracing::info!("Received shutdown signal. Stopping KWALL Node Agent...");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use kwall_common::{AgentRequest, AgentResponse};

    #[tokio::test]
    async fn test_agent_request_handling() {
        let agent = NodeAgent::new(KwallConfig::default());
        let state = agent.state();
        let manager = agent.manager();

        // Register endpoint through IPC handler
        let req = AgentRequest::RegisterEndpoint {
            ip: 0x0A000001,
            identity_id: 1050,
            namespace_id: 2,
            pod_uid_hash: 12345,
            ifindex: 3,
        };

        let resp = server::handle_request(req, state.clone(), manager.clone(), "6.8.0-test".into()).await;
        match resp {
            AgentResponse::Success => {}
            _ => panic!("Expected Success"),
        }

        // Query status
        let req_status = AgentRequest::GetStatus;
        let resp_status = server::handle_request(req_status, state, manager, "6.8.0-test".into()).await;
        match resp_status {
            AgentResponse::Status(s) => {
                assert_eq!(s.endpoints_count, 1);
                assert_eq!(s.kernel_version, "6.8.0-test");
            }
            _ => panic!("Expected Status response"),
        }
    }
}
