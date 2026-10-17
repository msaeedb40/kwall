pub mod netkit;

pub use netkit::{NetkitDevicePair, create_netkit_pair};

use anyhow::Result;
use kwall_common::{AgentRequest, AgentResponse, DEFAULT_SOCKET_PATH};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CniConfig {
    #[serde(rename = "cniVersion")]
    pub cni_version: String,
    pub name: String,
    #[serde(rename = "type")]
    pub plugin_type: String,
}

pub async fn notify_agent_register(
    ip: u32,
    identity_id: u32,
    namespace_id: u32,
    pod_uid_hash: u64,
    ifindex: u32,
) -> Result<()> {
    let req = AgentRequest::RegisterEndpoint {
        ip,
        identity_id,
        namespace_id,
        pod_uid_hash,
        ifindex,
    };

    if let Ok(mut stream) = UnixStream::connect(DEFAULT_SOCKET_PATH).await {
        let req_bytes = serde_json::to_vec(&req)?;
        stream.write_all(&req_bytes).await?;
        let mut buf = vec![0u8; 1024];
        let n = stream.read(&mut buf).await?;
        let resp: AgentResponse = serde_json::from_slice(&buf[..n])?;
        match resp {
            AgentResponse::Success => Ok(()),
            AgentResponse::Error(e) => Err(anyhow::anyhow!("Agent error: {}", e)),
            _ => Ok(()),
        }
    } else {
        // Agent not reachable (e.g. running in standalone test mode)
        Ok(())
    }
}

pub async fn notify_agent_unregister(ip: u32) -> Result<()> {
    let req = AgentRequest::UnregisterEndpoint { ip };
    if let Ok(mut stream) = UnixStream::connect(DEFAULT_SOCKET_PATH).await {
        let req_bytes = serde_json::to_vec(&req)?;
        stream.write_all(&req_bytes).await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cni_device_creation() {
        let pair = create_netkit_pair("123456789abc", "eth0").unwrap();
        assert!(pair.host_ifname.starts_with("kw_pri"));
        assert_eq!(pair.container_ifname, "eth0");
    }
}
