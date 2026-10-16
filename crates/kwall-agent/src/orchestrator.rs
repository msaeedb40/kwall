use std::sync::Arc;
use tokio::sync::RwLock;
use kwall_common::{KwallConfig, Result};
use kwall_dataplane::{DataplaneManager, DataplaneState, EventHub};
use kwall_security::SecurityEngine;
use tracing::info;
use crate::kernel::check_kernel_compatibility;
use crate::server::AgentIpcServer;

pub struct NodeAgent {
    config: KwallConfig,
    dataplane_state: Arc<RwLock<DataplaneState>>,
    dataplane_manager: Arc<RwLock<DataplaneManager>>,
    event_hub: Arc<EventHub>,
    security: Arc<RwLock<SecurityEngine>>,
}

impl NodeAgent {
    pub fn new(config: KwallConfig) -> Self {
        Self {
            config,
            dataplane_state: Arc::new(RwLock::new(DataplaneState::new())),
            dataplane_manager: Arc::new(RwLock::new(DataplaneManager::new())),
            event_hub: Arc::new(EventHub::new(4096)),
            security: Arc::new(RwLock::new(SecurityEngine::new(100, 500, 10, Vec::new()))),
        }
    }

    pub async fn start(&self) -> Result<()> {
        info!("Starting KWALL Node Agent...");

        // 1. Verify Kernel Compatibility
        let compat = check_kernel_compatibility()?;
        info!(
            "Kernel verification passed: {} (compatible={})",
            compat.kernel_version, compat.compatible
        );

        // 2. Initialize Dataplane
        {
            let mut mgr = self.dataplane_manager.write().await;
            mgr.init()?;
        }

        // 3. Start IPC Server
        let server = AgentIpcServer::new(
            self.config.socket_path.clone(),
            Arc::clone(&self.dataplane_state),
            Arc::clone(&self.dataplane_manager),
            compat.kernel_version,
        );

        tokio::spawn(async move {
            if let Err(e) = server.run().await {
                tracing::error!("Agent IPC server exited: {}", e);
            }
        });

        info!("KWALL Node Agent successfully initialized and running.");
        Ok(())
    }

    pub fn state(&self) -> Arc<RwLock<DataplaneState>> {
        Arc::clone(&self.dataplane_state)
    }

    pub fn manager(&self) -> Arc<RwLock<DataplaneManager>> {
        Arc::clone(&self.dataplane_manager)
    }

    pub fn event_hub(&self) -> Arc<EventHub> {
        Arc::clone(&self.event_hub)
    }

    pub fn security(&self) -> Arc<RwLock<SecurityEngine>> {
        Arc::clone(&self.security)
    }
}
