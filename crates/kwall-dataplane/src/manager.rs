use kwall_common::{KwallError, Result};
use tracing::info;

pub struct DataplaneManager {
    initialized: bool,
    attached_interfaces: Vec<String>,
}

impl DataplaneManager {
    pub fn new() -> Self {
        Self {
            initialized: false,
            attached_interfaces: Vec::new(),
        }
    }

    pub fn init(&mut self) -> Result<()> {
        info!("Initializing KWALL Dataplane Manager");
        self.initialized = true;
        Ok(())
    }

    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    pub fn attach_interface(&mut self, iface: &str) -> Result<()> {
        if !self.initialized {
            return Err(KwallError::Dataplane("Dataplane not initialized".into()));
        }
        info!("Attaching eBPF dataplane to interface {}", iface);
        if !self.attached_interfaces.iter().any(|i| i == iface) {
            self.attached_interfaces.push(iface.to_string());
        }
        Ok(())
    }

    pub fn detach_interface(&mut self, iface: &str) -> Result<()> {
        info!("Detaching eBPF dataplane from interface {}", iface);
        self.attached_interfaces.retain(|i| i != iface);
        Ok(())
    }

    pub fn attached_interfaces(&self) -> &[String] {
        &self.attached_interfaces
    }
}

impl Default for DataplaneManager {
    fn default() -> Self {
        Self::new()
    }
}
