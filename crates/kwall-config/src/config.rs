//! Centralized, validated KWALL configuration model.

use kwall_core::constants::{DEFAULT_FLOW_MAP_CAPACITY, DEFAULT_RING_BUFFER_SIZE_BYTES};
use kwall_core::error::{KwallError, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Node Agent Configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    pub node_name: String,
    pub network_interfaces: Vec<String>,
    pub ring_buffer_size_bytes: usize,
    pub flow_map_capacity: u32,
    pub enable_xdp: bool,
    pub enable_tc: bool,
    pub enable_lsm: bool,
    pub log_level: String,
    pub metrics_port: u16,
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            node_name: std::env::var("NODE_NAME").unwrap_or_else(|_| "localhost".to_string()),
            network_interfaces: vec!["eth0".to_string()],
            ring_buffer_size_bytes: DEFAULT_RING_BUFFER_SIZE_BYTES,
            flow_map_capacity: DEFAULT_FLOW_MAP_CAPACITY,
            enable_xdp: true,
            enable_tc: true,
            enable_lsm: true,
            log_level: "info".to_string(),
            metrics_port: 9090,
        }
    }
}

impl AgentConfig {
    /// Load configuration from a TOML file.
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| KwallError::Config(format!("Failed to read config file: {e}")))?;
        let config: Self = toml::from_str(&content)
            .map_err(|e| KwallError::Config(format!("Failed to parse config file: {e}")))?;
        config.validate()?;
        Ok(config)
    }

    /// Validates configuration parameters against system constraints.
    pub fn validate(&self) -> Result<()> {
        if self.network_interfaces.is_empty() {
            return Err(KwallError::Config(
                "At least one network interface must be configured".to_string(),
            ));
        }

        if !self.ring_buffer_size_bytes.is_power_of_two() {
            return Err(KwallError::Config(
                "ring_buffer_size_bytes must be a power of two".to_string(),
            ));
        }

        if self.flow_map_capacity == 0 {
            return Err(KwallError::Config(
                "flow_map_capacity must be greater than zero".to_string(),
            ));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config_is_valid() {
        let config = AgentConfig::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_invalid_network_interfaces() {
        let mut config = AgentConfig::default();
        config.network_interfaces.clear();
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_invalid_ring_buffer_size() {
        let config = AgentConfig {
            ring_buffer_size_bytes: 1000, // Not a power of two
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }
}
