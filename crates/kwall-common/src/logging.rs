//! Centralized structured logging initialization.

use kwall_core::error::{KwallError, Result};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

/// Logging format options.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogFormat {
    Text,
    Json,
}

/// Initializes the global tracing subscriber.
pub fn init_logging(default_level: &str, format: LogFormat) -> Result<()> {
    let env_filter = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new(default_level))
        .map_err(|e| KwallError::Config(format!("Invalid log level: {e}")))?;

    let registry = tracing_subscriber::registry().with(env_filter);

    match format {
        LogFormat::Json => {
            let json_layer = tracing_subscriber::fmt::layer()
                .json()
                .with_target(true)
                .with_thread_ids(true)
                .with_line_number(true);
            registry
                .with(json_layer)
                .try_init()
                .map_err(|e| KwallError::Internal(format!("Failed to init JSON logger: {e}")))?;
        }
        LogFormat::Text => {
            let text_layer = tracing_subscriber::fmt::layer()
                .with_target(true)
                .with_thread_ids(false)
                .with_line_number(true);
            registry
                .with(text_layer)
                .try_init()
                .map_err(|e| KwallError::Internal(format!("Failed to init text logger: {e}")))?;
        }
    }

    Ok(())
}
