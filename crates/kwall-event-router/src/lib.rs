//! # kwall-event-router
//!
//! Event models, normalizers from eBPF binary events, and high-throughput async dispatcher.

pub mod event;
pub mod normalizer;
pub mod router;

pub use event::{
    AlertEventData, EventPayload, KwallEvent, LsmEventData, NetworkEventData, ProcessEventData,
};
pub use normalizer::{normalize_lsm_event, normalize_net_event, normalize_process_event};
pub use router::{EventHandler, EventRouter};
