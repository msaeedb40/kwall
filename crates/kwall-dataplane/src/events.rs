use kwall_ebpf_common::{FlowEvent, SecurityEvent};
use tokio::sync::broadcast;
use tracing::info;

pub struct EventHub {
    flow_sender: broadcast::Sender<FlowEvent>,
    sec_sender: broadcast::Sender<SecurityEvent>,
}

impl EventHub {
    pub fn new(capacity: usize) -> Self {
        let (flow_sender, _) = broadcast::channel(capacity);
        let (sec_sender, _) = broadcast::channel(capacity);
        Self {
            flow_sender,
            sec_sender,
        }
    }

    pub fn subscribe_flows(&self) -> broadcast::Receiver<FlowEvent> {
        self.flow_sender.subscribe()
    }

    pub fn subscribe_security_events(&self) -> broadcast::Receiver<SecurityEvent> {
        self.sec_sender.subscribe()
    }

    pub fn dispatch_flow(&self, event: FlowEvent) {
        let _ = self.flow_sender.send(event);
    }

    pub fn dispatch_security_event(&self, event: SecurityEvent) {
        info!("Dispatching security event type={}", event.event_type);
        let _ = self.sec_sender.send(event);
    }
}

impl Default for EventHub {
    fn default() -> Self {
        Self::new(1024)
    }
}
