//! Kernel-to-userspace Ring Buffer consumer with zero-copy binary event decoding.

use aya::maps::{Map, MapData, RingBuf};
use kwall_core::error::{KwallError, Result};
use kwall_core::types::NodeId;
use kwall_ebpf_common::events::{BpfLsmEvent, BpfNetEvent, BpfProcessEvent};
use kwall_event_router::normalizer::{
    normalize_lsm_event, normalize_net_event, normalize_process_event,
};
use kwall_event_router::router::EventRouter;
use std::mem;
use tracing::warn;

/// Poller that drains the BPF ring buffer and dispatches decoded events.
pub struct RingBufferPoller {
    ring_buf: RingBuf<MapData>,
    node_id: NodeId,
}

impl RingBufferPoller {
    pub fn new(map: Map, node_id: NodeId) -> Result<Self> {
        let ring_buf = RingBuf::try_from(map)
            .map_err(|e| KwallError::Ebpf(format!("Failed to initialize RingBuf: {e}")))?;

        Ok(Self { ring_buf, node_id })
    }

    /// Polls and drains all pending events currently available in the kernel ring buffer.
    pub fn drain(&mut self, router: &EventRouter) -> usize {
        let mut count = 0;

        while let Some(item) = self.ring_buf.next() {
            let bytes: &[u8] = &item;
            count += 1;

            if bytes.len() == mem::size_of::<BpfNetEvent>() {
                let net_event: BpfNetEvent =
                    unsafe { std::ptr::read_unaligned(bytes.as_ptr() as *const _) };
                let event = normalize_net_event(&net_event, self.node_id);
                let _ = router.dispatch(event);
            } else if bytes.len() == mem::size_of::<BpfProcessEvent>() {
                let proc_event: BpfProcessEvent =
                    unsafe { std::ptr::read_unaligned(bytes.as_ptr() as *const _) };
                let event = normalize_process_event(&proc_event, self.node_id);
                let _ = router.dispatch(event);
            } else if bytes.len() == mem::size_of::<BpfLsmEvent>() {
                let lsm_event: BpfLsmEvent =
                    unsafe { std::ptr::read_unaligned(bytes.as_ptr() as *const _) };
                let event = normalize_lsm_event(&lsm_event, self.node_id);
                let _ = router.dispatch(event);
            } else {
                warn!(
                    "Received unknown ring buffer event size: {} bytes",
                    bytes.len()
                );
            }
        }

        count
    }
}
