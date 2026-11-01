//! Rolling ring-buffer packet capture (PCAP) and binary trace recording.
//!
//! Maintains bounded ring buffers of raw network frames per connection/workload,
//! serializing to standard libpcap binary format upon incident trigger.

use std::collections::VecDeque;
use std::sync::RwLock;

/// Standard libpcap global file magic numbers.
pub const PCAP_MAGIC_MICROSECONDS: u32 = 0xa1b2_c3d4;
pub const PCAP_VERSION_MAJOR: u16 = 2;
pub const PCAP_VERSION_MINOR: u16 = 4;
pub const LINKTYPE_ETHERNET: u32 = 1;

/// In-memory captured packet frame.
#[derive(Debug, Clone)]
pub struct CapturedPacket {
    pub timestamp_ns: u64,
    pub original_len: u32,
    pub data: Vec<u8>,
}

/// Rolling packet recorder maintaining a fixed-size ring buffer of recent packets.
pub struct RollingPcapRecorder {
    max_packets: usize,
    buffer: RwLock<VecDeque<CapturedPacket>>,
}

impl RollingPcapRecorder {
    /// Creates a recorder with a maximum packet retention limit.
    #[must_use]
    pub fn new(max_packets: usize) -> Self {
        Self {
            max_packets,
            buffer: RwLock::new(VecDeque::with_capacity(max_packets)),
        }
    }

    /// Appends a raw captured network packet to the rolling buffer.
    pub fn record_packet(&self, timestamp_ns: u64, packet_data: &[u8]) {
        let mut buf = self.buffer.write().unwrap();
        if buf.len() >= self.max_packets {
            buf.pop_front();
        }
        buf.push_back(CapturedPacket {
            timestamp_ns,
            original_len: packet_data.len() as u32,
            data: packet_data.to_vec(),
        });
    }

    /// Exports the recorded packets into standard binary PCAP format.
    #[must_use]
    pub fn dump_pcap(&self) -> Vec<u8> {
        let buf = self.buffer.read().unwrap();
        let mut pcap = Vec::with_capacity(24 + buf.len() * 64);

        // 1. PCAP Global Header (24 bytes)
        // magic (4)
        pcap.extend_from_slice(&PCAP_MAGIC_MICROSECONDS.to_le_bytes());
        // version major (2)
        pcap.extend_from_slice(&PCAP_VERSION_MAJOR.to_le_bytes());
        // version minor (2)
        pcap.extend_from_slice(&PCAP_VERSION_MINOR.to_le_bytes());
        // thiszone (4, GMT = 0)
        pcap.extend_from_slice(&0u32.to_le_bytes());
        // sigfigs (4, accuracy of timestamps = 0)
        pcap.extend_from_slice(&0u32.to_le_bytes());
        // snaplen (4, max packet length, e.g. 65535)
        pcap.extend_from_slice(&65535u32.to_le_bytes());
        // network (4, LinkType Ethernet = 1)
        pcap.extend_from_slice(&LINKTYPE_ETHERNET.to_le_bytes());

        // 2. Packet Records
        for pkt in buf.iter() {
            let sec = (pkt.timestamp_ns / 1_000_000_000) as u32;
            let usec = ((pkt.timestamp_ns % 1_000_000_000) / 1000) as u32;
            let cap_len = pkt.data.len() as u32;

            // Packet Record Header (16 bytes)
            pcap.extend_from_slice(&sec.to_le_bytes());
            pcap.extend_from_slice(&usec.to_le_bytes());
            pcap.extend_from_slice(&cap_len.to_le_bytes());
            pcap.extend_from_slice(&pkt.original_len.to_le_bytes());

            // Packet Payload
            pcap.extend_from_slice(&pkt.data);
        }

        pcap
    }

    /// Clears the rolling buffer.
    pub fn clear(&self) {
        let mut buf = self.buffer.write().unwrap();
        buf.clear();
    }

    /// Returns current number of packets in buffer.
    #[must_use]
    pub fn len(&self) -> usize {
        let buf = self.buffer.read().unwrap();
        buf.len()
    }

    /// Returns true if buffer is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pcap_generation() {
        let recorder = RollingPcapRecorder::new(10);

        let fake_pkt = vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99];
        recorder.record_packet(1_670_000_000_000_000_000, &fake_pkt);

        assert_eq!(recorder.len(), 1);
        let pcap_bytes = recorder.dump_pcap();

        // Check global header magic
        assert_eq!(&pcap_bytes[0..4], &PCAP_MAGIC_MICROSECONDS.to_le_bytes());
        // Minimum size: 24 (global header) + 16 (pkt header) + 10 (data) = 50 bytes
        assert_eq!(pcap_bytes.len(), 50);
    }
}
