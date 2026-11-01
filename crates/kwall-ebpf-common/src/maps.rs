//! Well-known BPF map names shared between the kernel and userspace loader.

pub const MAP_NAME_INGRESS_LPM: &str = "KWALL_INGRESS_LPM";
pub const MAP_NAME_EGRESS_LPM: &str = "KWALL_EGRESS_LPM";
pub const MAP_NAME_FLOW_TABLE: &str = "KWALL_FLOW_TABLE";
pub const MAP_NAME_PROCESS_MAP: &str = "KWALL_PROCESS_MAP";
pub const MAP_NAME_RING_BUFFER: &str = "KWALL_RING_BUF";
pub const MAP_NAME_STAT_COUNTERS: &str = "KWALL_STATS";
