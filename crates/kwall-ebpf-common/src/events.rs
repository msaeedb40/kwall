//! Compact, fixed-width binary event definitions emitted from eBPF ring buffers.

/// Maximum executable path length captured in kernel space.
pub const MAX_COMM_LEN: usize = 16;
pub const MAX_PATH_LEN: usize = 64;

/// Low-level network event emitted by XDP or TC programs into the BPF ring buffer.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BpfNetEvent {
    pub timestamp_ns: u64,
    pub src_ip: u32,
    pub dst_ip: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
    pub action: u8,
    pub pad: [u8; 2],
    pub packet_len: u32,
    pub ifindex: u32,
}

/// Low-level runtime execution event emitted by process tracepoints into the BPF ring buffer.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BpfProcessEvent {
    pub timestamp_ns: u64,
    pub pid: u32,
    pub tgid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub gid: u32,
    pub cgroup_id: u64,
    pub comm: [u8; MAX_COMM_LEN],
    pub filename: [u8; MAX_PATH_LEN],
}

/// Low-level LSM security decision event emitted into the ring buffer.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BpfLsmEvent {
    pub timestamp_ns: u64,
    pub pid: u32,
    pub uid: u32,
    pub cgroup_id: u64,
    pub hook_id: u32,
    pub action_taken: u32,
}
