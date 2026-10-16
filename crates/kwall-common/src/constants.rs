pub const DEFAULT_BPF_FS_PATH: &str = "/sys/fs/bpf/kwall";
pub const DEFAULT_SOCKET_PATH: &str = "/run/kwall/kwall.sock";
pub const DEFAULT_CONFIG_PATH: &str = "/etc/kwall/kwall.yaml";
pub const DEFAULT_METRICS_ADDR: &str = "0.0.0.0:9153";
pub const DEFAULT_GRPC_ADDR: &str = "127.0.0.1:9099";

pub const NETKIT_PRIMARY_PREFIX: &str = "kw_pri";
pub const NETKIT_PEER_PREFIX: &str = "kw_peer";

pub const MIN_SUPPORTED_KERNEL_MAJOR: u32 = 6;
pub const MIN_SUPPORTED_KERNEL_MINOR: u32 = 8;
