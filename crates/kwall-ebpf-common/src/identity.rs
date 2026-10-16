#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "user", derive(serde::Serialize, serde::Deserialize))]
pub struct EndpointIdentity {
    pub identity_id: u32,
    pub namespace_id: u32,
    pub pod_uid_hash: u64,
    pub ifindex: u32,
    pub ipv4: u32,
    pub ipv6: [u8; 16],
    pub flags: u32,
}

impl Default for EndpointIdentity {
    fn default() -> Self {
        Self {
            identity_id: 0,
            namespace_id: 0,
            pod_uid_hash: 0,
            ifindex: 0,
            ipv4: 0,
            ipv6: [0; 16],
            flags: 0,
        }
    }
}

pub const IDENTITY_HOST: u32 = 1;
pub const IDENTITY_WORLD: u32 = 2;
pub const IDENTITY_CLUSTER: u32 = 3;
pub const IDENTITY_INIT: u32 = 4;
pub const IDENTITY_HEALTH: u32 = 5;
pub const IDENTITY_MIN_WORKLOAD: u32 = 1000;
