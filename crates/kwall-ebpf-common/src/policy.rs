#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "user", derive(serde::Serialize, serde::Deserialize))]
pub struct PolicyKey {
    pub src_identity: u32,
    pub dst_identity: u32,
    pub dst_port: u16,
    pub protocol: u8,
    pub direction: u8,
}

impl Default for PolicyKey {
    fn default() -> Self {
        Self {
            src_identity: 0,
            dst_identity: 0,
            dst_port: 0,
            protocol: 0,
            direction: 0,
        }
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "user", derive(serde::Serialize, serde::Deserialize))]
pub struct PolicyValue {
    pub action: u32,
    pub policy_id: u32,
    pub priority: u32,
    pub rate_limit_pps: u32,
}

impl Default for PolicyValue {
    fn default() -> Self {
        Self {
            action: 0,
            policy_id: 0,
            priority: 0,
            rate_limit_pps: 0,
        }
    }
}
