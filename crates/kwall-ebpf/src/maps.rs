use aya_ebpf::{
    macros::map,
    maps::{HashMap, LruHashMap, PerCpuArray, RingBuf},
};
use kwall_ebpf_common::{
    ConntrackKey, ConntrackValue, EndpointIdentity, MetricsCounter, PolicyKey, PolicyValue,
};

#[map]
pub static KW_ENDPOINTS: HashMap<u32, EndpointIdentity> =
    HashMap::<u32, EndpointIdentity>::with_max_entries(65536, 0);

#[map]
pub static KW_POLICIES: HashMap<PolicyKey, PolicyValue> =
    HashMap::<PolicyKey, PolicyValue>::with_max_entries(65536, 0);

#[map]
pub static KW_CONNTRACK: LruHashMap<ConntrackKey, ConntrackValue> =
    LruHashMap::<ConntrackKey, ConntrackValue>::with_max_entries(262144, 0);

#[map]
pub static KW_IP_BLACKLIST: HashMap<u32, u8> = HashMap::<u32, u8>::with_max_entries(65536, 0);

#[map]
pub static KW_METRICS: PerCpuArray<MetricsCounter> =
    PerCpuArray::<MetricsCounter>::with_max_entries(1, 0);

#[map]
pub static KW_FLOW_EVENTS: RingBuf = RingBuf::with_byte_size(1024 * 1024, 0);

#[map]
pub static KW_SEC_EVENTS: RingBuf = RingBuf::with_byte_size(512 * 1024, 0);
