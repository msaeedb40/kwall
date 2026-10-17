use kwall_common::{NETKIT_PRIMARY_PREFIX, Result};
use tracing::info;

pub struct NetkitDevicePair {
    pub host_ifname: String,
    pub container_ifname: String,
}

pub fn create_netkit_pair(container_id: &str, target_ifname: &str) -> Result<NetkitDevicePair> {
    let suffix = if container_id.len() >= 6 {
        &container_id[..6]
    } else {
        container_id
    };

    let host_ifname = format!("{}{}", NETKIT_PRIMARY_PREFIX, suffix);
    let container_ifname = target_ifname.to_string();

    info!(
        "Creating netkit device pair: host={}, container={}",
        host_ifname, container_ifname
    );

    Ok(NetkitDevicePair {
        host_ifname,
        container_ifname,
    })
}
