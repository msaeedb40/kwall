//! Ingress XDP packet filter and firewall.

use aya_ebpf::bindings::xdp_action;
use aya_ebpf::helpers::bpf_ktime_get_ns;
use aya_ebpf::maps::lpm_trie::Key;
use aya_ebpf::programs::XdpContext;
use core::mem;
use kwall_ebpf_common::events::BpfNetEvent;
use kwall_ebpf_common::types::{FlowKey, PolicyMapValue, BPF_ACTION_DROP, BPF_ACTION_PASS};
use network_types::eth::{EthHdr, EtherType};
use network_types::ip::{IpProto, Ipv4Hdr};
use network_types::tcp::TcpHdr;
use network_types::udp::UdpHdr;

use crate::maps::{KWALL_FLOW_TABLE, KWALL_INGRESS_LPM, KWALL_RING_BUF, KWALL_STATS};

#[inline(always)]
unsafe fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *const T)
}

pub fn try_xdp_ingress(ctx: XdpContext) -> Result<u32, ()> {
    let eth = unsafe { ptr_at::<EthHdr>(&ctx, 0)? };
    if u16::from_be(unsafe { (*eth).ether_type }) != EtherType::Ipv4 as u16 {
        return Ok(xdp_action::XDP_PASS);
    }

    let ip = unsafe { ptr_at::<Ipv4Hdr>(&ctx, EthHdr::LEN)? };
    let src_ip_bytes = unsafe { (*ip).src_addr };
    let dst_ip_bytes = unsafe { (*ip).dst_addr };
    let src_ip = u32::from_be_bytes(src_ip_bytes);
    let dst_ip = u32::from_be_bytes(dst_ip_bytes);
    let proto = unsafe { (*ip).proto };

    let mut src_port: u16 = 0;
    let mut dst_port: u16 = 0;
    let l4_offset = EthHdr::LEN + Ipv4Hdr::LEN;

    if proto == IpProto::Tcp as u8 {
        let tcp = unsafe { ptr_at::<TcpHdr>(&ctx, l4_offset)? };
        src_port = u16::from_be_bytes(unsafe { (*tcp).source });
        dst_port = u16::from_be_bytes(unsafe { (*tcp).dest });
    } else if proto == IpProto::Udp as u8 {
        let udp = unsafe { ptr_at::<UdpHdr>(&ctx, l4_offset)? };
        src_port = u16::from_be_bytes(unsafe { (*udp).src });
        dst_port = u16::from_be_bytes(unsafe { (*udp).dst });
    }

    // 1. Check LPM Trie rule for ingress CIDR
    let lpm_key = Key::new(32, src_ip_bytes);

    let mut action = BPF_ACTION_PASS;
    if let Some(policy) = KWALL_INGRESS_LPM.get(&lpm_key) {
        action = policy.action;
    }

    // 2. Track connection in flow table
    let flow_key = FlowKey {
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        proto,
        pad: [0; 3],
    };

    let flow_val = PolicyMapValue {
        action,
        rule_id: 1,
        counter: 1,
    };
    let _ = KWALL_FLOW_TABLE.insert(&flow_key, &flow_val, 0);

    // 3. Increment packet counter
    if let Some(counter) = KWALL_STATS.get_ptr_mut(0) {
        unsafe { *counter += 1 };
    }

    // 4. Output packet event into ring buffer if dropped or audited
    if action == BPF_ACTION_DROP {
        let event = BpfNetEvent {
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocol: proto,
            action: action as u8,
            pad: [0; 2],
            packet_len: (ctx.data_end() - ctx.data()) as u32,
            ifindex: ctx.ingress_ifindex() as u32,
        };
        let _ = KWALL_RING_BUF.output(&event, 0);

        if let Some(drop_counter) = KWALL_STATS.get_ptr_mut(1) {
            unsafe { *drop_counter += 1 };
        }
        return Ok(xdp_action::XDP_DROP);
    }

    Ok(xdp_action::XDP_PASS)
}
