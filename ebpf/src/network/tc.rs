//! Traffic Control (TC clsact) ingress and egress packet inspection.

use aya_ebpf::bindings::{TC_ACT_OK, TC_ACT_SHOT};
use aya_ebpf::helpers::bpf_ktime_get_ns;
use aya_ebpf::maps::lpm_trie::Key;
use aya_ebpf::programs::TcContext;
use core::mem;
use kwall_ebpf_common::events::BpfNetEvent;
use kwall_ebpf_common::types::{BPF_ACTION_DROP, BPF_ACTION_PASS};
use network_types::eth::{EthHdr, EtherType};
use network_types::ip::{IpProto, Ipv4Hdr};
use network_types::tcp::TcpHdr;
use network_types::udp::UdpHdr;

use crate::maps::{KWALL_EGRESS_LPM, KWALL_RING_BUF, KWALL_STATS};

#[inline(always)]
unsafe fn ptr_at<T>(ctx: &TcContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *const T)
}

pub fn try_tc_egress(ctx: TcContext) -> Result<i32, ()> {
    let eth = unsafe { ptr_at::<EthHdr>(&ctx, 0)? };
    if u16::from_be(unsafe { (*eth).ether_type }) != EtherType::Ipv4 as u16 {
        return Ok(TC_ACT_OK);
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

    // Check egress LPM trie
    let lpm_key = Key::new(32, dst_ip_bytes);

    let mut action = BPF_ACTION_PASS;
    if let Some(policy) = KWALL_EGRESS_LPM.get(&lpm_key) {
        action = policy.action;
    }

    // Output event to ring buffer on drop
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
            ifindex: 0,
        };
        let _ = KWALL_RING_BUF.output(&event, 0);

        if let Some(drop_counter) = KWALL_STATS.get_ptr_mut(2) {
            unsafe { *drop_counter += 1 };
        }
        return Ok(TC_ACT_SHOT);
    }

    Ok(TC_ACT_OK)
}
