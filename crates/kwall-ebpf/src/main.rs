#![no_std]
#![no_main]

pub mod maps;
pub mod packet;

use aya_ebpf::{
    bindings::xdp_action,
    helpers::bpf_ktime_get_ns,
    macros::{classifier, xdp},
    programs::{TcContext, XdpContext},
};
use core::mem;
use kwall_ebpf_common::{
    ConntrackKey, ConntrackState, ConntrackValue, DropReason, FlowEvent, L4Protocol,
    PacketAction, PolicyKey, SecurityEvent, SecurityEventType, Severity, TrafficDirection,
    IDENTITY_HOST, IDENTITY_WORLD,
};
use maps::{
    KW_CONNTRACK, KW_ENDPOINTS, KW_FLOW_EVENTS, KW_IP_BLACKLIST, KW_METRICS, KW_POLICIES,
    KW_SEC_EVENTS,
};
use packet::{
    ptr_at, EthHdr, Ipv4Hdr, TcpHdr, UdpHdr, ETH_P_IP, IPPROTO_ICMP, IPPROTO_TCP,
    IPPROTO_UDP,
};

pub const TC_ACT_UNSPEC: i32 = -1;
pub const TC_ACT_OK: i32 = 0;
pub const TC_ACT_SHOT: i32 = 2;

// ----------------------------------------------------------------------------
// XDP INGRESS PROGRAM: Early drops, DDoS mitigation, Blacklist enforcement
// ----------------------------------------------------------------------------
#[xdp]
pub fn kwall_xdp_ingress(ctx: XdpContext) -> u32 {
    match try_xdp_ingress(ctx) {
        Ok(action) => action,
        Err(_) => xdp_action::XDP_PASS,
    }
}

#[inline(always)]
fn try_xdp_ingress(ctx: XdpContext) -> Result<u32, ()> {
    let data = ctx.data();
    let data_end = ctx.data_end();

    let eth = unsafe { ptr_at::<EthHdr>(data, data_end, 0)? };
    let proto = u16::from_be(unsafe { (*eth).h_proto });
    if proto != ETH_P_IP {
        return Ok(xdp_action::XDP_PASS);
    }

    let ip_offset = mem::size_of::<EthHdr>();
    let ip = unsafe { ptr_at::<Ipv4Hdr>(data, data_end, ip_offset)? };
    let src_ip = u32::from_be(unsafe { (*ip).src_addr });

    // Early drop check: IP blacklist lookup
    if unsafe { KW_IP_BLACKLIST.get(&src_ip).is_some() } {
        // Record metric
        if let Some(metrics) = KW_METRICS.get_ptr_mut(0) {
            unsafe {
                (*metrics).drops += 1;
                (*metrics).packets += 1;
            }
        }

        // Emit security event to ring buffer
        if let Some(mut slot) = KW_SEC_EVENTS.reserve::<SecurityEvent>(0) {
            let mut sec_event = SecurityEvent::default();
            sec_event.timestamp_ns = unsafe { bpf_ktime_get_ns() };
            sec_event.event_type = SecurityEventType::SynFlood as u32;
            sec_event.severity = Severity::High as u32;
            sec_event.extra_data[0] = src_ip as u64;
            slot.write(sec_event);
            slot.submit(0);
        }

        return Ok(xdp_action::XDP_DROP);
    }

    // Packet metrics accounting
    if let Some(metrics) = KW_METRICS.get_ptr_mut(0) {
        unsafe {
            (*metrics).packets += 1;
            (*metrics).bytes += (data_end - data) as u64;
        }
    }

    Ok(xdp_action::XDP_PASS)
}

// ----------------------------------------------------------------------------
// TC INGRESS PROGRAM: Workload Identity, Stateful Conntrack, Policy Engine
// ----------------------------------------------------------------------------
#[classifier]
pub fn kwall_tc_ingress(ctx: TcContext) -> i32 {
    match try_tc_ingress(ctx) {
        Ok(action) => action,
        Err(_) => TC_ACT_OK,
    }
}

#[inline(always)]
fn try_tc_ingress(ctx: TcContext) -> Result<i32, ()> {
    process_packet(ctx, TrafficDirection::Ingress)
}

// ----------------------------------------------------------------------------
// TC EGRESS PROGRAM: Outbound Pod Traffic Enforcement & Flow Accounting
// ----------------------------------------------------------------------------
#[classifier]
pub fn kwall_tc_egress(ctx: TcContext) -> i32 {
    match try_tc_egress(ctx) {
        Ok(action) => action,
        Err(_) => TC_ACT_OK,
    }
}

#[inline(always)]
fn try_tc_egress(ctx: TcContext) -> Result<i32, ()> {
    process_packet(ctx, TrafficDirection::Egress)
}

// ----------------------------------------------------------------------------
// Core Packet Processing & Policy Evaluation Pipeline
// ----------------------------------------------------------------------------
#[inline(always)]
fn process_packet(ctx: TcContext, direction: TrafficDirection) -> Result<i32, ()> {
    let data = ctx.data();
    let data_end = ctx.data_end();

    let eth = unsafe { ptr_at::<EthHdr>(data, data_end, 0)? };
    let eth_proto = u16::from_be(unsafe { (*eth).h_proto });
    if eth_proto != ETH_P_IP {
        return Ok(TC_ACT_OK);
    }

    let ip_offset = mem::size_of::<EthHdr>();
    let ip = unsafe { ptr_at::<Ipv4Hdr>(data, data_end, ip_offset)? };
    let ip_proto = unsafe { (*ip).protocol };
    let src_ip_raw = unsafe { (*ip).src_addr };
    let dst_ip_raw = unsafe { (*ip).dst_addr };

    let src_ip = u32::from_be(src_ip_raw);
    let dst_ip = u32::from_be(dst_ip_raw);
    let l4_offset = ip_offset + unsafe { (*ip).ihl_bytes() };

    let mut src_port: u16 = 0;
    let mut dst_port: u16 = 0;
    let l4_protocol: L4Protocol;

    if ip_proto == IPPROTO_TCP {
        l4_protocol = L4Protocol::Tcp;
        let tcp = unsafe { ptr_at::<TcpHdr>(data, data_end, l4_offset)? };
        src_port = u16::from_be(unsafe { (*tcp).source });
        dst_port = u16::from_be(unsafe { (*tcp).dest });
    } else if ip_proto == IPPROTO_UDP {
        l4_protocol = L4Protocol::Udp;
        let udp = unsafe { ptr_at::<UdpHdr>(data, data_end, l4_offset)? };
        src_port = u16::from_be(unsafe { (*udp).source });
        dst_port = u16::from_be(unsafe { (*udp).dest });
    } else if ip_proto == IPPROTO_ICMP {
        l4_protocol = L4Protocol::Icmp;
    } else {
        l4_protocol = L4Protocol::Unknown;
    }

    // Resolve Workload Identities
    let src_identity = unsafe {
        KW_ENDPOINTS
            .get(&src_ip)
            .map(|ep| ep.identity_id)
            .unwrap_or(IDENTITY_WORLD)
    };

    let dst_identity = unsafe {
        KW_ENDPOINTS
            .get(&dst_ip)
            .map(|ep| ep.identity_id)
            .unwrap_or(IDENTITY_WORLD)
    };

    // Conntrack key construction
    let mut ct_key = ConntrackKey::default();
    ct_key.src_ip[0..4].copy_from_slice(&src_ip_raw.to_ne_bytes());
    ct_key.dst_ip[0..4].copy_from_slice(&dst_ip_raw.to_ne_bytes());
    ct_key.src_port = src_port;
    ct_key.dst_port = dst_port;
    ct_key.protocol = l4_protocol as u8;
    ct_key.is_ipv6 = 0;

    let now_ns = unsafe { bpf_ktime_get_ns() };
    let pkt_len = (data_end - data) as u64;

    // Check existing connection tracking state
    if let Some(ct_val) = KW_CONNTRACK.get_ptr_mut(&ct_key) {
        unsafe {
            (*ct_val).last_seen_ns = now_ns;
            (*ct_val).packets += 1;
            (*ct_val).bytes += pkt_len;
        }

        let verdict = unsafe { (*ct_val).verdict };
        if verdict == (PacketAction::Drop as u8) {
            return Ok(TC_ACT_SHOT);
        }
        return Ok(TC_ACT_OK);
    }

    // Evaluate policy for new connection
    let pol_key = PolicyKey {
        src_identity,
        dst_identity,
        dst_port,
        protocol: l4_protocol as u8,
        direction: direction as u8,
    };

    // Check exact rule, then wildcard port (port = 0)
    let pol_rule = unsafe {
        KW_POLICIES.get(&pol_key).or_else(|| {
            let mut wildcard_key = pol_key;
            wildcard_key.dst_port = 0;
            KW_POLICIES.get(&wildcard_key)
        })
    };

    let (verdict_action, drop_reason, policy_id) = match pol_rule {
        Some(rule) if rule.action == (PacketAction::Pass as u32) => {
            (PacketAction::Pass, DropReason::None, rule.policy_id)
        }
        Some(rule) => (PacketAction::Drop, DropReason::PolicyDeny, rule.policy_id),
        None => {
            // Default policy: Allow host traffic, default deny external/unknown pod-to-pod
            if src_identity == IDENTITY_HOST || dst_identity == IDENTITY_HOST {
                (PacketAction::Pass, DropReason::None, 0)
            } else {
                (PacketAction::Drop, DropReason::PolicyDeny, 0)
            }
        }
    };

    // Store in conntrack table
    let ct_val = ConntrackValue {
        state: if verdict_action == PacketAction::Pass {
            ConntrackState::Established as u8
        } else {
            ConntrackState::Invalid as u8
        },
        verdict: verdict_action as u8,
        _pad: [0; 2],
        last_seen_ns: now_ns,
        packets: 1,
        bytes: pkt_len,
        policy_id,
        _pad2: 0,
    };
    let _ = KW_CONNTRACK.insert(&ct_key, &ct_val, 0);

    // Emit Flow Record to Ring Buffer
    if let Some(mut slot) = KW_FLOW_EVENTS.reserve::<FlowEvent>(0) {
        let mut event = FlowEvent::default();
        event.timestamp_ns = now_ns;
        event.src_identity = src_identity;
        event.dst_identity = dst_identity;
        event.src_ip[0..4].copy_from_slice(&src_ip_raw.to_ne_bytes());
        event.dst_ip[0..4].copy_from_slice(&dst_ip_raw.to_ne_bytes());
        event.src_port = src_port;
        event.dst_port = dst_port;
        event.protocol = l4_protocol as u8;
        event.direction = direction as u8;
        event.action = verdict_action as u8;
        event.drop_reason = drop_reason as u8;
        event.packets = 1;
        event.bytes = pkt_len;
        event.policy_id = policy_id;
        slot.write(event);
        slot.submit(0);
    }

    if verdict_action == PacketAction::Drop {
        Ok(TC_ACT_SHOT)
    } else {
        Ok(TC_ACT_OK)
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
