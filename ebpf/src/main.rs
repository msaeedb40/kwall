#![no_std]
#![no_main]

mod maps;
mod network;
mod runtime;
mod security;

use aya_ebpf::bindings::xdp_action;
use aya_ebpf::macros::{cgroup_sock, classifier, lsm, sock_ops, tracepoint, xdp};
use aya_ebpf::programs::{
    LsmContext, SockContext, SockOpsContext, TcContext, TracePointContext, XdpContext,
};

#[xdp]
pub fn xdp_ingress(ctx: XdpContext) -> u32 {
    match network::xdp::try_xdp_ingress(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

#[classifier]
pub fn tc_egress(ctx: TcContext) -> i32 {
    match network::tc::try_tc_egress(ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

#[cgroup_sock(sock_create)]
pub fn sock_create(ctx: SockContext) -> i32 {
    match network::cgroup::try_sock_create(ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

#[sock_ops]
pub fn sockops_handler(ctx: SockOpsContext) -> u32 {
    match network::sockops::try_sock_ops(ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

#[tracepoint]
pub fn sched_process_exec(ctx: TracePointContext) -> u32 {
    match runtime::process::try_sched_process_exec(ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

#[tracepoint]
pub fn sched_process_exit(ctx: TracePointContext) -> u32 {
    match runtime::process::try_sched_process_exit(ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

#[lsm(hook = "bprm_check_security")]
pub fn bprm_check_security(ctx: LsmContext) -> i32 {
    match security::lsm::try_bprm_check_security(ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
