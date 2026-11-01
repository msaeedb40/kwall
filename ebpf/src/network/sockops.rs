//! Socket operations (`sockops`) program for TCP state transition tracking and socket redirection.

use aya_ebpf::programs::SockOpsContext;

pub fn try_sock_ops(_ctx: SockOpsContext) -> Result<u32, ()> {
    // In sockops, return 0 indicates success
    Ok(0)
}
