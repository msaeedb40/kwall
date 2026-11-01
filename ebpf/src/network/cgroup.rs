//! Cgroup socket lifecycle and connection hooks.

use aya_ebpf::programs::SockContext;

pub fn try_sock_create(_ctx: SockContext) -> Result<i32, ()> {
    // Return 1 to allow socket creation
    Ok(1)
}
