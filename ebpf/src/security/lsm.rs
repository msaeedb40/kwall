//! Linux Security Module (LSM BPF) access control enforcement.

use aya_ebpf::helpers::{bpf_get_current_cgroup_id, bpf_get_current_pid_tgid, bpf_get_current_uid_gid, bpf_ktime_get_ns};
use aya_ebpf::programs::LsmContext;
use kwall_ebpf_common::events::BpfLsmEvent;

use crate::maps::{KWALL_PROCESS_MAP, KWALL_RING_BUF};

const EPERM: i32 = 1;

pub fn try_bprm_check_security(_ctx: LsmContext) -> Result<i32, ()> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;

    // Check if process execution is prohibited by policy
    let action_opt = unsafe { KWALL_PROCESS_MAP.get(&pid) };
    if let Some(&action) = action_opt {
        if action == 1 {
            // Block execution
            let uid_gid = bpf_get_current_uid_gid();
            let uid = uid_gid as u32;
            let cgroup_id = unsafe { bpf_get_current_cgroup_id() };

            let event = BpfLsmEvent {
                timestamp_ns: unsafe { bpf_ktime_get_ns() },
                pid,
                uid,
                cgroup_id,
                hook_id: 1, // bprm_check_security
                action_taken: 1, // Deny
            };
            let _ = KWALL_RING_BUF.output(&event, 0);

            return Ok(-EPERM);
        }
    }

    Ok(0)
}
