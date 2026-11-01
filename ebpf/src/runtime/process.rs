//! Process lifecycle monitoring via kernel tracepoints.

use aya_ebpf::helpers::{
    bpf_get_current_cgroup_id, bpf_get_current_comm, bpf_get_current_pid_tgid,
    bpf_get_current_uid_gid, bpf_ktime_get_ns,
};
use aya_ebpf::programs::TracePointContext;
use kwall_ebpf_common::events::{BpfProcessEvent, MAX_COMM_LEN, MAX_PATH_LEN};

use crate::maps::{KWALL_PROCESS_MAP, KWALL_RING_BUF};

pub fn try_sched_process_exec(_ctx: TracePointContext) -> Result<u32, ()> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    let tgid = pid_tgid as u32;

    let uid_gid = bpf_get_current_uid_gid();
    let uid = uid_gid as u32;
    let gid = (uid_gid >> 32) as u32;

    let cgroup_id = unsafe { bpf_get_current_cgroup_id() };
    let timestamp_ns = unsafe { bpf_ktime_get_ns() };

    let mut comm = [0u8; MAX_COMM_LEN];
    if let Ok(c) = bpf_get_current_comm() {
        comm = c;
    }

    let filename = [0u8; MAX_PATH_LEN];

    // Record active process in BPF map
    let _ = KWALL_PROCESS_MAP.insert(&pid, &uid, 0);

    // Emit event into ring buffer
    let event = BpfProcessEvent {
        timestamp_ns,
        pid,
        tgid,
        ppid: 0,
        uid,
        gid,
        cgroup_id,
        comm,
        filename,
    };

    let _ = KWALL_RING_BUF.output(&event, 0);

    Ok(0)
}

pub fn try_sched_process_exit(_ctx: TracePointContext) -> Result<u32, ()> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;

    // Clean up process tracking entry
    let _ = KWALL_PROCESS_MAP.remove(&pid);

    Ok(0)
}
