pub mod cgroup;
pub mod process;

pub use cgroup::{parse_cgroup_path, ContainerCgroupInfo};
pub use process::{ProcessInfo, ProcessInspector};

pub struct RuntimeInspector;

impl RuntimeInspector {
    pub fn new() -> Self {
        Self
    }

    pub fn inspect_process(&self, pid: u32) -> kwall_common::Result<ProcessInfo> {
        ProcessInspector::inspect_pid(pid)
    }
}

impl Default for RuntimeInspector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_current_process_inspection() {
        let inspector = RuntimeInspector::new();
        let my_pid = std::process::id();
        let info = inspector.inspect_process(my_pid).expect("Failed to inspect self");
        assert_eq!(info.pid, my_pid);
        assert!(info.exe_path.is_some());
        assert!(!info.cmdline.is_empty());
    }
}
