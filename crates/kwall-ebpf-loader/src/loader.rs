//! Aya-based eBPF program loader and lifecycle manager.

use aya::programs::{Lsm, SchedClassifier, TcAttachType, TracePoint, Xdp, XdpMode};
use aya::{Btf, Ebpf};
use kwall_core::error::{KwallError, Result};
use std::ffi::CString;
use tracing::{info, warn};

/// Manages eBPF program lifecycle and kernel attachments.
pub struct EbpfLoader {
    bpf: Ebpf,
    attached_interfaces: Vec<String>,
}

impl EbpfLoader {
    /// Loads eBPF bytecode into the kernel from an in-memory byte slice.
    pub fn load_from_bytes(bytecode: &[u8]) -> Result<Self> {
        let bpf = Ebpf::load(bytecode)
            .map_err(|e| KwallError::Ebpf(format!("Failed to load eBPF bytecode: {e}")))?;

        info!("eBPF bytecode loaded successfully into kernel");

        Ok(Self {
            bpf,
            attached_interfaces: Vec::new(),
        })
    }

    /// Attaches XDP packet filter to the specified network interface.
    pub fn attach_xdp(&mut self, iface: &str) -> Result<()> {
        let program: &mut Xdp = self
            .bpf
            .program_mut("xdp_ingress")
            .ok_or_else(|| {
                KwallError::Ebpf("Program xdp_ingress not found in bytecode".to_string())
            })?
            .try_into()
            .map_err(|e| KwallError::Ebpf(format!("Failed to cast program to XDP: {e}")))?;

        program
            .load()
            .map_err(|e| KwallError::Ebpf(format!("Failed to load xdp_ingress: {e}")))?;

        let c_iface = CString::new(iface)
            .map_err(|e| KwallError::Ebpf(format!("Invalid interface name: {e}")))?;

        program
            .attach(&c_iface, XdpMode::Default)
            .map_err(|e| KwallError::Ebpf(format!("Failed to attach XDP to {iface}: {e}")))?;

        info!("Attached XDP ingress firewall to interface: {}", iface);
        self.attached_interfaces.push(iface.to_string());
        Ok(())
    }

    /// Attaches TC egress classifier to the specified network interface.
    pub fn attach_tc_egress(&mut self, iface: &str) -> Result<()> {
        let program: &mut SchedClassifier = self
            .bpf
            .program_mut("tc_egress")
            .ok_or_else(|| KwallError::Ebpf("Program tc_egress not found in bytecode".to_string()))?
            .try_into()
            .map_err(|e| {
                KwallError::Ebpf(format!("Failed to cast program to SchedClassifier: {e}"))
            })?;

        program
            .load()
            .map_err(|e| KwallError::Ebpf(format!("Failed to load tc_egress: {e}")))?;

        let c_iface = CString::new(iface)
            .map_err(|e| KwallError::Ebpf(format!("Invalid interface name: {e}")))?;

        program
            .attach(&c_iface, TcAttachType::Egress)
            .map_err(|e| KwallError::Ebpf(format!("Failed to attach TC to {iface}: {e}")))?;

        info!("Attached TC egress classifier to interface: {}", iface);
        Ok(())
    }

    /// Attaches kernel tracepoints for process execution and lifecycle.
    pub fn attach_tracepoints(&mut self) -> Result<()> {
        let exec_prog: &mut TracePoint = self
            .bpf
            .program_mut("sched_process_exec")
            .ok_or_else(|| KwallError::Ebpf("Program sched_process_exec not found".to_string()))?
            .try_into()
            .map_err(|e| {
                KwallError::Ebpf(format!("Failed to cast tracepoint sched_process_exec: {e}"))
            })?;

        exec_prog
            .load()
            .map_err(|e| KwallError::Ebpf(format!("Failed to load sched_process_exec: {e}")))?;
        exec_prog
            .attach("sched", "sched_process_exec")
            .map_err(|e| KwallError::Ebpf(format!("Failed to attach sched_process_exec: {e}")))?;

        let exit_prog: &mut TracePoint = self
            .bpf
            .program_mut("sched_process_exit")
            .ok_or_else(|| KwallError::Ebpf("Program sched_process_exit not found".to_string()))?
            .try_into()
            .map_err(|e| {
                KwallError::Ebpf(format!("Failed to cast tracepoint sched_process_exit: {e}"))
            })?;

        exit_prog
            .load()
            .map_err(|e| KwallError::Ebpf(format!("Failed to load sched_process_exit: {e}")))?;
        exit_prog
            .attach("sched", "sched_process_exit")
            .map_err(|e| KwallError::Ebpf(format!("Failed to attach sched_process_exit: {e}")))?;

        info!("Attached kernel tracepoints for process lifecycle (exec/exit)");
        Ok(())
    }

    /// Attaches LSM security hooks if supported by kernel.
    pub fn attach_lsm(&mut self) -> Result<()> {
        let btf = match Btf::from_sys_fs() {
            Ok(b) => b,
            Err(e) => {
                warn!("BTF not available from sysfs, skipping LSM: {e}");
                return Ok(());
            }
        };

        let lsm_prog: Option<&mut Lsm> = self
            .bpf
            .program_mut("bprm_check_security")
            .and_then(|p| p.try_into().ok());

        if let Some(prog) = lsm_prog {
            if let Err(e) = prog.load("bprm_check_security", &btf) {
                warn!("LSM hook bprm_check_security could not be loaded: {e}");
                return Ok(());
            }
            if let Err(e) = prog.attach() {
                warn!("Failed to attach LSM hook: {e}");
                return Ok(());
            }
            info!("Attached LSM bprm_check_security hook");
        }

        Ok(())
    }

    /// Access reference to loaded Ebpf container.
    pub fn bpf(&self) -> &Ebpf {
        &self.bpf
    }

    /// Access mutable reference to loaded Ebpf container.
    pub fn bpf_mut(&mut self) -> &mut Ebpf {
        &mut self.bpf
    }
}
