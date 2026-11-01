#![cfg_attr(not(feature = "std"), no_std)]

//! # kwall-ebpf-common
//!
//! Kernel-compatible C ABI structures, binary event wire formats, and BPF map definitions.
//! Can be compiled in `no_std` environments for eBPF targets.

pub mod events;
pub mod maps;
pub mod types;

pub use events::*;
pub use maps::*;
pub use types::*;
