//! # eBPF Uprobe-Based TLS Cleartext Inspection
//!
//! Attaches dynamic uprobes to TLS library functions to intercept plaintext payloads
//! **before encryption** (on write) and **after decryption** (on read), without
//! terminating TLS sessions, without requiring certificates, and with zero mTLS disruption.
//!
//! ## Instrumented Libraries
//!
//! | Library              | Write Hook                              | Read Hook                              |
//! |----------------------|-----------------------------------------|----------------------------------------|
//! | OpenSSL / LibreSSL   | `SSL_write` / `SSL_write_ex`            | `SSL_read` / `SSL_read_ex`             |
//! | rustls (Rust)        | `rustls::ConnectionCommon::write_tls`   | `rustls::ConnectionCommon::read_tls`   |
//! | Go `crypto/tls`      | `crypto/tls.(*Conn).Write`              | `crypto/tls.(*Conn).Read`              |
//! | BoringSSL (gVisor)   | `SSL_write`                             | `SSL_read`                             |
//!
//! ## Mechanism
//!
//! Uprobes instrument the function entry point (`uprobe`) to capture the plaintext
//! buffer pointer and length from function arguments (registers `rdi`/`rsi`/`rdx`
//! on x86-64 SysV ABI).  A `uretprobe` captures the return value (bytes processed)
//! and reads the actual cleartext from the process virtual address space via
//! `bpf_probe_read_user`.
//!
//! ## Security Scope
//!
//! Only the first `MAX_CLEARTEXT_CAPTURE_BYTES` bytes are captured per hook invocation
//! to bound stack allocation and avoid verifier complexity.  The captured snippet is
//! forwarded to the `KWALL_TLS_EVENTS` ring buffer for userspace WAF analysis.

#![no_std]
#![no_main]

use aya_ebpf::bindings::BPF_F_NO_PREALLOC;
use aya_ebpf::macros::{map, uprobe, uretprobe};
use aya_ebpf::maps::{HashMap, PerCpuArray, RingBuf};
use aya_ebpf::programs::{ProbeContext, RetProbeContext};
use aya_ebpf::{helpers::bpf_probe_read_user_buf, macros::uprobe as uprobe_attr};

/// Maximum bytes of cleartext payload captured per hook invocation.
const MAX_CLEARTEXT_CAPTURE_BYTES: usize = 512;

/// TLS event ring buffer — cleartext snippets forwarded to userspace WAF.
#[map]
static KWALL_TLS_EVENTS: RingBuf = RingBuf::with_byte_size(8 * 1024 * 1024, 0); // 8 MB

/// Per-CPU scratch buffer: holds (ssl_ptr, buf_ptr, buf_len) between uprobe entry and uretprobe.
/// Keyed by tid (u32), value = TlsCallContext.
#[map]
static KWALL_TLS_CALL_CTX: HashMap<u32, TlsCallContext> =
    HashMap::with_max_entries(8192, BPF_F_NO_PREALLOC);

/// Call context saved at uprobe entry, retrieved at uretprobe exit.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct TlsCallContext {
    /// Pointer to the SSL/TLS object (opaque handle).
    pub ssl_ptr: u64,
    /// Pointer to the plaintext buffer (user virtual address).
    pub buf_ptr: u64,
    /// Buffer size argument (as passed by application).
    pub buf_len: u32,
    /// Direction: 0=write (pre-encrypt), 1=read (post-decrypt).
    pub direction: u8,
    /// Library tag: 0=openssl, 1=rustls, 2=go-tls.
    pub library: u8,
}

/// Captured TLS cleartext event emitted to `KWALL_TLS_EVENTS`.
#[repr(C)]
pub struct TlsCleartextEvent {
    /// Originating PID.
    pub pid: u32,
    /// Thread ID.
    pub tid: u32,
    /// Nanosecond timestamp.
    pub timestamp_ns: u64,
    /// Direction: 0=outbound (pre-encrypt), 1=inbound (post-decrypt).
    pub direction: u8,
    /// Library identifier.
    pub library: u8,
    /// Actual bytes captured (≤ MAX_CLEARTEXT_CAPTURE_BYTES).
    pub captured_bytes: u16,
    /// Cleartext payload snippet.
    pub payload: [u8; MAX_CLEARTEXT_CAPTURE_BYTES],
}

// ---------------------------------------------------------------------------
// OpenSSL: SSL_write entry — save context
// ---------------------------------------------------------------------------

/// Uprobe on `SSL_write(SSL *ssl, const void *buf, int num)`.
///
/// x86-64 SysV: rdi=ssl, rsi=buf, rdx=num
#[uprobe]
pub fn kwall_ssl_write_entry(ctx: ProbeContext) -> u32 {
    try_tls_write_entry(&ctx, 0 /* openssl */);
    0
}

/// Uprobe on `SSL_read(SSL *ssl, void *buf, int num)`.
///
/// At entry the buffer is not yet populated; we only record the pointer.
/// The uretprobe will read the decrypted data after SSL_read returns.
#[uprobe]
pub fn kwall_ssl_read_entry(ctx: ProbeContext) -> u32 {
    try_tls_read_entry(&ctx, 0 /* openssl */);
    0
}

/// Uretprobe on `SSL_write` — capture the plaintext that was just encrypted.
#[uretprobe]
pub fn kwall_ssl_write_exit(ctx: RetProbeContext) -> u32 {
    try_tls_exit(&ctx, 0 /* write */);
    0
}

/// Uretprobe on `SSL_read` — capture the decrypted plaintext returned to the app.
#[uretprobe]
pub fn kwall_ssl_read_exit(ctx: RetProbeContext) -> u32 {
    try_tls_exit(&ctx, 1 /* read */);
    0
}

// ---------------------------------------------------------------------------
// rustls: ConnectionCommon::write_tls / read_tls
// ---------------------------------------------------------------------------

/// Uprobe on `rustls::ConnectionCommon::write_tls`.
///
/// Rust ABI on x86-64: rdi=self (ConnectionCommon ptr), rsi=writer trait object.
/// The plaintext data is held in the internal `deframer` / `message` buffer.
#[uprobe]
pub fn kwall_rustls_write_entry(ctx: ProbeContext) -> u32 {
    try_tls_write_entry(&ctx, 1 /* rustls */);
    0
}

/// Uretprobe on `rustls::ConnectionCommon::write_tls`.
#[uretprobe]
pub fn kwall_rustls_write_exit(ctx: RetProbeContext) -> u32 {
    try_tls_exit(&ctx, 0 /* write */);
    0
}

/// Uprobe on `rustls::ConnectionCommon::read_tls`.
#[uprobe]
pub fn kwall_rustls_read_entry(ctx: ProbeContext) -> u32 {
    try_tls_read_entry(&ctx, 1 /* rustls */);
    0
}

/// Uretprobe on `rustls::ConnectionCommon::read_tls`.
#[uretprobe]
pub fn kwall_rustls_read_exit(ctx: RetProbeContext) -> u32 {
    try_tls_exit(&ctx, 1 /* read */);
    0
}

// ---------------------------------------------------------------------------
// Go crypto/tls: (*Conn).Write / (*Conn).Read
// ---------------------------------------------------------------------------

/// Uprobe on `crypto/tls.(*Conn).Write`.
///
/// Go ABI (register-based, Go 1.17+): AX=*Conn, BX=buf ptr, CX=buf len.
#[uprobe]
pub fn kwall_go_tls_write_entry(ctx: ProbeContext) -> u32 {
    try_tls_write_entry(&ctx, 2 /* go-tls */);
    0
}

/// Uretprobe on `crypto/tls.(*Conn).Write`.
#[uretprobe]
pub fn kwall_go_tls_write_exit(ctx: RetProbeContext) -> u32 {
    try_tls_exit(&ctx, 0 /* write */);
    0
}

/// Uprobe on `crypto/tls.(*Conn).Read`.
#[uprobe]
pub fn kwall_go_tls_read_entry(ctx: ProbeContext) -> u32 {
    try_tls_read_entry(&ctx, 2 /* go-tls */);
    0
}

/// Uretprobe on `crypto/tls.(*Conn).Read`.
#[uretprobe]
pub fn kwall_go_tls_read_exit(ctx: RetProbeContext) -> u32 {
    try_tls_exit(&ctx, 1 /* read */);
    0
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

fn try_tls_write_entry(ctx: &ProbeContext, library: u8) {
    let tid = aya_ebpf::helpers::bpf_get_current_pid_tgid() as u32;
    let ssl_ptr: u64 = ctx.arg(0).unwrap_or(0);
    let buf_ptr: u64 = ctx.arg(1).unwrap_or(0);
    let buf_len: u32 = ctx.arg::<u32>(2).unwrap_or(0);

    let call_ctx = TlsCallContext {
        ssl_ptr,
        buf_ptr,
        buf_len,
        direction: 0, // write
        library,
    };
    unsafe { KWALL_TLS_CALL_CTX.insert(&tid, &call_ctx, 0).ok() };
}

fn try_tls_read_entry(ctx: &ProbeContext, library: u8) {
    let tid = aya_ebpf::helpers::bpf_get_current_pid_tgid() as u32;
    let ssl_ptr: u64 = ctx.arg(0).unwrap_or(0);
    let buf_ptr: u64 = ctx.arg(1).unwrap_or(0);
    let buf_len: u32 = ctx.arg::<u32>(2).unwrap_or(0);

    let call_ctx = TlsCallContext {
        ssl_ptr,
        buf_ptr,
        buf_len,
        direction: 1, // read
        library,
    };
    unsafe { KWALL_TLS_CALL_CTX.insert(&tid, &call_ctx, 0).ok() };
}

fn try_tls_exit(ctx: &RetProbeContext, direction: u8) {
    let pid_tgid = aya_ebpf::helpers::bpf_get_current_pid_tgid();
    let tid = pid_tgid as u32;
    let pid = (pid_tgid >> 32) as u32;

    let call_ctx = match unsafe { KWALL_TLS_CALL_CTX.get(&tid) } {
        Some(c) => *c,
        None => return,
    };
    unsafe { KWALL_TLS_CALL_CTX.remove(&tid).ok() };

    // How many bytes did the TLS function actually process?
    let ret_bytes: i64 = unsafe { ctx.ret().unwrap_or(0) };
    if ret_bytes <= 0 {
        return;
    }
    let capture_len = (ret_bytes as usize).min(MAX_CLEARTEXT_CAPTURE_BYTES) as u16;

    // Reserve ring buffer entry.
    let Some(mut entry) = KWALL_TLS_EVENTS.reserve::<TlsCleartextEvent>(0) else {
        return;
    };
    let ev = entry.as_mut_ptr();

    // Zero-init the payload array to avoid kernel verifier issues with uninitialised memory.
    unsafe {
        (*ev).pid = pid;
        (*ev).tid = tid;
        (*ev).timestamp_ns = aya_ebpf::helpers::bpf_ktime_get_ns();
        (*ev).direction = direction;
        (*ev).library = call_ctx.library;
        (*ev).captured_bytes = capture_len;
        (*ev).payload = [0u8; MAX_CLEARTEXT_CAPTURE_BYTES];

        // Read cleartext from userspace buffer pointer captured at entry.
        let dst = (*ev).payload.as_mut_ptr();
        bpf_probe_read_user_buf(
            call_ctx.buf_ptr as *const u8,
            core::slice::from_raw_parts_mut(dst, capture_len as usize),
        )
        .ok();
    }

    entry.submit(0);
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
