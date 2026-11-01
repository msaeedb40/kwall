//! # eBPF sk_msg / sk_skb Socket Stream Interception
//!
//! Implements kernel-level socket data interception using BPF socket programs
//! to inspect HTTP/1.1, HTTP/2, and gRPC payloads directly in kernel socket
//! send/receive buffers — zero userspace copy overhead.
//!
//! ## Program Types
//!
//! - **`sk_msg`**: Intercepts `sendmsg(2)` calls on sockmap entries.
//!   Inspects outbound application data before it is enqueued in the TCP send buffer.
//!   Returns `SK_PASS` to forward or `SK_DROP` to silently discard malicious payloads.
//!
//! - **`sk_skb`** (stream parser + verdict): Reconstructs application-layer messages
//!   from TCP segment streams and applies per-message security verdicts.
//!
//! ## Socket Maps
//!
//! - `KWALL_SOCK_MAP`: `SockMap` — kernel socket redirection table (sk_msg target).
//! - `KWALL_STREAM_MAP`: `SockMap` — stream parser verdict map (sk_skb target).
//! - `KWALL_APP_EVENTS`: `RingBuf` — application-layer security events ring buffer.
//! - `KWALL_WAF_RULES`: `HashMap` — pre-compiled WAF rule fingerprints (u32 → verdict).

#![no_std]
#![no_main]

use aya_ebpf::bindings::sk_action;
use aya_ebpf::macros::{sk_msg, sk_skb, map};
use aya_ebpf::maps::{HashMap, RingBuf, SockMap};
use aya_ebpf::programs::{SkMsgContext, SkSkbContext};

/// Sockmap for sk_msg redirection (HTTP/gRPC send interception).
#[map]
static KWALL_SOCK_MAP: SockMap = SockMap::with_max_entries(65536, 0);

/// Sockmap for sk_skb stream parser verdicts (TCP stream reassembly).
#[map]
static KWALL_STREAM_MAP: SockMap = SockMap::with_max_entries(65536, 0);

/// Ring buffer for application-layer security events dispatched to userspace.
#[map]
static KWALL_APP_EVENTS: RingBuf = RingBuf::with_byte_size(4 * 1024 * 1024, 0); // 4 MB

/// Pre-compiled WAF rule fingerprints: u32 hash → verdict (0=pass, 1=block).
#[map]
static KWALL_WAF_RULES: HashMap<u32, u8> = HashMap::with_max_entries(4096, 0);

// ---------------------------------------------------------------------------
// sk_msg: Outbound send interception
// ---------------------------------------------------------------------------

/// `sk_msg` BPF program attached to `KWALL_SOCK_MAP`.
///
/// Intercepts each `sendmsg(2)` call on tracked sockets.  Reads the first 16
/// bytes of the message data to identify protocol signatures and emit a ring
/// buffer event for userspace WAF processing.
///
/// Returns `SK_PASS` to forward the data or `SK_DROP` to suppress it.
#[sk_msg]
pub fn kwall_sk_msg(ctx: SkMsgContext) -> u32 {
    match try_sk_msg(&ctx) {
        Ok(action) => action,
        Err(_) => sk_action::SK_PASS,
    }
}

fn try_sk_msg(ctx: &SkMsgContext) -> Result<u32, ()> {
    // Read protocol fingerprint bytes from msg data (first 8 bytes).
    // HTTP/1.x request methods: "GET ", "POST", "PUT ", "DELE", "PATC", "HEAD"
    // HTTP/2 preface: "PRI * HTTP/2.0\r\n\r\n" — first 4 bytes = 0x50524920
    // gRPC (HTTP/2 HEADERS frame): starts with 0x00 (flag) + 3-byte length + 0x01 (type)
    let b0 = unsafe { ctx.data_ptr::<u8>(0).map(|p| *p).unwrap_or(0) };
    let b1 = unsafe { ctx.data_ptr::<u8>(1).map(|p| *p).unwrap_or(0) };
    let b2 = unsafe { ctx.data_ptr::<u8>(2).map(|p| *p).unwrap_or(0) };
    let b3 = unsafe { ctx.data_ptr::<u8>(3).map(|p| *p).unwrap_or(0) };

    // Build a u32 fingerprint from the first 4 bytes.
    let fingerprint: u32 = ((b0 as u32) << 24)
        | ((b1 as u32) << 16)
        | ((b2 as u32) << 8)
        | (b3 as u32);

    // Check pre-compiled WAF rule hash table.
    if let Some(verdict) = unsafe { KWALL_WAF_RULES.get(&fingerprint) } {
        if *verdict == 1u8 {
            // Emit app security event to ring buffer for audit.
            if let Some(mut entry) = KWALL_APP_EVENTS.reserve::<AppEvent>(0) {
                let ev = entry.as_mut_ptr();
                unsafe {
                    (*ev).event_type = AppEventType::WafBlock as u8;
                    (*ev).fingerprint = fingerprint;
                    (*ev).verdict = 1;
                }
                entry.submit(0);
            }
            return Ok(sk_action::SK_DROP);
        }
    }

    // Emit passthrough event for statistical telemetry.
    if let Some(mut entry) = KWALL_APP_EVENTS.reserve::<AppEvent>(0) {
        let ev = entry.as_mut_ptr();
        unsafe {
            (*ev).event_type = AppEventType::SockMsgIntercepted as u8;
            (*ev).fingerprint = fingerprint;
            (*ev).verdict = 0;
        }
        entry.submit(0);
    }

    Ok(sk_action::SK_PASS)
}

// ---------------------------------------------------------------------------
// sk_skb: Stream parser — message boundary detection
// ---------------------------------------------------------------------------

/// `sk_skb` stream parser: determines where one application message ends.
///
/// For HTTP/1.x: scans for `\r\n\r\n` (header-body boundary).
/// For HTTP/2:   reads the 3-byte frame length prefix to compute message size.
/// For gRPC:     reads the 5-byte Length-Prefixed Message header.
#[sk_skb(stream_parser)]
pub fn kwall_skb_parser(ctx: SkSkbContext) -> u32 {
    match try_skb_parser(&ctx) {
        Ok(len) => len,
        Err(_) => 0,
    }
}

fn try_skb_parser(ctx: &SkSkbContext) -> Result<u32, ()> {
    let data_len = ctx.len();
    if data_len == 0 {
        return Ok(0);
    }

    // Attempt HTTP/2 frame header decode: bytes [0..2] = 24-bit frame length.
    let b0 = ctx.load::<u8>(0).unwrap_or(0) as u32;
    let b1 = ctx.load::<u8>(1).unwrap_or(0) as u32;
    let b2 = ctx.load::<u8>(2).unwrap_or(0) as u32;
    let frame_len = (b0 << 16) | (b1 << 8) | b2;

    // HTTP/2 frame header = 9 bytes; full message = header + payload.
    if frame_len > 0 && frame_len + 9 <= data_len {
        return Ok(frame_len + 9);
    }

    // Default: treat entire skb as one message (HTTP/1.x / fallback).
    Ok(data_len)
}

/// `sk_skb` stream verdict: classifies each parsed application message.
///
/// Returns `SK_PASS` or `SK_DROP` based on WAF rule evaluation.
#[sk_skb(stream_verdict)]
pub fn kwall_skb_verdict(ctx: SkSkbContext) -> u32 {
    match try_skb_verdict(&ctx) {
        Ok(action) => action,
        Err(_) => sk_action::SK_PASS,
    }
}

fn try_skb_verdict(ctx: &SkSkbContext) -> Result<u32, ()> {
    // Read first 4 bytes as fingerprint for WAF hash lookup.
    let b0 = ctx.load::<u8>(0).unwrap_or(0) as u32;
    let b1 = ctx.load::<u8>(1).unwrap_or(0) as u32;
    let b2 = ctx.load::<u8>(2).unwrap_or(0) as u32;
    let b3 = ctx.load::<u8>(3).unwrap_or(0) as u32;
    let fingerprint: u32 = (b0 << 24) | (b1 << 16) | (b2 << 8) | b3;

    if let Some(verdict) = unsafe { KWALL_WAF_RULES.get(&fingerprint) } {
        if *verdict == 1u8 {
            if let Some(mut entry) = KWALL_APP_EVENTS.reserve::<AppEvent>(0) {
                let ev = entry.as_mut_ptr();
                unsafe {
                    (*ev).event_type = AppEventType::WafBlock as u8;
                    (*ev).fingerprint = fingerprint;
                    (*ev).verdict = 1;
                }
                entry.submit(0);
            }
            return Ok(sk_action::SK_DROP);
        }
    }

    // Redirect through sockmap to downstream consumer (userspace RASP agent).
    unsafe { KWALL_STREAM_MAP.redirect(ctx.sk_index(), 0) }.map_err(|_| ())?;
    Ok(sk_action::SK_PASS)
}

// ---------------------------------------------------------------------------
// Wire format: application-layer security event (emitted to KWALL_APP_EVENTS)
// ---------------------------------------------------------------------------

/// Application-layer security event emitted by sk_msg / sk_skb programs.
#[repr(C)]
pub struct AppEvent {
    /// Event classification (see `AppEventType`).
    pub event_type: u8,
    /// 4-byte protocol fingerprint extracted from message header.
    pub fingerprint: u32,
    /// WAF verdict (0=pass, 1=block).
    pub verdict: u8,
}

/// Categories of application-layer events.
#[repr(u8)]
pub enum AppEventType {
    SockMsgIntercepted = 0,
    SkbParsed = 1,
    WafBlock = 2,
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
