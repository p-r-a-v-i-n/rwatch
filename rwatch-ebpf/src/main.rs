#![no_std]
#![no_main]

use aya_ebpf::helpers::{
    bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid, bpf_probe_read_kernel,
    bpf_probe_read_user_str_bytes,
};
use aya_ebpf::{
    macros::{kprobe, map, tracepoint},
    maps::PerfEventArray,
    programs::{ProbeContext, TracePointContext},
};

use aya_log_ebpf::info;

use rwatch_common::{ChmodEvent, ConnectEvent, ExecEvent, FileAccessEvent};

#[map(name = "EVENTS")]
static mut EVENTS: PerfEventArray<ExecEvent> = PerfEventArray::new(0);

#[map(name = "CHMOD_EVENTS")]
static mut CHMOD_EVENTS: PerfEventArray<ChmodEvent> = PerfEventArray::new(0);

#[map(name = "CONNECT_EVENTS")]
static mut CONNECT_EVENTS: PerfEventArray<ConnectEvent> = PerfEventArray::new(0);

#[map(name = "FILE_EVENTS")]
static mut FILE_EVENTS: PerfEventArray<FileAccessEvent> = PerfEventArray::new(0);

// ==================== Execve Monitoring ====================

#[tracepoint]
pub fn rwatch(ctx: TracePointContext) -> u32 {
    match try_rwatch(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_rwatch(ctx: TracePointContext) -> Result<u32, u32> {
    info!(&ctx, "DEBUG: Execve HIT");
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;

    let uid_gid = bpf_get_current_uid_gid();
    let uid = (uid_gid & 0xFFFFFFFF) as u32;

    let comm = bpf_get_current_comm().unwrap_or([0; 16]);

    let filename_ptr: *const u8 =
        unsafe { ctx.read_at::<*const u8>(16).unwrap_or(core::ptr::null()) };

    let mut event = ExecEvent {
        pid,
        uid,
        comm,
        filename: [0; 256],
    };

    unsafe {
        let _ = bpf_probe_read_user_str_bytes(filename_ptr, &mut event.filename);
        let events = core::ptr::addr_of_mut!(EVENTS);
        (*events).output(&ctx, &event, 0);
    }

    Ok(0)
}

// ==================== Chmod Monitoring ====================

#[repr(C)]
struct PtRegs {
    r15: u64,
    r14: u64,
    r13: u64,
    r12: u64,
    bp: u64,
    bx: u64,
    r11: u64,
    r10: u64,
    r9: u64,
    r8: u64,
    ax: u64,
    cx: u64,
    dx: u64,
    si: u64,
    di: u64,
    orig_ax: u64,
    ip: u64,
    cs: u64,
    flags: u64,
    sp: u64,
    ss: u64,
}

#[kprobe]
pub fn detect_chmod(ctx: ProbeContext) -> u32 {
    match try_detect_chmod(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_detect_chmod(ctx: ProbeContext) -> Result<u32, u32> {
    let regs_ptr: *const PtRegs = ctx.arg(0).unwrap_or(core::ptr::null());

    if regs_ptr.is_null() {
        return Ok(0);
    }

    let regs: PtRegs = unsafe { bpf_probe_read_kernel(regs_ptr).map_err(|_| 0u32)? };
    let (filename_addr, mode) = (regs.di, regs.si);

    let filename_ptr = filename_addr as *const u8;
    let mode_u32 = mode as u32;

    check_chmod(ctx, filename_ptr, mode_u32)
}

#[kprobe]
pub fn detect_fchmodat(ctx: ProbeContext) -> u32 {
    match try_detect_fchmodat(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_detect_fchmodat(ctx: ProbeContext) -> Result<u32, u32> {
    let regs_ptr: *const PtRegs = ctx.arg(0).unwrap_or(core::ptr::null());

    if regs_ptr.is_null() {
        return Ok(0);
    }

    let regs: PtRegs = unsafe { bpf_probe_read_kernel(regs_ptr).map_err(|_| 0u32)? };
    let (filename_addr, mode) = (regs.si, regs.dx);

    let filename_ptr = filename_addr as *const u8;
    let mode_u32 = mode as u32;

    check_chmod(ctx, filename_ptr, mode_u32)
}

fn check_chmod(ctx: ProbeContext, filename_ptr: *const u8, mode: u32) -> Result<u32, u32> {
    if (mode & 0o111) == 0 {
        return Ok(0);
    }

    if filename_ptr.is_null() {
        return Ok(0);
    }

    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    let uid_gid = bpf_get_current_uid_gid();
    let uid = (uid_gid & 0xFFFFFFFF) as u32;
    let comm = bpf_get_current_comm().unwrap_or([0; 16]);

    let mut event = ChmodEvent {
        pid,
        uid,
        mode,
        filename: [0; 256],
        comm,
    };

    unsafe {
        let _ = bpf_probe_read_user_str_bytes(filename_ptr, &mut event.filename);

        let path = &event.filename;

        let prefix_bin = b"/bin/";
        let prefix_usr_bin = b"/usr/bin/";
        let prefix_lib = b"/lib/";
        let prefix_usr_lib = b"/usr/lib/";
        let prefix_usr_sbin = b"/usr/sbin/";
        let prefix_sbin = b"/sbin/";

        let mut allow = false;

        if starts_with(path, prefix_bin) {
            allow = true;
        } else if starts_with(path, prefix_usr_bin) {
            allow = true;
        } else if starts_with(path, prefix_lib) {
            allow = true;
        } else if starts_with(path, prefix_usr_lib) {
            allow = true;
        } else if starts_with(path, prefix_usr_sbin) {
            allow = true;
        } else if starts_with(path, prefix_sbin) {
            allow = true;
        }

        if !allow {
            let events = core::ptr::addr_of_mut!(CHMOD_EVENTS);
            (*events).output(&ctx, &event, 0);
        }
    }

    Ok(0)
}

// ==================== Network Connect Monitoring ====================

/// Kernel struct sock layout offsets (x86_64, may vary by kernel version).
/// We read __sk_common.skc_daddr and __sk_common.skc_dport.
#[kprobe]
pub fn detect_connect(ctx: ProbeContext) -> u32 {
    match try_detect_connect(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_detect_connect(ctx: ProbeContext) -> Result<u32, u32> {
    // tcp_connect(struct sock *sk)
    let sk: *const u8 = ctx.arg(0).unwrap_or(core::ptr::null());
    if sk.is_null() {
        return Ok(0);
    }

    // struct sock -> __sk_common.skc_daddr is at offset 0 of sk_common
    // struct sock -> __sk_common.skc_dport is at offset 12 (after daddr(4) + padding/rcv_saddr(4) + skc_hash(4))
    // These offsets are for typical x86_64 kernels.
    // __sk_common offsets:
    //   skc_daddr: offset 0   (in __sk_common, which is at offset 0 of sock)
    //   skc_rcv_saddr: offset 4
    //   skc_dport: offset 12  (union with skc_num at offset 14)

    let dest_addr: u32 =
        unsafe { bpf_probe_read_kernel((sk as *const u32).byte_offset(0)).map_err(|_| 0u32)? };

    let dest_port: u16 =
        unsafe { bpf_probe_read_kernel((sk as *const u16).byte_offset(12)).map_err(|_| 0u32)? };

    // Skip loopback (127.x.x.x) and zero addresses
    let first_byte = (dest_addr & 0xFF) as u8;
    if first_byte == 127 || dest_addr == 0 {
        return Ok(0);
    }

    // Skip port 0 (not a real connection)
    if dest_port == 0 {
        return Ok(0);
    }

    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    let uid_gid = bpf_get_current_uid_gid();
    let uid = (uid_gid & 0xFFFFFFFF) as u32;
    let comm = bpf_get_current_comm().unwrap_or([0; 16]);

    let event = ConnectEvent {
        pid,
        uid,
        comm,
        dest_addr,
        dest_port,
        _pad: 0,
    };

    unsafe {
        let events = core::ptr::addr_of_mut!(CONNECT_EVENTS);
        (*events).output(&ctx, &event, 0);
    }

    Ok(0)
}

// ==================== File Integrity Monitoring ====================

#[tracepoint]
pub fn detect_file_access(ctx: TracePointContext) -> u32 {
    match try_detect_file_access(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_detect_file_access(ctx: TracePointContext) -> Result<u32, u32> {
    // sys_enter_openat tracepoint:
    //   offset 16: dfd (int)
    //   offset 24: filename (const char __user *)
    //   offset 32: flags (int)

    let filename_ptr: *const u8 =
        unsafe { ctx.read_at::<*const u8>(24).unwrap_or(core::ptr::null()) };

    if filename_ptr.is_null() {
        return Ok(0);
    }

    let flags: u32 = unsafe { ctx.read_at::<u32>(32).unwrap_or(0) };

    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    let uid_gid = bpf_get_current_uid_gid();
    let uid = (uid_gid & 0xFFFFFFFF) as u32;
    let comm = bpf_get_current_comm().unwrap_or([0; 16]);

    let mut event = FileAccessEvent {
        pid,
        uid,
        comm,
        filename: [0; 128],
        flags,
    };

    unsafe {
        let _ = bpf_probe_read_user_str_bytes(filename_ptr, &mut event.filename);
    }

    // Filter: only emit events for sensitive paths
    let is_sensitive = starts_with(&event.filename, b"/etc/shadow")
        || starts_with(&event.filename, b"/etc/passwd")
        || starts_with(&event.filename, b"/etc/sudoers")
        || starts_with(&event.filename, b"/root/.ssh/");

    if !is_sensitive {
        return Ok(0);
    }

    unsafe {
        let events = core::ptr::addr_of_mut!(FILE_EVENTS);
        (*events).output(&ctx, &event, 0);
    }

    Ok(0)
}

// ==================== Utilities ====================

fn starts_with(haystack: &[u8], needle: &[u8]) -> bool {
    if haystack.len() < needle.len() {
        return false;
    }
    for i in 0..needle.len() {
        if haystack[i] != needle[i] {
            return false;
        }
    }
    true
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[link_section = "license"]
#[no_mangle]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
