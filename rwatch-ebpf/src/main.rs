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

use rwatch_common::{ChmodEvent, ExecEvent};

#[map(name = "EVENTS")]
static mut EVENTS: PerfEventArray<ExecEvent> = PerfEventArray::new(0);

#[map(name = "CHMOD_EVENTS")]
static mut CHMOD_EVENTS: PerfEventArray<ChmodEvent> = PerfEventArray::new(0);

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
    // __x64_sys_chmod(struct pt_regs *regs)
    // filename = regs->di
    // mode = regs->si

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
    // __x64_sys_fchmodat(struct pt_regs *regs)
    // dfd = regs->di
    // filename = regs->si
    // mode = regs->dx

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
    // Check if executable bit is set
    // 0100 (user exec) | 0010 (group exec) | 0001 (other exec).
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
