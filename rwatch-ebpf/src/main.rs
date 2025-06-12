#![no_std]
#![no_main]

use aya_ebpf::{
    macros::{map, tracepoint},
    maps::PerfEventArray,
    programs::TracePointContext,
};
use aya_ebpf::helpers::{
    bpf_get_current_comm,
    bpf_get_current_pid_tgid,
    bpf_get_current_uid_gid
};

use rwatch_common::ExecEvent;


#[map(name = "EVENTS")]
static mut EVENTS: PerfEventArray<ExecEvent> = PerfEventArray::new(0);

#[tracepoint]
pub fn rwatch(ctx: TracePointContext) -> u32 {
    match try_rwatch(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_rwatch(ctx: TracePointContext) -> Result<u32, u32> {

    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;

    let uid_gid = bpf_get_current_uid_gid();
    let uid = (uid_gid & 0xFFFFFFFF) as u32;

    let comm = bpf_get_current_comm().unwrap_or([0; 16]);

    let event = ExecEvent { pid, uid, comm };

    unsafe {
        let events = core::ptr::addr_of_mut!(EVENTS);
        (*events).output(&ctx, &event, 0);
    }

    Ok(0)
}




#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[link_section = "license"]
#[no_mangle]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";