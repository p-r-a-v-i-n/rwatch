#![no_std]
#![no_main]

use aya_log_ebpf::info;
use aya_ebpf::{
    macros::{map, tracepoint},
    maps::PerfEventArray,
    programs::TracePointContext,
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
    info!(&ctx, "tracepoint sys_enter_execve called");
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