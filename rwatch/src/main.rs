mod rule_engine;

use aya::maps::perf::{AsyncPerfEventArray, PerfBufferError};
use aya::programs::TracePoint;
use aya::util::online_cpus;
use bytes::BytesMut;
use tokio::task;
use colored::Colorize;

use rule_engine::RuleEngine;

use rwatch_common::ExecEvent;

#[rustfmt::skip]
use log::{debug, warn,};
use tokio::signal;

use crate::rule_engine::Alert;

fn log_alert(alert: Alert) {
    let log_message = format!(
        "PID={} UID={} COMM={} FILENAME={} -- {}",
        alert.pid, alert.uid, &alert.comm, &alert.filename, &alert.rule.description
    );

    match alert.rule.severity {
        rwatch_common::Severity::Info => info!("[Info]: {}", log_message),
        rwatch_common::Severity::Warning => warn!("[Warning]: {}".yellow(), log_message),
        rwatch_common::Severity::Critical => log::error!("[Critical]: {}".red(), log_message)
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {ret}");
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/rwatch"
    )))?;
    if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {e}");
    }
    let program: &mut TracePoint = ebpf.program_mut("rwatch").unwrap().try_into()?;
    program.load()?;
    program.attach("syscalls", "sys_enter_execve")?;

    let mut perf_array = AsyncPerfEventArray::try_from(ebpf.take_map("EVENTS").unwrap())?;

    // for cpu in cpus {

    //     let mut buf = perf_array.open(cpu_id, None)?;

    //     task::spawn(async move {
    //         let mut buffers = (0..10)
    //             .map(|_| BytesMut::with_capacity(1024))
    //             .collect::<Vec<_>>();

    //         loop {
    //             match buf.read_events(&mut buffers).await {
    //                 Ok(events) => {
    //                     for i in 0..events.read {
    //                         let buf = &buffers[i];
    //                         if buf.len() >= core::mem::size_of::<ExecEvent>() {
    //                             let ptr = buf.as_ptr() as *const ExecEvent;
    //                             let event = unsafe { ptr.read_unaligned() };
    //                             let comm = String::from_utf8_lossy(&event.comm)
    //                                 .trim_end_matches(char::from(0))
    //                                 .to_string();
    //                             info!("Got event: pid={} uid={} comm={}", event.pid, event.uid, comm);
    //                         }
    //                     }
    //                 }
    //                 Err(e) => {
    //                     warn!("failed to read events on cpu {}: {}", cpu_id, e);
    //                 }
    //             }
    //         }
    //     });
    // }
    for cpu_id in online_cpus().map_err(|(msg, e)| anyhow::anyhow!("{msg}: {e}"))? {
        let mut buf = perf_array.open(cpu_id, None)?;

        let rule_engine = RuleEngine::new();

        task::spawn(async move {
            let mut buffers = (0..10)
                .map(|_| BytesMut::with_capacity(1024))
                .collect::<Vec<_>>();

            loop {
                let events = buf.read_events(&mut buffers).await?;

                for i in 0..events.read {
                    let buf = &buffers[i];

                    if buf.len() < std::mem::size_of::<ExecEvent>() {
                        continue;
                    }

                    // let ptr = buf.as_ptr() as *const ExecEvent;

                    let event = unsafe { std::ptr::read_unaligned(buf.as_ptr() as *const ExecEvent) };

                    let alerts = rule_engine.evaluate(&event);

                    for alert in alerts {
                        log_alert(alert);
                    }
                }
            }

            #[allow(unreachable_code)]
            Ok::<_, PerfBufferError>(())
        });
    }

    let ctrl_c = signal::ctrl_c();
    println!("Waiting for Ctrl-C...");
    ctrl_c.await?;
    println!("Exiting...");

    Ok(())
}

