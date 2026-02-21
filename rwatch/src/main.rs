mod rule_engine;

use aya::maps::perf::{AsyncPerfEventArray, PerfBufferError};
use aya::programs::{KProbe, TracePoint};
use aya::util::online_cpus;
use bytes::BytesMut;
use clap::Parser;
use colored::Colorize;
use std::sync::Arc;
use tokio::task;

use rule_engine::RuleEngine;

use rwatch_common::{ChmodEvent, ConnectEvent, ExecEvent, FileAccessEvent};

#[rustfmt::skip]
use log::{debug, warn, info, error};
use tokio::signal;

use crate::rule_engine::Alert;

#[derive(Parser, Debug)]
#[command(author, version, about = "Real-time threat detection using eBPF + Rust", long_about = None)]
struct Args {
    /// Path to rules configuration file
    #[arg(short, long, default_value = "rules.yaml")]
    config: String,

    /// Output format (text, json)
    #[arg(short, long, default_value = "text")]
    output: String,
}

/// Format IPv4 address from network byte order u32
fn format_ipv4(addr: u32) -> String {
    let bytes = addr.to_ne_bytes();
    format!("{}.{}.{}.{}", bytes[0], bytes[1], bytes[2], bytes[3])
}

fn log_alert(alert: Alert, output_format: &str) {
    if output_format == "json" {
        match serde_json::to_string(&alert) {
            Ok(json) => println!("{}", json),
            Err(e) => error!("Failed to serialize alert to JSON: {}", e),
        }
        return;
    }

    let log_message = format!(
        "PID={} UID={} COMM={} FILENAME={} -- {}",
        alert.pid, alert.uid, &alert.comm, &alert.filename, &alert.rule.description
    );

    match alert.rule.severity {
        rwatch_common::Severity::Info => info!("[Info]: {}", log_message),
        rwatch_common::Severity::Warning => warn!("[Warning]: {}", log_message.yellow()),
        rwatch_common::Severity::Critical => error!("[Critical]: {}", log_message.red()),
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    env_logger::init();

    // Load rules
    let mut rule_engine = RuleEngine::new();
    if std::path::Path::new(&args.config).exists() {
        rule_engine.load_from_file(&args.config)?;
    } else {
        warn!("Config file {} not found, loading defaults", args.config);
        rule_engine.load_defaults();
    }
    let rule_engine = Arc::new(rule_engine);
    let output_format = Arc::new(args.output);

    // Bump the memlock rlimit.
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {ret}");
    }

    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/rwatch"
    )))?;
    if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
        warn!("failed to initialize eBPF logger: {e}");
    }

    // Attach execve tracepoint
    let program: &mut TracePoint = ebpf.program_mut("rwatch").unwrap().try_into()?;
    program.load()?;
    program.attach("syscalls", "sys_enter_execve")?;

    // Attach chmod kprobes
    let program_chmod: &mut KProbe = ebpf.program_mut("detect_chmod").unwrap().try_into()?;
    program_chmod.load()?;
    program_chmod.attach("__x64_sys_chmod", 0)?;

    let program_fchmodat: &mut KProbe = ebpf.program_mut("detect_fchmodat").unwrap().try_into()?;
    program_fchmodat.load()?;
    program_fchmodat.attach("__x64_sys_fchmodat", 0)?;

    // Attach network connect kprobe
    let program_connect: &mut KProbe = ebpf.program_mut("detect_connect").unwrap().try_into()?;
    program_connect.load()?;
    program_connect.attach("tcp_connect", 0)?;

    // Attach file access tracepoint
    let program_file: &mut TracePoint =
        ebpf.program_mut("detect_file_access").unwrap().try_into()?;
    program_file.load()?;
    program_file.attach("syscalls", "sys_enter_openat")?;

    let mut perf_array = AsyncPerfEventArray::try_from(ebpf.take_map("EVENTS").unwrap())?;
    let mut chmod_perf_array =
        AsyncPerfEventArray::try_from(ebpf.take_map("CHMOD_EVENTS").unwrap())?;
    let mut connect_perf_array =
        AsyncPerfEventArray::try_from(ebpf.take_map("CONNECT_EVENTS").unwrap())?;
    let mut file_perf_array = AsyncPerfEventArray::try_from(ebpf.take_map("FILE_EVENTS").unwrap())?;

    // ==================== Exec Events ====================
    for cpu_id in online_cpus().map_err(|(msg, e)| anyhow::anyhow!("{msg}: {e}"))? {
        let mut buf = perf_array.open(cpu_id, None)?;
        let rule_engine = Arc::clone(&rule_engine);
        let output_format = Arc::clone(&output_format);

        task::spawn(async move {
            let mut buffers = (0..10)
                .map(|_| BytesMut::with_capacity(1024))
                .collect::<Vec<_>>();

            loop {
                let events = buf.read_events(&mut buffers).await?;

                for buf in buffers.iter().take(events.read) {
                    if buf.len() < std::mem::size_of::<ExecEvent>() {
                        continue;
                    }

                    let event =
                        unsafe { std::ptr::read_unaligned(buf.as_ptr() as *const ExecEvent) };

                    let alerts = rule_engine.evaluate(&event);

                    for alert in alerts {
                        log_alert(alert, &output_format);
                    }
                }
            }

            #[allow(unreachable_code)]
            Ok::<_, PerfBufferError>(())
        });
    }

    // ==================== Chmod Events ====================
    for cpu_id in online_cpus().map_err(|(msg, e)| anyhow::anyhow!("{msg}: {e}"))? {
        let mut buf = chmod_perf_array.open(cpu_id, None)?;
        let output_format = Arc::clone(&output_format);

        task::spawn(async move {
            let mut buffers = (0..10)
                .map(|_| BytesMut::with_capacity(1024))
                .collect::<Vec<_>>();

            loop {
                let events = buf.read_events(&mut buffers).await?;

                for buf in buffers.iter().take(events.read) {
                    if buf.len() < std::mem::size_of::<ChmodEvent>() {
                        continue;
                    }

                    let event =
                        unsafe { std::ptr::read_unaligned(buf.as_ptr() as *const ChmodEvent) };

                    let filename = String::from_utf8_lossy(&event.filename)
                        .trim_end_matches(char::from(0))
                        .to_string();
                    let comm = String::from_utf8_lossy(&event.comm)
                        .trim_end_matches(char::from(0))
                        .to_string();

                    if *output_format == "json" {
                        let chmod_alert = serde_json::json!({
                            "type": "chmod",
                            "severity": "warning",
                            "description": "Chmod +x detected on suspicious file",
                            "pid": event.pid,
                            "uid": event.uid,
                            "comm": comm,
                            "filename": filename,
                            "mode": format!("{:o}", event.mode)
                        });
                        println!("{}", chmod_alert);
                    } else {
                        let alert_msg = format!(
                            "[ALERT] Chmod +x detected! File: {}, PID: {}, UID: {}, Comm: {}",
                            filename, event.pid, event.uid, comm
                        );
                        warn!("{}", alert_msg.red().bold());
                    }
                }
            }

            #[allow(unreachable_code)]
            Ok::<_, PerfBufferError>(())
        });
    }

    // ==================== Network Connect Events ====================
    for cpu_id in online_cpus().map_err(|(msg, e)| anyhow::anyhow!("{msg}: {e}"))? {
        let mut buf = connect_perf_array.open(cpu_id, None)?;
        let output_format = Arc::clone(&output_format);

        task::spawn(async move {
            let mut buffers = (0..10)
                .map(|_| BytesMut::with_capacity(1024))
                .collect::<Vec<_>>();

            loop {
                let events = buf.read_events(&mut buffers).await?;

                for buf in buffers.iter().take(events.read) {
                    if buf.len() < std::mem::size_of::<ConnectEvent>() {
                        continue;
                    }

                    let event =
                        unsafe { std::ptr::read_unaligned(buf.as_ptr() as *const ConnectEvent) };

                    let comm = String::from_utf8_lossy(&event.comm)
                        .trim_end_matches(char::from(0))
                        .to_string();
                    let dest_ip = format_ipv4(event.dest_addr);
                    let dest_port = u16::from_be(event.dest_port);

                    if *output_format == "json" {
                        let connect_alert = serde_json::json!({
                            "type": "connect",
                            "severity": "info",
                            "description": "Outbound TCP connection detected",
                            "pid": event.pid,
                            "uid": event.uid,
                            "comm": comm,
                            "dest_ip": dest_ip,
                            "dest_port": dest_port
                        });
                        println!("{}", connect_alert);
                    } else {
                        let alert_msg = format!(
                            "[NET] TCP Connect: {}:{} PID={} UID={} COMM={}",
                            dest_ip, dest_port, event.pid, event.uid, comm
                        );
                        info!("{}", alert_msg.cyan());
                    }
                }
            }

            #[allow(unreachable_code)]
            Ok::<_, PerfBufferError>(())
        });
    }

    // ==================== File Access Events (FIM) ====================
    for cpu_id in online_cpus().map_err(|(msg, e)| anyhow::anyhow!("{msg}: {e}"))? {
        let mut buf = file_perf_array.open(cpu_id, None)?;
        let output_format = Arc::clone(&output_format);

        task::spawn(async move {
            let mut buffers = (0..10)
                .map(|_| BytesMut::with_capacity(1024))
                .collect::<Vec<_>>();

            loop {
                let events = buf.read_events(&mut buffers).await?;

                for buf in buffers.iter().take(events.read) {
                    if buf.len() < std::mem::size_of::<FileAccessEvent>() {
                        continue;
                    }

                    let event =
                        unsafe { std::ptr::read_unaligned(buf.as_ptr() as *const FileAccessEvent) };

                    let filename = String::from_utf8_lossy(&event.filename)
                        .trim_end_matches(char::from(0))
                        .to_string();
                    let comm = String::from_utf8_lossy(&event.comm)
                        .trim_end_matches(char::from(0))
                        .to_string();

                    if *output_format == "json" {
                        let file_alert = serde_json::json!({
                            "type": "file_access",
                            "severity": "critical",
                            "description": "Sensitive file access detected",
                            "pid": event.pid,
                            "uid": event.uid,
                            "comm": comm,
                            "filename": filename,
                            "flags": event.flags
                        });
                        println!("{}", file_alert);
                    } else {
                        let alert_msg = format!(
                            "[FIM] Sensitive file accessed: {} PID={} UID={} COMM={}",
                            filename, event.pid, event.uid, comm
                        );
                        error!("{}", alert_msg.red().bold());
                    }
                }
            }

            #[allow(unreachable_code)]
            Ok::<_, PerfBufferError>(())
        });
    }

    let ctrl_c = signal::ctrl_c();
    println!("rwatch is running. Press Ctrl-C to exit.");
    ctrl_c.await?;
    println!("Exiting...");

    Ok(())
}
