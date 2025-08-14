#![no_std]
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ExecEvent {
    pub pid: u32,
    pub uid: u32,
    pub comm: [u8; 16], // process name (TASK_COMM_LEN),
    pub filename: [u8; 256],
}

pub enum Severity {
    Info,
    Warning,
    Critical
}
