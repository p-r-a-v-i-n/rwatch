#![no_std]
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ExecEvent {
    pub pid: u32,
    pub uid: u32,
    pub comm: [u8; 16], // process name (TASK_COMM_LEN),
    pub filename: [u8; 256],
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ChmodEvent {
    pub pid: u32,
    pub uid: u32,
    pub mode: u32,
    pub filename: [u8; 256],
    pub comm: [u8; 16],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Info,
    Warning,
    Critical,
}
