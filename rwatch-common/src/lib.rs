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

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ConnectEvent {
    pub pid: u32,
    pub uid: u32,
    pub comm: [u8; 16],
    pub dest_addr: u32, // IPv4 in network byte order
    pub dest_port: u16,
    pub _pad: u16,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct FileAccessEvent {
    pub pid: u32,
    pub uid: u32,
    pub comm: [u8; 16],
    pub filename: [u8; 128],
    pub flags: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "user", derive(serde::Serialize, serde::Deserialize))]
pub enum Severity {
    #[cfg_attr(feature = "user", serde(rename = "info"))]
    Info,
    #[cfg_attr(feature = "user", serde(rename = "warning"))]
    Warning,
    #[cfg_attr(feature = "user", serde(rename = "critical"))]
    Critical,
}
