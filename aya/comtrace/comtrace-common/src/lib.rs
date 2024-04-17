#![no_std]

pub const AF_INET: u16 = 2;

#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct TcpEvent {
    pub saddr: [u8; 16],     // 16
    pub daddr: [u8; 16],     // 16
    pub bytes_received: u64, //  8
    pub bytes_sent: u64,     //  8
    pub tstamp: u64,         //  8
    pub pid: u32,            //  4
    pub oldstate: i32,       //  4
    pub newstate: i32,       //  4
    pub family: u16,         //  2
    pub lport: u16,          //  2
    pub dport: u16,          //  2
    pub comm: [u8; 16],      //  2
    pub pad: [u8; 6],
}

impl Default for TcpEvent {
    fn default() -> Self {
        Self {
            saddr: Default::default(),
            daddr: Default::default(),
            bytes_received: Default::default(),
            bytes_sent: Default::default(),
            tstamp: Default::default(),
            pid: Default::default(),
            oldstate: Default::default(),
            newstate: Default::default(),
            family: Default::default(),
            lport: Default::default(),
            dport: Default::default(),
            comm: Default::default(),
            pad: Default::default(),
        }
    }
}
