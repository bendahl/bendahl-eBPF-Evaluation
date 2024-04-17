#![no_std]
pub mod jittergen;

#[repr(C)]
pub enum Setting {Action, Protocol, Port, Percent, MinLat, MaxLat}

pub const JITTER: u16 = 1;
pub const DROP: u16 = 2;
pub const REORDER: u16 = 3;
