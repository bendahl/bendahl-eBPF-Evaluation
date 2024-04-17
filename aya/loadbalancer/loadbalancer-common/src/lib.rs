#![no_std]

#[repr(C)]
pub enum Setting {
    Port,
    NoBackens,
    OutIf,
}
