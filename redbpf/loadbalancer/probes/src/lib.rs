#![no_std]
pub mod loadbalancer;

#[repr(C)]
pub enum Setting {
    Port,
    NoBackens,
    OutIf,
}