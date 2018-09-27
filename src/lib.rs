//! Rust implementation of the IEEE 802.15.4 standard


#![deny(missing_docs)]
#![deny(warnings)]

#![no_std]


#[macro_use] extern crate hash32_derive;

extern crate byteorder;
extern crate hash32;


pub mod mac;
