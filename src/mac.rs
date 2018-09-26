//! Implementation of the IEEE 802.15.4 MAC layer


use byteorder::{
    ByteOrder,
    LittleEndian,
};


/// PAN ID and short address
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct Address {
    /// The PAN ID
    pub pan_id: u16,

    /// 16-bit short address
    pub short_addr: u16,
}

impl Address {
    /// Writes the address into a buffer
    ///
    /// # Panics
    ///
    /// Panics, if the buffer is less than 4 bytes long.
    pub fn write(&self, buf: &mut [u8]) {
        LittleEndian::write_u16(buf, self.pan_id);
        LittleEndian::write_u16(&mut buf[2..], self.short_addr);
    }
}
