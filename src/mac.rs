//! Implementation of the IEEE 802.15.4 MAC layer


use core::mem::size_of_val;

use byteorder::{
    ByteOrder,
    LittleEndian,
};


/// MAC frame header
pub struct Header {
    /// Frame Type
    pub frame_type: FrameType,

    /// Auxiliary Security header
    pub security: Security,

    /// Frame Pending
    pub frame_pending: bool,

    /// Acknowledgement Request
    pub ack_request: bool,

    /// PAN ID Compress
    ///
    /// This should eventually just be a `bool`, but as PAN ID compression is
    /// not supported right now, we're using an enum here to suppress the
    /// unsupported option.
    pub pan_id_compress: PanIdCompress,

    /// Destination Address
    ///
    /// Currently only PAN ID and short address format is supported.
    pub destination: Address,

    /// Source Address
    ///
    /// Currently only PAN ID and short address format is supported.
    pub source: Address,

    /// Sequence Number
    pub seq: u8,
}

impl Header {
    /// Writes the header into a buffer
    ///
    /// Returns the number of bytes written.
    ///
    /// # Panics
    ///
    /// Panics, if the buffer is not long enough to hold the header. The header
    /// length depends on the options chosen and varies between 3 and 30 octets
    /// (although the current implementation will, as of this writing, always
    /// write 11 octets).
    pub fn write(&self, buf: &mut [u8]) -> usize {
        let frame_control =
            (self.frame_type      as u16) <<  0 |
            (self.security        as u16) <<  3 |
            (self.frame_pending   as u16) <<  4 |
            (self.ack_request     as u16) <<  5 |
            (self.pan_id_compress as u16) <<  6 |

            0b10 << 10 | // Destination Address Mode (short address)
            0b01 << 12 | // Frame Version
            0b10 << 14;  // Source Address Mode (short address)

        let mut len = 0;

        // Write Frame Control
        LittleEndian::write_u16(&mut buf[len..], frame_control);
        len += size_of_val(&frame_control);

        // Write Sequence Number
        buf[len] = self.seq;
        len += size_of_val(&self.seq);

        // Write destination address
        self.destination.write(&mut buf[len..]);
        len += size_of_val(&self.destination);

        // Write source address
        self.source.write(&mut buf[len..]);
        len += size_of_val(&self.source);

        len
    }
}


/// MAC frame type
#[derive(Clone, Copy, Eq, PartialEq)]
pub enum FrameType {
    /// Beacon
    Beacon = 0b000,

    /// Data
    Data = 0b001,

    /// Acknowledgement
    Acknowledgement = 0b010,

    /// MAC command
    MacCommand = 0b011,
}

/// MAC header auxiliary security header
///
/// Auxiliary security headers are currently unsupported.
#[derive(Clone, Copy, Eq, PartialEq)]
pub enum Security {
    /// No auxiliary security header present
    None = 0b0,
}

/// PAN ID compression
///
/// PAN ID compression is currently not supported.
#[derive(Clone, Copy, Eq, PartialEq)]
pub enum PanIdCompress {
    /// PAN ID compression is disabled
    Disabled = 0b0,
}


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
