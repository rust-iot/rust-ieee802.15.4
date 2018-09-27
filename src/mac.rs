//! Implementation of the IEEE 802.15.4 MAC layer


use core::mem::size_of_val;

use byteorder::{
    ByteOrder,
    LittleEndian,
};


/// MAC frame
#[derive(Debug)]
pub struct Frame<'p> {
    /// The frame header
    pub header: Header,

    /// The frame payload
    pub payload: &'p [u8],

    /// The frame footer
    pub footer: [u8; 2],
}

impl<'p> Frame<'p> {
    /// Reads a frame from the buffer
    pub fn read(buf: &'p [u8]) -> Result<Self, ReadError> {
        let (header, len) = Header::read(buf)?;

        if buf[len..].len() < 2 {
            return Err(ReadError::NotAFrame);
        }

        let mut footer     = [0; 2];
        let     footer_pos = buf.len() - 2;
        footer.copy_from_slice(&buf[footer_pos..]);

        let payload = &buf[len .. footer_pos];

        Ok(Frame {
            header,
            payload,
            footer,
        })
    }

    /// Writes the frame into a buffer
    ///
    /// Returns the number of bytes written.
    ///
    /// # Panics
    ///
    /// Panics, if the buffer is not long enough to hold the frame.
    pub fn write(&self, buf: &mut [u8], write_footer: WriteFooter) -> usize {
        let mut len = 0;

        // Write header
        len += self.header.write(&mut buf[len..]);

        // Write payload
        buf[len .. len+self.payload.len()].copy_from_slice(self.payload);
        len += self.payload.len();

        // Write footer
        match write_footer {
            WriteFooter::No => (),
        }

        len
    }
}


/// Tells [`Frame::write`] whether to write the footer
///
/// Eventually, this should support three options:
/// - Don't write the footer
/// - Calculate the 2-byte CRC checksum and write that as the footer
/// - Write the footer as written into the `footer` field
///
/// For now, only not writing the footer is supported.
pub enum WriteFooter {
    /// Don't write the footer
    No,
}


/// MAC frame header
#[derive(Debug)]
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
    /// Reads a header from the buffer
    pub fn read(buf: &[u8]) -> Result<(Self, usize), ReadError> {
        // First, make sure we have enough buffer for the Frame Control field
        if buf.len() < 2 {
            return Err(ReadError::NotAFrame);
        }

        let mut len = 0;

        let frame_type       = (buf[0] >> 0) & 0x7;
        let security         = (buf[0] >> 3) & 0x1;
        let frame_pending    = (buf[0] >> 4) & 0x1;
        let ack_request      = (buf[0] >> 5) & 0x1;
        let pan_id_compress  = (buf[0] >> 6) & 0x1;
        let dest_addr_mode   = (buf[1] >> 2) & 0x3;
        let frame_version    = (buf[1] >> 4) & 0x3;
        let source_addr_mode = (buf[1] >> 6) & 0x3;

        let frame_type = FrameType::from_bits(frame_type)
            .ok_or(ReadError::InvalidFrameType(frame_type))?;
        let security = Security::from_bits(security)
            .ok_or(ReadError::SecurityNotSupported)?;
        let frame_pending = frame_pending == 0b1;
        let ack_request = ack_request == 0b1;
        let pan_id_compress = PanIdCompress::from_bits(pan_id_compress)
            .ok_or(ReadError::PanIdCompressNotSupported)?;

        if dest_addr_mode != 0b10 {
            return Err(ReadError::AddressModeNotSupported(dest_addr_mode));
        }
        if frame_version != 0b01 {
            return Err(ReadError::InvalidFrameVersion(frame_version));
        }
        if source_addr_mode != 0b10 {
            return Err(ReadError::AddressModeNotSupported(source_addr_mode));
        }

        len += 2;

        let seq = buf[len];
        len += 1;

        let (destination, addr_len) = Address::read(&buf[len..])?;
        len += addr_len;

        let (source, addr_len) = Address::read(&buf[len..])?;
        len += addr_len;

        let header = Header {
            frame_type,
            security,
            frame_pending,
            ack_request,
            pan_id_compress,
            seq,
            destination,
            source,
        };

        Ok((header, len))
    }

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

        // Write addresses
        len += self.destination.write(&mut buf[len..]);
        len += self.source.write(&mut buf[len..]);

        len
    }
}


/// MAC frame type
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
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

impl FrameType {
    /// Creates an instance from the value given
    pub fn from_bits(bits: u8) -> Option<Self> {
        match bits {
            0b000 => Some(FrameType::Beacon),
            0b001 => Some(FrameType::Data),
            0b010 => Some(FrameType::Acknowledgement),
            0b011 => Some(FrameType::MacCommand),
            _     => None,
        }
    }
}


/// MAC header auxiliary security header
///
/// Auxiliary security headers are currently unsupported.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Security {
    /// No auxiliary security header present
    None = 0b0,
}

impl Security {
    /// Creates an instance from the value given
    pub fn from_bits(bits: u8) -> Option<Self> {
        match bits {
            0b0 => Some(Security::None),
            _   => None,
        }
    }
}


/// PAN ID compression
///
/// PAN ID compression is currently not supported.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PanIdCompress {
    /// PAN ID compression is disabled
    Disabled = 0b0,
}

impl PanIdCompress {
    /// Creates an instance from the value given
    pub fn from_bits(bits: u8) -> Option<Self> {
        match bits {
            0b0 => Some(PanIdCompress::Disabled),
            _   => None,
        }
    }
}


/// PAN ID and short address
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Address {
    /// The PAN ID
    pub pan_id: u16,

    /// 16-bit short address
    pub short_addr: u16,
}

impl Address {
    /// Returns the broadcast address
    pub fn broadcast() -> Self {
        Address {
            pan_id:     0xffff,
            short_addr: 0xffff,
        }
    }

    /// Reads an address from the buffer
    pub fn read(buf: &[u8]) -> Result<(Self, usize), ReadError> {
        if buf.len() < 4 {
            return Err(ReadError::NotAFrame);
        }

        let mut len = 0;

        let pan_id = LittleEndian::read_u16(&buf[len..]);
        len += size_of_val(&pan_id);

        let short_addr = LittleEndian::read_u16(&buf[len..]);
        len += size_of_val(&short_addr);

        let address = Address {
            pan_id,
            short_addr,
        };

        Ok((address, len))
    }

    /// Writes the address into a buffer
    ///
    /// # Panics
    ///
    /// Panics, if the buffer is less than 4 bytes long.
    pub fn write(&self, buf: &mut [u8]) -> usize {
        let mut len = 0;

        LittleEndian::write_u16(&mut buf[len..], self.pan_id);
        len += size_of_val(&self.pan_id);

        LittleEndian::write_u16(&mut buf[len..], self.short_addr);
        len += size_of_val(&self.short_addr);

        len
    }
}


/// Signals an error that occured while reading a frame
#[derive(Debug)]
pub enum ReadError {
    /// Buffer does not contain a full frame
    NotAFrame,

    /// The frame type is not recognized
    InvalidFrameType(u8),

    /// The frame has the security bit set, which is not supported
    SecurityNotSupported,

    /// The frame compresses the PAN ID, which is not supported
    PanIdCompressNotSupported,

    /// The frame's address mode is not supported
    AddressModeNotSupported(u8),

    /// The frame's version is invalid or not supported
    InvalidFrameVersion(u8),
}
