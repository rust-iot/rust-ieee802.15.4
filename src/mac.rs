//! Partial implementation of the IEEE 802.15.4 MAC layer
//!
//! The main type in this module is [Frame], a type that represents an IEEE
//! 802.15.4 MAC frame. The other types in this module are supporting types
//! that are either part of [Frame] or are required to support its API.
//!
//! [Frame]: struct.Frame.html


use core::mem::size_of_val;

use byteorder::{
    ByteOrder,
    LittleEndian,
};
use hash32_derive::Hash32;


/// An IEEE 802.15.4 MAC frame
///
/// Represents a MAC frame. Can be used to [decode] a frame from bytes, or
/// [encode] a frame to bytes.
///
/// [decode]: #method.decode
/// [encode]: #method.encode
#[derive(Debug)]
pub struct Frame<'p> {
    /// Header
    pub header: Header,

    /// Payload
    pub payload: &'p [u8],

    /// Footer
    ///
    /// This is a 2-byte CRC checksum.
    ///
    /// When creating an instance of this struct for encoding, you don't
    /// necessarily need to write an actual CRC checksum here. [`Frame::encode`]
    /// can omit writing this checksum, for example if the transceiver hardware
    /// automatically adds the checksum for you.
    pub footer: [u8; 2],
}

impl<'p> Frame<'p> {
    /// Decodes a frame from a byte buffer
    ///
    /// # Errors
    ///
    /// This function returns an error, if the bytes either don't encode a valid
    /// IEEE 802.15.4 frame, or encode a frame that is not fully supported by
    /// this implementation. Please refer to [`DecodeError`] for details.
    ///
    /// # Example
    ///
    /// ``` rust
    /// use ieee802154::mac::{
    ///     Address,
    ///     ShortAddress,
    ///     Frame,
    ///     FrameType,
    ///     PanId,
    ///     Security,
    /// };
    ///
    /// # fn main() -> Result<(), ::ieee802154::mac::DecodeError> {
    /// // Construct a simple MAC frame. The CRC checksum (the last 2 bytes) is
    /// // invalid, for the sake of convenience.
    /// let bytes = [
    ///     0x01, 0x98,             // frame control
    ///     0x00,                   // sequence number
    ///     0x12, 0x34, 0x56, 0x78, // PAN identifier and address of destination
    ///     0x12, 0x34, 0x9a, 0xbc, // PAN identifier and address of source
    ///     0xde, 0xf0,             // payload
    ///     0x12, 0x34,             // footer
    /// ];
    ///
    /// let frame = Frame::decode(&bytes)?;
    ///
    /// assert_eq!(frame.header.seq,             0x00);
    /// assert_eq!(frame.header.frame_type,      FrameType::Data);
    /// assert_eq!(frame.header.security,        Security::None);
    /// assert_eq!(frame.header.frame_pending,   false);
    /// assert_eq!(frame.header.ack_request,     false);
    /// assert_eq!(frame.header.pan_id_compress, false);
    ///
    /// assert_eq!(
    ///     frame.header.destination,
    ///     Address::Short(PanId(0x3412), ShortAddress(0x7856))
    /// );
    /// assert_eq!(
    ///     frame.header.source,
    ///     Address::Short(PanId(0x3412), ShortAddress(0xbc9a))
    /// );
    ///
    /// assert_eq!(frame.payload, &[0xde, 0xf0]);
    /// assert_eq!(frame.footer,  [0x12, 0x34]);
    /// #
    /// # Ok(())
    /// # }
    /// ```
    pub fn decode(buf: &'p [u8]) -> Result<Self, DecodeError> {
        let (header, len) = Header::decode(buf)?;

        if buf[len..].len() < 2 {
            return Err(DecodeError::NotEnoughBytes);
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

    /// Encodes the frame into a buffer
    ///
    /// Returns the number of bytes written to the buffer.
    ///
    /// # Panics
    ///
    /// Panics, if the buffer is not long enough to hold the frame. If you
    /// believe that this behavior is inappropriate, please leave your feedback
    /// on the [issue tracker].
    ///
    /// # Example
    ///
    /// ``` rust
    /// use ieee802154::mac::{
    ///     Address,
    ///     ShortAddress,
    ///     Frame,
    ///     FrameType,
    ///     FrameVersion,
    ///     Header,
    ///     PanId,
    ///     Security,
    ///     WriteFooter,
    /// };
    ///
    /// let frame = Frame {
    ///     header: Header {
    ///         seq:             0x00,
    ///         frame_type:      FrameType::Data,
    ///         security:        Security::None,
    ///         frame_pending:   false,
    ///         ack_request:     false,
    ///         pan_id_compress: false,
    ///         version:         FrameVersion::Ieee802154_2006,
    ///
    ///         destination: Address::Short(PanId(0x1234), ShortAddress(0x5678)),
    ///         source:      Address::Short(PanId(0x1234), ShortAddress(0x9abc)),
    ///     },
    ///
    ///     payload: &[0xde, 0xf0],
    ///     footer:  [0x12, 0x34]
    /// };
    ///
    /// let mut bytes = [0u8; 32];
    ///
    /// frame.encode(&mut bytes, WriteFooter::No);
    ///
    /// let expected_bytes = [
    ///     0x01, 0x98,             // frame control
    ///     0x00,                   // sequence number
    ///     0x34, 0x12, 0x78, 0x56, // PAN identifier and address of destination
    ///     0x34, 0x12, 0xbc, 0x9a, // PAN identifier and address of source
    ///     0xde, 0xf0,             // payload
    ///     0x00, 0x00,             // footer, not written
    /// ];
    /// assert_eq!(bytes[..expected_bytes.len()], expected_bytes[..]);
    /// ```
    ///
    /// [issue tracker]: https://github.com/braun-robotics/ieee-802.15.4/issues/9
    pub fn encode(&self, buf: &mut [u8], write_footer: WriteFooter) -> usize {
        let mut len = 0;

        // Write header
        len += self.header.encode(&mut buf[len..]);

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

/// Tells [`Frame::encode`] whether to write the footer
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
    pub pan_id_compress: bool,

    /// Frame version
    pub version: FrameVersion,

    /// Destination Address
    pub destination: Address,

    /// Source Address
    pub source: Address,

    /// Sequence Number
    pub seq: u8,
}

impl Header {
    /// Decodes a header from a byte buffer
    ///
    /// This method is used by [`Frame::decode`] to decode the frame header.
    /// Unless you decide to write your own code for decoding frames, there
    /// should be no reason to call this method directly.
    ///
    /// # Errors
    ///
    /// This function returns an error, if the bytes either don't encode a valid
    /// IEEE 802.15.4 frame header, or encode a frame header that is not fully
    /// supported by this implementation. Please refer to [`DecodeError`] for
    /// details.
    ///
    /// # Example
    ///
    /// ``` rust
    /// use ieee802154::mac::{
    ///     Address,
    ///     ShortAddress,
    ///     FrameType,
    ///     Header,
    ///     PanId,
    ///     Security,
    /// };
    ///
    /// # fn main() -> Result<(), ::ieee802154::mac::DecodeError> {
    /// // Construct a simple header.
    /// let bytes = [
    ///     0x01, 0x98,             // frame control
    ///     0x00,                   // sequence number
    ///     0x12, 0x34, 0x56, 0x78, // PAN identifier and address of destination
    ///     0x12, 0x34, 0x9a, 0xbc, // PAN identifier and address of source
    /// ];
    ///
    /// let (header, num_bytes) = Header::decode(&bytes)?;
    ///
    /// assert_eq!(num_bytes, bytes.len());
    ///
    /// assert_eq!(header.seq,             0x00);
    /// assert_eq!(header.frame_type,      FrameType::Data);
    /// assert_eq!(header.security,        Security::None);
    /// assert_eq!(header.frame_pending,   false);
    /// assert_eq!(header.ack_request,     false);
    /// assert_eq!(header.pan_id_compress, false);
    ///
    /// assert_eq!(
    ///     header.destination,
    ///     Address::Short(PanId(0x3412), ShortAddress(0x7856))
    /// );
    /// assert_eq!(
    ///     header.source,
    ///     Address::Short(PanId(0x3412), ShortAddress(0xbc9a))
    /// );
    /// #
    /// # Ok(())
    /// # }
    /// ```
    pub fn decode(buf: &[u8]) -> Result<(Self, usize), DecodeError> {
        // First, make sure we have enough buffer for the Frame Control field
        if buf.len() < 2 {
            return Err(DecodeError::NotEnoughBytes);
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
            .ok_or(DecodeError::InvalidFrameType(frame_type))?;
        let security = Security::from_bits(security)
            .ok_or(DecodeError::SecurityNotSupported)?;
        let frame_pending = frame_pending == 0b1;
        let ack_request = ack_request == 0b1;
        let pan_id_compress = pan_id_compress == 0x01;
        let dest_addr_mode = AddressMode::from_bits(dest_addr_mode)?;
        let source_addr_mode = AddressMode::from_bits(source_addr_mode)?;

        if frame_version > 0b01 {
            return Err(DecodeError::InvalidFrameVersion(frame_version));
        }
        let version = FrameVersion::from_bits(frame_version)
            .ok_or(DecodeError::InvalidFrameVersion(frame_version))?;
        len += 2;

        let seq = buf[len];
        len += 1;

        let (destination, addr_len) = Address::decode(&buf[len..], &dest_addr_mode)?;
        len += addr_len;

        let source = if !pan_id_compress {
            let (source, addr_len) = Address::decode(&buf[len..], &source_addr_mode)?;
            len += addr_len;
            source
        } else {
            let pan_id = destination.pan_id()
                .ok_or(DecodeError::InvalidAddressMode(dest_addr_mode as u8))?;
            let (source, addr_len) = Address::decode_compress(
                &buf[len..],
                &source_addr_mode,
                pan_id,
            )?;
            len += addr_len;
            source
        };

        let header = Header {
            frame_type,
            security,
            frame_pending,
            ack_request,
            pan_id_compress,
            version,
            destination,
            source,
            seq,
        };

        Ok((header, len))
    }

    /// Encodes the header into a buffer
    ///
    /// Returns the number of bytes written to the buffer.
    ///
    /// # Panics
    ///
    /// Panics, if the buffer is not long enough to hold the header. If you
    /// believe that this behavior is inappropriate, please leave your feedback
    /// on the [issue tracker]. Will also panic if the destination PAN
    /// identifier differs from the source PAN identifier when using PAN
    /// identifier compress.
    ///
    /// The header length depends on the options chosen and varies between 3 and
    /// 30 octets.
    ///
    /// # Example
    ///
    /// ``` rust
    /// use ieee802154::mac::{
    ///     Address,
    ///     ShortAddress,
    ///     FrameType,
    ///     FrameVersion,
    ///     Header,
    ///     PanId,
    ///     Security,
    /// };
    ///
    /// let header = Header {
    ///     seq:             0x00,
    ///     frame_type:      FrameType::Data,
    ///     security:        Security::None,
    ///     frame_pending:   false,
    ///     ack_request:     false,
    ///     pan_id_compress: false,
    ///     version:         FrameVersion::Ieee802154_2006,
    ///
    ///     destination: Address::Short(PanId(0x1234), ShortAddress(0x5678)),
    ///     source:      Address::Short(PanId(0x1234), ShortAddress(0x9abc)),
    /// };
    ///
    /// let mut bytes = [0u8; 11];
    ///
    /// header.encode(&mut bytes);
    ///
    /// let expected_bytes = [
    ///     0x01, 0x98,             // frame control
    ///     0x00,                   // sequence number
    ///     0x34, 0x12, 0x78, 0x56, // PAN identifier and address of destination
    ///     0x34, 0x12, 0xbc, 0x9a, // PAN identifier and address of source
    /// ];
    /// assert_eq!(bytes[..expected_bytes.len()], expected_bytes[..]);
    /// ```
    ///
    /// [issue tracker]: https://github.com/braun-robotics/ieee-802.15.4/issues/9
    pub fn encode(&self, buf: &mut [u8]) -> usize {
        let frame_control = (self.frame_type as u16) << 0
            | (self.security as u16) << 3
            | (self.frame_pending as u16) << 4
            | (self.ack_request as u16) << 5
            | (self.pan_id_compress as u16) << 6
            | (self.destination.address_mode() as u16) << 10
            | (self.version as u16) << 12
            | (self.source.address_mode() as u16) << 14;

        let mut len = 0;

        // Write Frame Control
        LittleEndian::write_u16(&mut buf[len..], frame_control);
        len += size_of_val(&frame_control);

        // Write Sequence Number
        buf[len] = self.seq;
        len += size_of_val(&self.seq);

        // Write addresses
        len += self.destination.encode(&mut buf[len..]);
        len += if self.pan_id_compress {
            assert_eq!(self.destination.pan_id(), self.source.pan_id());
            self.source.encode_compress(&mut buf[len..])
        } else {
            self.source.encode(&mut buf[len..])
        };

        len
    }
}

/// Defines the type of a MAC frame
///
/// Part of [`Header`].
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
    /// Creates an instance of [`FrameType`] from the provided bits
    ///
    /// Returns `None`, if the provided bits don't encode a valid frame type.
    ///
    /// # Example
    ///
    /// ``` rust
    /// use ieee802154::mac::FrameType;
    ///
    /// let frame_type = FrameType::from_bits(0b001);
    /// assert_eq!(frame_type, Some(FrameType::Data));
    /// ```
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


/// Defines whether an auxiliary security header is present in the MAC header
///
/// Part of [`Header`]. Auxiliary security headers are currently unsupported by
/// this implementation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Security {
    /// No auxiliary security header is present
    None = 0b0,
}

impl Security {
    /// Creates an instance of [`Security`] from the provided bits
    ///
    /// Returns `None`, if the provided bits don't encode a valid value of
    /// `Security`.
    ///
    /// # Example
    ///
    /// ``` rust
    /// use ieee802154::mac::Security;
    ///
    /// let security = Security::from_bits(0b0);
    /// assert_eq!(security, Some(Security::None));
    /// ```
    pub fn from_bits(bits: u8) -> Option<Self> {
        match bits {
            0b0 => Some(Security::None),
            _ => None,
        }
    }
}

/// Defines version information for a frame
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FrameVersion {
    /// A frame conforming to the 802.15.4-2003 standard
    Ieee802154_2003 = 0b00,
    /// A frame conforming to the 802.15.4-2006 standard
    Ieee802154_2006 = 0b01,
    /// A frame conforming to the current 802.15.4 standard
    Ieee802154 = 0b10,
}

impl FrameVersion {
    /// Creates an instance of [`FrameVersion`] from the provided bits
    ///
    /// Returns `None`, if the provided bits don't encode a valid value of
    /// `FrameVersion`.
    ///
    /// # Example
    ///
    /// ``` rust
    /// use ieee802154::mac::FrameVersion;
    ///
    /// let version = FrameVersion::from_bits(0b0);
    /// assert_eq!(version, Some(FrameVersion::Ieee802154_2003));
    /// ```
    pub fn from_bits(bits: u8) -> Option<Self> {
        match bits {
            0b00 => Some(FrameVersion::Ieee802154_2003),
            0b01 => Some(FrameVersion::Ieee802154_2006),
            0b10 => Some(FrameVersion::Ieee802154),
            _ => None,
        }
    }
}

/// Defines the type of Address
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AddressMode {
    /// PAN identifier and address field are not present
    None = 0b00,
    /// Address field contains a 16 bit short address
    Short = 0b10,
    /// Address field contains a 64 bit extended address
    Extended = 0b11,
}

impl AddressMode {
    /// Creates an instance of [`AddressMode`] from the provided bits
    ///
    /// Returns `None`, if the provided bits don't encode a valid value of
    /// `AddressMode`.
    ///
    /// # Example
    ///
    /// ``` rust
    /// use ieee802154::mac::AddressMode;
    ///
    /// let address_mode = AddressMode::from_bits(0b10).unwrap();
    /// assert_eq!(address_mode, AddressMode::Short);
    /// ```
    pub fn from_bits(bits: u8) -> Result<Self, DecodeError> {
        match bits {
            0b00 => Ok(AddressMode::None),
            0b10 => Ok(AddressMode::Short),
            0b11 => Ok(AddressMode::Extended),
            _ => Err(DecodeError::InvalidAddressMode(bits)),
        }
    }
}

/// Personal Area Network Identifier
///
/// A 16-bit value that identifies a PAN
#[derive(Clone, Copy, Debug, Eq, Hash, Hash32, PartialEq)]
pub struct PanId(pub u16);

impl PanId {
    /// Get the broadcast PAN identifier
    pub fn broadcast() -> Self {
        Self(0xffff)
    }

    /// Decodes an PAN identifier from a byte buffer
    ///
    /// # Errors
    ///
    /// This function returns an error, if there are not enough bytes in the
    /// buffer to encode a valid `Address` instance.
    ///
    /// # Example
    ///
    /// ``` rust
    /// use ieee802154::mac::PanId;
    ///
    /// # fn main() -> Result<(), ::ieee802154::mac::DecodeError> {
    /// let bytes = [0x56, 0x78];
    /// let (address, num_bytes) = PanId::decode(&bytes)?;
    ///
    /// assert_eq!(num_bytes, bytes.len());
    /// assert_eq!(address.0, 0x7856);
    /// #
    /// # Ok(())
    /// # }
    /// ```
    pub fn decode(buf: &[u8]) -> Result<(Self, usize), DecodeError> {
        if buf.len() < 2 {
            return Err(DecodeError::NotEnoughBytes);
        }

        let pan_id = LittleEndian::read_u16(buf);
        let len = size_of_val(&pan_id);

        Ok((PanId(pan_id), len))
    }

    /// Encodes the PAN identifier into a buffer
    ///
    /// Returns the number of bytes written to the buffer.
    ///
    /// # Panics
    ///
    /// Panics, if the buffer is less than 2 bytes long. If you believe that
    /// this behavior is inappropriate, please leave your feedback on the
    /// [issue tracker].
    ///
    /// # Example
    ///
    /// ``` rust
    /// use ieee802154::mac::PanId;
    ///
    /// let address = PanId(0x1234);
    ///
    /// let mut bytes = [0u8; 2];
    /// address.encode(&mut bytes);
    ///
    /// let expected_bytes = [0x34, 0x12];
    /// assert_eq!(bytes[..expected_bytes.len()], expected_bytes[..]);
    /// ```
    ///
    /// [issue tracker]: https://github.com/braun-robotics/ieee-802.15.4/issues/9
    pub fn encode(&self, buf: &mut [u8]) -> usize {
        LittleEndian::write_u16(buf, self.0);
        size_of_val(&self.0)
    }
}

/// A 16-bit short address
///
/// Short address assigned to a device during association, used to identify the
/// device in the PAN.
#[derive(Clone, Copy, Debug, Eq, Hash, Hash32, PartialEq)]
pub struct ShortAddress(pub u16);

impl ShortAddress {
    /// Creates an instance of `Address` that presents the broadcast address
    pub fn broadcast() -> Self {
        ShortAddress(0xffff)
    }

    /// Decodes an address from a byte buffer
    ///
    /// This method is used by [`Header::decode`] to decode addresses. Unless
    /// you decide to write your own code for decoding headers, there should be
    /// no reason to call this method directly.
    ///
    /// # Errors
    ///
    /// This function returns an error, if there are not enough bytes in the
    /// buffer to encode a valid `Address` instance.
    ///
    /// # Example
    ///
    /// ``` rust
    /// use ieee802154::mac::ShortAddress;
    ///
    /// # fn main() -> Result<(), ::ieee802154::mac::DecodeError> {
    /// let bytes = [0x56, 0x78];
    /// let (address, num_bytes) = ShortAddress::decode(&bytes)?;
    ///
    /// assert_eq!(num_bytes, bytes.len());
    /// assert_eq!(address, ShortAddress(0x7856));
    /// #
    /// # Ok(())
    /// # }
    /// ```
    pub fn decode(buf: &[u8]) -> Result<(Self, usize), DecodeError> {
        if buf.len() < 2 {
            return Err(DecodeError::NotEnoughBytes);
        }

        let addr = LittleEndian::read_u16(&buf);

        Ok((ShortAddress(addr), size_of_val(&addr)))
    }

    /// Encodes the address into a buffer
    ///
    /// Returns the number of bytes written to the buffer.
    ///
    /// # Panics
    ///
    /// Panics, if the buffer is less than 2 bytes long. If you believe that
    /// this behavior is inappropriate, please leave your feedback on the
    /// [issue tracker].
    ///
    /// # Example
    ///
    /// ``` rust
    /// use ieee802154::mac::ShortAddress;
    ///
    /// let address = ShortAddress(0x5678);
    ///
    /// let mut bytes = [0u8; 2];
    /// address.encode(&mut bytes);
    ///
    /// let expected_bytes = [0x78, 0x56];
    /// assert_eq!(bytes[..expected_bytes.len()], expected_bytes[..]);
    /// ```
    ///
    /// [issue tracker]: https://github.com/braun-robotics/ieee-802.15.4/issues/9
    pub fn encode(&self, buf: &mut [u8]) -> usize {
        LittleEndian::write_u16(buf, self.0);
        size_of_val(&self.0)
    }
}

/// A 64-bit extended address
///
/// A unique address that is used to identify an device in the PAN.
#[derive(Clone, Copy, Debug, Eq, Hash, Hash32, PartialEq)]
pub struct ExtendedAddress(pub u64);

impl ExtendedAddress {
    /// Creates an instance of `Address` that presents the broadcast address
    pub fn broadcast() -> Self {
        ExtendedAddress(0xffffffffffffffffu64)
    }

    /// Decodes an address from a byte buffer
    pub fn decode(buf: &[u8]) -> Result<(Self, usize), DecodeError> {
        if buf.len() < 8 {
            return Err(DecodeError::NotEnoughBytes);
        }
        let addr = LittleEndian::read_u64(&buf);
        Ok((ExtendedAddress(addr), size_of_val(&addr)))
    }

    /// Encodes the address into a buffer
    pub fn encode(&self, buf: &mut [u8]) -> usize {
        LittleEndian::write_u64(buf, self.0);
        size_of_val(&self.0)
    }
}

/// An address that might contain an PAN ID and address
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Address {
    /// No address
    None,
    /// Short (16-bit) address and PAN ID (16-bit)
    Short(PanId, ShortAddress),
    /// Extended (64-bit) address and PAN ID (16-bit)
    Extended(PanId, ExtendedAddress),
}

impl Address {
    /// Creates an instance of `Address` that represents the broadcast address
    pub fn broadcast(mode: &AddressMode) -> Self {
        match mode {
            AddressMode::None => Address::None,
            AddressMode::Short => Address::Short(PanId::broadcast(), ShortAddress::broadcast()),
            AddressMode::Extended => {
                Address::Extended(PanId::broadcast(), ExtendedAddress::broadcast())
            }
        }
    }

    /// Decodes an address from a byte buffer
    pub fn decode(buf: &[u8], mode: &AddressMode) -> Result<(Self, usize), DecodeError> {
        let (address, len) = match mode {
            AddressMode::None => (Address::None, 0),
            AddressMode::Short => {
                let mut length = 0;
                let (i, l) = PanId::decode(buf)?;
                length += l;
                let (a, l) = ShortAddress::decode(&buf[l..])?;
                length += l;
                (Address::Short(i, a), length)
            }
            AddressMode::Extended => {
                let mut length = 0;
                let (i, l) = PanId::decode(buf)?;
                length += l;
                let (a, l) = ExtendedAddress::decode(&buf[l..])?;
                length += l;
                (Address::Extended(i, a), length)
            }
        };
        Ok((address, len))
    }

    /// Decodes an address from a byte buffer
    pub fn decode_compress(
        buf: &[u8],
        mode: &AddressMode,
        pan_id: PanId,
    ) -> Result<(Self, usize), DecodeError> {
        let (address, len) = match mode {
            AddressMode::None => (Address::None, 0),
            AddressMode::Short => {
                let (a, l) = ShortAddress::decode(buf)?;
                (Address::Short(pan_id, a), l)
            }
            AddressMode::Extended => {
                let (a, l) = ExtendedAddress::decode(buf)?;
                (Address::Extended(pan_id, a), l)
            }
        };
        Ok((address, len))
    }

    /// Encodes the address into a buffer
    pub fn encode(&self, buf: &mut [u8]) -> usize {
        match *self {
            Address::None => 0,
            Address::Short(i, a) => {
                let pan_id_size = i.encode(buf);
                let address_size = a.encode(&mut buf[pan_id_size..]);
                pan_id_size + address_size
            }
            Address::Extended(i, a) => {
                let pan_id_size = i.encode(buf);
                let address_size = a.encode(&mut buf[pan_id_size..]);
                pan_id_size + address_size
            }
        }
    }

    /// Encodes the address into a buffer
    pub fn encode_compress(&self, buf: &mut [u8]) -> usize {
        match *self {
            Address::None => 0,
            Address::Short(_, a) => a.encode(buf),
            Address::Extended(_, a) => a.encode(buf),
        }
    }

    /// Get the PAN ID for this address
    pub fn pan_id(&self) -> Option<PanId> {
        match *self {
            Address::None => None,
            Address::Short(pan_id, _) => Some(pan_id),
            Address::Extended(pan_id, _) => Some(pan_id),
        }
    }

    /// Get the address mode for this address
    pub fn address_mode(&self) -> AddressMode {
        match *self {
            Address::None => AddressMode::None,
            Address::Short(_, _) => AddressMode::Short,
            Address::Extended(_, _) => AddressMode::Extended,
        }
    }
}

/// Signals an error that occured while decoding bytes
#[derive(Debug, PartialEq)]
pub enum DecodeError {
    /// Buffer does not contain enough bytes
    NotEnoughBytes,

    /// The frame type is invalid
    InvalidFrameType(u8),

    /// The frame has the security bit set, which is not supported
    SecurityNotSupported,

    /// The frame's address mode is invalid
    InvalidAddressMode(u8),

    /// The frame's version is invalid or not supported
    InvalidFrameVersion(u8),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_ver0_pan_id_compression() {
        let data = [
            0x41, 0x88, 0x91, 0x8f, 0x20, 0xff, 0xff, 0x33, 0x44, 0x00, 0x00,
        ];
        let frame = Frame::decode(&data).unwrap();
        assert_eq!(frame.header.frame_type, FrameType::Data);
        assert_eq!(frame.header.security, Security::None);
        assert_eq!(frame.header.frame_pending, false);
        assert_eq!(frame.header.ack_request, false);
        assert_eq!(frame.header.pan_id_compress, true);
        assert_eq!(frame.header.version, FrameVersion::Ieee802154_2003);
        assert_eq!(
            frame.header.destination,
            Address::Short(PanId(0x208f), ShortAddress(0xffff))
        );
        assert_eq!(
            frame.header.source,
            Address::Short(PanId(0x208f), ShortAddress(0x4433))
        );
        assert_eq!(frame.header.seq, 145);
    }

    #[test]
    fn decode_ver0_pan_id_compression_bad() {
        let data = [
            0x41, 0x80, 0x91, 0x8f, 0x20, 0xff, 0xff, 0x33, 0x44, 0x00, 0x00,
        ];
        let frame = Frame::decode(&data);
        assert!(frame.is_err());
        if let Err(e) = frame {
            assert_eq!(e, DecodeError::InvalidAddressMode(0))
        }
    }

    #[test]
    fn decode_ver0_extended() {
        let data = [
            0x21, 0xc8, 0x8b, 0xff, 0xff, 0x02, 0x00, 0x23, 0x00, 0x60, 0xe2, 0x16, 0x21, 0x1c,
            0x4a, 0xc2, 0xae, 0xaa, 0xbb, 0xcc,
        ];
        let frame = Frame::decode(&data).unwrap();
        assert_eq!(frame.header.frame_type, FrameType::Data);
        assert_eq!(frame.header.security, Security::None);
        assert_eq!(frame.header.frame_pending, false);
        assert_eq!(frame.header.ack_request, true);
        assert_eq!(frame.header.pan_id_compress, false);
        assert_eq!(frame.header.version, FrameVersion::Ieee802154_2003);
        assert_eq!(
            frame.header.destination,
            Address::Short(PanId(0xffff), ShortAddress(0x0002))
        );
        assert_eq!(
            frame.header.source,
            Address::Extended(PanId(0x0023), ExtendedAddress(0xaec24a1c2116e260))
        );
        assert_eq!(frame.header.seq, 139);
    }

    #[test]
    fn encode_ver0_short() {
        let frame = Frame {
            header: Header {
                frame_type: FrameType::Data,
                security: Security::None,
                frame_pending: false,
                ack_request: false,
                pan_id_compress: false,
                version: FrameVersion::Ieee802154_2003,
                destination: Address::Short(PanId(0x1234), ShortAddress(0x5678)),
                source: Address::Short(PanId(0x4321), ShortAddress(0x9abc)),
                seq: 0x01,
            },
            payload: &[0xde, 0xf0],
            footer: [0x00, 0x00],
        };
        let mut buf = [0u8; 32];
        let size = frame.encode(&mut buf, WriteFooter::No);
        assert_eq!(size, 13);
        assert_eq!(
            buf[..size],
            [0x01, 0x88, 0x01, 0x34, 0x12, 0x78, 0x56, 0x21, 0x43, 0xbc, 0x9a, 0xde, 0xf0]
        );
    }

    #[test]
    fn encode_ver1_extended() {
        let frame = Frame {
            header: Header {
                frame_type: FrameType::Beacon,
                security: Security::None,
                frame_pending: true,
                ack_request: false,
                pan_id_compress: false,
                version: FrameVersion::Ieee802154_2006,
                destination: Address::Extended(PanId(0x1234), ExtendedAddress(0x1122334455667788)),
                source: Address::Short(PanId(0x4321), ShortAddress(0x9abc)),
                seq: 0xff,
            },
            payload: &[0xde, 0xf0],
            footer: [0x00, 0x00],
        };
        let mut buf = [0u8; 32];
        let size = frame.encode(&mut buf, WriteFooter::No);
        assert_eq!(size, 19);
        assert_eq!(
            buf[..size],
            [
                0x10, 0x9c, 0xff, 0x34, 0x12, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x21,
                0x43, 0xbc, 0x9a, 0xde, 0xf0
            ]
        );
    }

    #[test]
    fn encode_ver0_pan_compress() {
        let frame = Frame {
            header: Header {
                frame_type: FrameType::Acknowledgement,
                security: Security::None,
                frame_pending: false,
                ack_request: false,
                pan_id_compress: true,
                version: FrameVersion::Ieee802154_2003,
                destination: Address::Extended(PanId(0x1234), ExtendedAddress(0x1122334455667788)),
                source: Address::Short(PanId(0x1234), ShortAddress(0x9abc)),
                seq: 0xff,
            },
            payload: &[0xde, 0xf0],
            footer: [0x00, 0x00],
        };
        let mut buf = [0u8; 32];
        let size = frame.encode(&mut buf, WriteFooter::No);
        assert_eq!(size, 17);
        assert_eq!(
            buf[..size],
            [
                0x42, 0x8c, 0xff, 0x34, 0x12, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0xbc,
                0x9a, 0xde, 0xf0
            ]
        );
    }

    #[test]
    fn encode_ver2_none() {
        let frame = Frame {
            header: Header {
                frame_type: FrameType::MacCommand,
                security: Security::None,
                frame_pending: false,
                ack_request: true,
                pan_id_compress: false,
                version: FrameVersion::Ieee802154,
                destination: Address::None,
                source: Address::Short(PanId(0x1234), ShortAddress(0x9abc)),
                seq: 0xff,
            },
            payload: &[0xde, 0xf0],
            footer: [0x00, 0x00],
        };
        let mut buf = [0u8; 32];
        let size = frame.encode(&mut buf, WriteFooter::No);
        assert_eq!(size, 9);
        assert_eq!(
            buf[..size],
            [0x23, 0xa0, 0xff, 0x34, 0x12, 0xbc, 0x9a, 0xde, 0xf0]
        );
    }

}
