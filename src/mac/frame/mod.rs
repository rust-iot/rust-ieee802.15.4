//! Partial implementation of the IEEE 802.15.4 Frame
//!
//! The main type in this module is [Frame], a type that represents an IEEE
//! 802.15.4 MAC frame. The other types in this module are supporting types
//! that are either part of [Frame] or are required to support its API.
//!
//! [Frame]: struct.Frame.html

// TODO:
// - change &mut [u8] -> bytes::BufMut
// - change &[u8] => bytes::Buf
// - remove one variant enums

use bytes::{Buf, BufMut};
use hash32_derive::Hash32;

use crate::mac::beacon::Beacon;
use crate::mac::command::Command;

pub mod frame_control;
pub use frame_control::{AddressMode, FrameControl, FrameType};

/// An IEEE 802.15.4 MAC frame
///
/// Represents a MAC frame. Can be used to [decode] a frame from bytes, or
/// [encode] a frame to bytes.
///
/// [decode]: #method.decode
/// [encode]: #method.encode
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Frame<'p> {
    /// Header
    pub header: Header,

    /// Content
    pub content: FrameContent,

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
    /// let frame = Frame::decode(&bytes, true)?;
    /// let fcnt = frame.header.frame_control;
    ///
    /// assert_eq!(frame.header.seq,             0x00);
    /// assert_eq!(fcnt.frame_type,      FrameType::Data);
    /// assert_eq!(fcnt.security,        false);
    /// assert_eq!(fcnt.frame_pending,   false);
    /// assert_eq!(fcnt.ack_request,     false);
    /// assert_eq!(fcnt.pan_id_compress, false);
    ///
    /// assert_eq!(
    ///     frame.header.destination,
    ///     Some(Address::Short(PanId(0x3412), ShortAddress(0x7856)))
    /// );
    /// assert_eq!(
    ///     frame.header.source,
    ///     Some(Address::Short(PanId(0x3412), ShortAddress(0xbc9a)))
    /// );
    ///
    /// assert_eq!(frame.payload, &[0xde, 0xf0]);
    /// assert_eq!(frame.footer,  [0x12, 0x34]);
    /// #
    /// # Ok(())
    /// # }
    /// ```
    pub fn decode(mut buf: &'p [u8], contains_footer: bool) -> Result<Self, DecodeError> {
        let orginal_buf = buf;

        let header = Header::decode(&mut buf)?;

        let content = FrameContent::decode(&mut buf, &header)?;

        let taken_bytes = orginal_buf.len() - buf.remaining();
        let payload_with_footer = &orginal_buf[taken_bytes..];

        if payload_with_footer.len() != buf.remaining() {
            panic!(
                "Noncontinuous Buf implementation aren't supported. Consider use `bytes::Bytes`"
            );
        }
        buf.advance(buf.remaining());

        let mut footer = [0; 2];
        let payload = if contains_footer {
            if payload_with_footer.len() < 2 {
                return Err(DecodeError::NotEnoughBytes);
            }
            let footer_pos = payload_with_footer.len() - 2;
            footer.copy_from_slice(&payload_with_footer[footer_pos..]);
            &payload_with_footer[..footer_pos]
        } else {
            payload_with_footer
        };

        Ok(Frame {
            header,
            content,
            payload,
            footer,
        })
    }

    /// Encodes the frame into a buffer
    ///
    /// # Example
    ///
    /// ``` rust
    /// use ieee802154::mac::{
    ///     Address,
    ///     ShortAddress,
    ///     Frame,
    ///     FrameContent,
    ///     FrameType,
    ///     FrameVersion,
    ///     Header,
    ///     PanId,
    ///     WriteFooter,
    ///     FrameControl,
    ///     AddressMode,
    /// };
    ///
    /// let frame = Frame {
    ///     header: Header {
    ///         frame_control: FrameControl {
    ///         frame_type:      FrameType::Data,
    ///         security:        false,
    ///         frame_pending:   false,
    ///         ack_request:     false,
    ///         pan_id_compress: false,
    ///         version:         FrameVersion::Ieee802154_2006,
    ///         dest_addr_mode: AddressMode::Short,
    ///         src_addr_mode: AddressMode::Short,
    ///         },
    ///         seq:             0x00,
    ///
    ///         destination: Some(Address::Short(PanId(0x1234), ShortAddress(0x5678))),
    ///         source:      Some(Address::Short(PanId(0x1234), ShortAddress(0x9abc))),
    ///     },
    ///     content: FrameContent::Data,
    ///     payload: &[0xde, 0xf0],
    ///     footer:  [0x12, 0x34]
    /// };
    ///
    /// let mut bytes = bytes::BytesMut::with_capacity(32);
    ///
    /// frame.encode(&mut bytes, WriteFooter::No);
    /// let encoded_bytes = bytes.split().freeze();
    ///
    /// let expected_bytes = [
    ///     0x01, 0x98,             // frame control
    ///     0x00,                   // sequence number
    ///     0x34, 0x12, 0x78, 0x56, // PAN identifier and address of destination
    ///     0x34, 0x12, 0xbc, 0x9a, // PAN identifier and address of source
    ///     0xde, 0xf0,             // payload
    ///    // footer, not written
    /// ];
    /// assert_eq!(encoded_bytes[..], expected_bytes[..]);
    /// ```
    pub fn encode(&self, buf: &mut dyn BufMut, write_footer: WriteFooter) {
        // Write header
        self.header.encode(buf);

        // Write content
        self.content.encode(buf);

        // Write payload
        buf.put_slice(self.payload);

        // Write footer
        match write_footer {
            WriteFooter::No => (),
        }
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
///
/// External documentation for [MAC frame format start at 5.2]
///
/// [MAC frame format start at 5.2]: http://ecee.colorado.edu/~liue/teaching/comm_standards/2015S_zigbee/802.15.4-2011.pdf
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Header {
    /// Frame Control Field
    pub frame_control: FrameControl,

    /// Sequence Number
    pub seq: u8,

    /// Destination Address
    pub destination: Option<Address>,

    /// Source Address
    pub source: Option<Address>,
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
    /// };
    ///
    /// # fn main() -> Result<(), ::ieee802154::mac::DecodeError> {
    /// // Construct a simple header.
    /// let mut bytes = &[
    ///     0x01, 0x98,             // frame control
    ///     0x00,                   // sequence number
    ///     0x12, 0x34, 0x56, 0x78, // PAN identifier and address of destination
    ///     0x12, 0x34, 0x9a, 0xbc, // PAN identifier and address of source
    /// ][..];
    ///
    /// let header = Header::decode(&mut bytes)?;
    /// let fctl = header.frame_control;
    ///
    /// assert_eq!(fctl.frame_type,      FrameType::Data);
    /// assert_eq!(fctl.security,        false);
    /// assert_eq!(fctl.frame_pending,   false);
    /// assert_eq!(fctl.ack_request,     false);
    /// assert_eq!(fctl.pan_id_compress, false);
    /// assert_eq!(header.seq,             0x00);
    ///
    /// assert_eq!(
    ///     header.destination,
    ///     Some(Address::Short(PanId(0x3412), ShortAddress(0x7856)))
    /// );
    /// assert_eq!(
    ///     header.source,
    ///     Some(Address::Short(PanId(0x3412), ShortAddress(0xbc9a)))
    /// );
    /// #
    /// # Ok(())
    /// # }
    /// ```
    pub fn decode(buf: &mut dyn Buf) -> Result<Self, DecodeError> {
        // First, make sure we have enough buffer for the Frame Control field
        if buf.remaining() < 3 {
            return Err(DecodeError::NotEnoughBytes);
        }

        let fctl = FrameControl::try_from_bits(buf.get_u16_le())?;

        let seq = buf.get_u8();

        let destination = Address::decode(buf, &fctl.dest_addr_mode)?;

        let source = if !fctl.pan_id_compress {
            Address::decode(buf, &fctl.src_addr_mode)?
        } else {
            let pan_id = destination
                .ok_or(DecodeError::InvalidAddressMode(fctl.dest_addr_mode.as_u8()))?
                .pan_id();
            Address::decode_compress(buf, &fctl.src_addr_mode, pan_id)?
        };

        let header = Header {
            frame_control: fctl,
            seq,
            destination,
            source,
        };

        Ok(header)
    }

    /// Encodes the header into a buffer
    ///
    /// The header length depends on the options chosen and varies between 3 and
    /// 30 octets.
    ///
    /// # Example
    ///
    /// ``` rust
    /// use bytes::BytesMut;
    /// use ieee802154::mac::{
    ///     Address,
    ///     AddressMode,
    ///     ShortAddress,
    ///     FrameType,
    ///     FrameVersion,
    ///     Header,
    ///     PanId,
    ///     FrameControl,
    /// };
    ///
    /// let header = Header {
    ///     frame_control: FrameControl {
    ///     frame_type:      FrameType::Data,
    ///     security:        false,
    ///     frame_pending:   false,
    ///     ack_request:     false,
    ///     pan_id_compress: false,
    ///     version:         FrameVersion::Ieee802154_2006,
    ///         dest_addr_mode: AddressMode::Short,
    ///         src_addr_mode: AddressMode::Short,
    ///     },
    ///     seq:             0x00,
    ///
    ///     destination: Some(Address::Short(PanId(0x1234), ShortAddress(0x5678))),
    ///     source:      Some(Address::Short(PanId(0x1234), ShortAddress(0x9abc))),
    /// };
    ///
    /// let mut bytes = BytesMut::with_capacity(11);
    ///
    /// header.encode(&mut bytes);
    /// let encoded_bytes = bytes.split().freeze();
    ///
    /// let expected_bytes = [
    ///     0x01, 0x98,             // frame control
    ///     0x00,                   // sequence number
    ///     0x34, 0x12, 0x78, 0x56, // PAN identifier and address of destination
    ///     0x34, 0x12, 0xbc, 0x9a, // PAN identifier and address of source
    /// ];
    /// assert_eq!(encoded_bytes, expected_bytes[..]);
    /// ```
    pub fn encode(&self, buf: &mut dyn BufMut) {
        let frame_control_raw = self.frame_control.to_bits();

        buf.put_u16_le(frame_control_raw);

        // Write Sequence Number
        buf.put_u8(self.seq);

        // Write addresses
        if let Some(destination) = self.destination {
            assert!(self.frame_control.dest_addr_mode != AddressMode::None);
            destination.encode(buf);
        }

        match (self.source, self.frame_control.pan_id_compress) {
            (Some(source), true) => {
                assert!(self.frame_control.src_addr_mode != AddressMode::None);
                source.encode_compress(buf);
            }
            (Some(source), false) => {
                assert!(self.frame_control.src_addr_mode != AddressMode::None);
                source.encode(buf);
            }
            (None, true) => panic!("Frame cnt request commpress address without address"),
            (None, false) => (),
        }
    }
}

/// Personal Area Network Identifier
///
/// A 16-bit value that identifies a PAN
///
/// # Example
///
/// ``` rust
/// use ieee802154::mac::frame::PanId;
///
/// let pan_id = PanId(0x0123);
/// ```
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
    /// let mut bytes = &[0x56, 0x78][..];
    /// let address = PanId::decode(&mut bytes)?;
    ///
    /// assert_eq!(address.0, 0x7856);
    /// #
    /// # Ok(())
    /// # }
    /// ```
    pub fn decode(buf: &mut dyn Buf) -> Result<Self, DecodeError> {
        if buf.remaining() < 2 {
            return Err(DecodeError::NotEnoughBytes);
        }

        Ok(PanId(buf.get_u16_le()))
    }

    /// Encodes the PAN identifier into a buffer
    ///
    /// # Example
    ///
    /// ``` rust
    /// use ieee802154::mac::PanId;
    /// use bytes::BytesMut;
    ///
    /// let address = PanId(0x1234);
    ///
    /// let mut bytes = BytesMut::with_capacity(2);
    /// address.encode(&mut bytes);
    ///
    /// let expected_bytes = [0x34, 0x12];
    /// assert_eq!(bytes[..], expected_bytes[..]);
    /// ```
    pub fn encode(&self, buf: &mut dyn BufMut) {
        buf.put_u16_le(self.0)
    }
}

/// A 16-bit short address
///
/// Short address assigned to a device during association, used to identify the
/// device in the PAN.
///
/// # Example
///
/// ``` rust
/// use ieee802154::mac::frame::ShortAddress;
///
/// let short_address = ShortAddress(0x0123);
/// ```
#[derive(Clone, Copy, Debug, Eq, Hash, Hash32, PartialEq)]
pub struct ShortAddress(pub u16);

impl ShortAddress {
    /// An instance of `ShortAddress` that represents the broadcast address.
    pub const BROADCAST: Self = ShortAddress(0xffff);

    /// Creates an instance of `ShortAddress` that represents the broadcast address
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
    /// let mut bytes = &[0x56, 0x78][..];
    /// let address = ShortAddress::decode(&mut bytes)?;
    ///
    /// assert_eq!(address, ShortAddress(0x7856));
    /// #
    /// # Ok(())
    /// # }
    /// ```
    pub fn decode(buf: &mut dyn Buf) -> Result<Self, DecodeError> {
        if buf.remaining() < 2 {
            return Err(DecodeError::NotEnoughBytes);
        }

        Ok(ShortAddress(buf.get_u16_le()))
    }

    /// Encodes the address into a buffer
    ///
    /// # Example
    ///
    /// ``` rust
    /// use ieee802154::mac::ShortAddress;
    ///
    /// let address = ShortAddress(0x5678);
    ///
    /// let mut bytes = bytes::BytesMut::with_capacity(2);
    /// address.encode(&mut bytes);
    ///
    /// let expected_bytes = [0x78, 0x56];
    /// assert_eq!(bytes[..], expected_bytes[..]);
    /// ```
    pub fn encode(&self, buf: &mut dyn BufMut) {
        buf.put_u16_le(self.0)
    }
}

/// A 64-bit extended address
///
/// A unique address that is used to identify an device in the PAN.
///
/// # Example
///
/// ``` rust
/// use ieee802154::mac::frame::ExtendedAddress;
///
/// let ext_address = ExtendedAddress(0x0123456789abcdef);
/// ```
#[derive(Clone, Copy, Debug, Eq, Hash, Hash32, PartialEq)]
pub struct ExtendedAddress(pub u64);

impl ExtendedAddress {
    /// An instance of `ExtendedAddress` that represents the broadcast address.
    pub const BROADCAST: Self = ExtendedAddress(0xffffffffffffffffu64);

    /// Creates an instance of `ExtendedAddress` that represents the broadcast address
    pub fn broadcast() -> Self {
        ExtendedAddress(0xffffffffffffffffu64)
    }

    /// Decodes an address from a byte buffer
    pub fn decode(buf: &mut dyn Buf) -> Result<Self, DecodeError> {
        if buf.remaining() < 8 {
            return Err(DecodeError::NotEnoughBytes);
        }
        Ok(ExtendedAddress(buf.get_u64_le()))
    }

    /// Encodes the address into a buffer
    pub fn encode(&self, buf: &mut dyn BufMut) {
        buf.put_u64_le(self.0)
    }
}

/// An address that might contain an PAN ID and address
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Address {
    /// Short (16-bit) address and PAN ID (16-bit)
    Short(PanId, ShortAddress),
    /// Extended (64-bit) address and PAN ID (16-bit)
    Extended(PanId, ExtendedAddress),
}

impl Address {
    /// Creates an instance of `Address` that represents the broadcast address
    pub fn broadcast(mode: &AddressMode) -> Option<Self> {
        match mode {
            AddressMode::None => None,
            AddressMode::Short => Some(Address::Short(
                PanId::broadcast(),
                ShortAddress::broadcast(),
            )),
            AddressMode::Extended => Some(Address::Extended(
                PanId::broadcast(),
                ExtendedAddress::broadcast(),
            )),
        }
    }

    /// Decodes an address from a byte buffer
    pub fn decode(buf: &mut dyn Buf, mode: &AddressMode) -> Result<Option<Self>, DecodeError> {
        let opt_address = match mode {
            AddressMode::None => None,
            AddressMode::Short => {
                let pan_id = PanId::decode(buf)?;
                let short = ShortAddress::decode(buf)?;
                Some(Address::Short(pan_id, short))
            }
            AddressMode::Extended => {
                let pan_id = PanId::decode(buf)?;
                let extended = ExtendedAddress::decode(buf)?;
                Some(Address::Extended(pan_id, extended))
            }
        };
        Ok(opt_address)
    }

    /// Decodes an address from a byte buffer
    pub fn decode_compress(
        buf: &mut dyn Buf,
        mode: &AddressMode,
        pan_id: PanId,
    ) -> Result<Option<Self>, DecodeError> {
        let opt_address = match mode {
            AddressMode::None => None,
            AddressMode::Short => {
                let short = ShortAddress::decode(buf)?;
                Some(Address::Short(pan_id, short))
            }
            AddressMode::Extended => {
                let extended = ExtendedAddress::decode(buf)?;
                Some(Address::Extended(pan_id, extended))
            }
        };
        Ok(opt_address)
    }

    /// Encodes the address into a buffer
    pub fn encode(&self, buf: &mut dyn BufMut) {
        match *self {
            Address::Short(pan_id, short) => {
                pan_id.encode(buf);
                short.encode(buf);
            }
            Address::Extended(pan_id, extended) => {
                pan_id.encode(buf);
                extended.encode(buf);
            }
        }
    }

    /// Encodes the address into a buffer
    pub fn encode_compress(&self, buf: &mut dyn BufMut) {
        match *self {
            Address::Short(_, a) => a.encode(buf),
            Address::Extended(_, a) => a.encode(buf),
        }
    }

    /// Get the PAN ID for this address
    pub fn pan_id(&self) -> PanId {
        match *self {
            Address::Short(pan_id, _) => pan_id,
            Address::Extended(pan_id, _) => pan_id,
        }
    }

    /// Get the address mode for this address
    pub fn address_mode(&self) -> AddressMode {
        match *self {
            Address::Short(_, _) => AddressMode::Short,
            Address::Extended(_, _) => AddressMode::Extended,
        }
    }
}

/// Content of a frame
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum FrameContent {
    /// Beacon frame content
    Beacon(Beacon),
    /// Data frame
    Data,
    /// Acknowledgement frame
    Acknowledgement,
    /// MAC command frame
    Command(Command),
}

impl FrameContent {
    /// Decode frame content from byte buffer
    pub fn decode(buf: &mut dyn Buf, header: &Header) -> Result<Self, DecodeError> {
        match header.frame_control.frame_type {
            FrameType::Beacon => {
                let beacon = Beacon::decode(buf)?;
                Ok(FrameContent::Beacon(beacon))
            }
            FrameType::Data => Ok(FrameContent::Data),
            FrameType::Acknowledgement => Ok(FrameContent::Acknowledgement),
            FrameType::MacCommand => {
                let command = Command::decode(buf)?;
                Ok(FrameContent::Command(command))
            }
        }
    }
    /// Encode frame content into byte buffer
    pub fn encode(&self, buf: &mut dyn BufMut) {
        match self {
            FrameContent::Beacon(beacon) => beacon.encode(buf),
            FrameContent::Data | FrameContent::Acknowledgement => (),
            FrameContent::Command(command) => command.encode(buf),
        }
    }
}

/// Signals an error that occured while decoding bytes
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
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

    /// The data stream contains an invalid value
    InvalidValue,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mac::beacon;
    use crate::mac::command;
    use crate::mac::FrameVersion;
    use bytes::BytesMut;

    #[test]
    fn decode_ver0_pan_id_compression() {
        let data = [
            0x41, 0x88, 0x91, 0x8f, 0x20, 0xff, 0xff, 0x33, 0x44, 0x00, 0x00,
        ];
        let mut sliced_data = &data[..];
        let frame = Frame::decode(&mut sliced_data, true).unwrap();
        let fctl = frame.header.frame_control;
        assert_eq!(fctl.frame_type, FrameType::Data);
        assert_eq!(fctl.security, false);
        assert_eq!(fctl.frame_pending, false);
        assert_eq!(fctl.ack_request, false);
        assert_eq!(fctl.pan_id_compress, true);
        assert_eq!(fctl.version, FrameVersion::Ieee802154_2003);
        assert_eq!(
            frame.header.destination,
            Some(Address::Short(PanId(0x208f), ShortAddress(0xffff)))
        );
        assert_eq!(
            frame.header.source,
            Some(Address::Short(PanId(0x208f), ShortAddress(0x4433)))
        );
        assert_eq!(frame.header.seq, 145);
    }

    #[test]
    fn decode_ver0_pan_id_compression_bad() {
        let data = [
            0x41, 0x80, 0x91, 0x8f, 0x20, 0xff, 0xff, 0x33, 0x44, 0x00, 0x00,
        ];
        let mut sliced_data = &data[..];
        let frame = Frame::decode(&mut sliced_data, true);
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
        let frame = Frame::decode(&data[..], true).unwrap();
        let fctl = frame.header.frame_control;
        assert_eq!(fctl.frame_type, FrameType::Data);
        assert_eq!(fctl.security, false);
        assert_eq!(fctl.frame_pending, false);
        assert_eq!(fctl.ack_request, true);
        assert_eq!(fctl.pan_id_compress, false);
        assert_eq!(fctl.version, FrameVersion::Ieee802154_2003);
        assert_eq!(
            frame.header.destination,
            Some(Address::Short(PanId(0xffff), ShortAddress(0x0002)))
        );
        assert_eq!(
            frame.header.source,
            Some(Address::Extended(
                PanId(0x0023),
                ExtendedAddress(0xaec24a1c2116e260)
            ))
        );
        assert_eq!(frame.header.seq, 139);
    }

    #[test]
    fn encode_ver0_short() {
        let frame = Frame {
            header: Header {
                frame_control: FrameControl {
                    frame_type: FrameType::Data,
                    security: false,
                    frame_pending: false,
                    ack_request: false,
                    pan_id_compress: false,
                    version: FrameVersion::Ieee802154_2003,
                    dest_addr_mode: AddressMode::Short,
                    src_addr_mode: AddressMode::Short,
                },
                destination: Some(Address::Short(PanId(0x1234), ShortAddress(0x5678))),
                source: Some(Address::Short(PanId(0x4321), ShortAddress(0x9abc))),
                seq: 0x01,
            },
            content: FrameContent::Data,
            payload: &[0xde, 0xf0],
            footer: [0x00, 0x00],
        };
        let mut buf = [0u8; 32];
        let buf_len = buf.len();
        let mut sliced_buf = &mut buf[..];
        frame.encode(&mut sliced_buf, WriteFooter::No);
        let size = buf_len - sliced_buf.len();
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
                frame_control: FrameControl {
                    frame_type: FrameType::Beacon,
                    security: false,
                    frame_pending: true,
                    ack_request: false,
                    pan_id_compress: false,
                    dest_addr_mode: AddressMode::Extended,
                    version: FrameVersion::Ieee802154_2006,
                    src_addr_mode: AddressMode::Short,
                },
                destination: Some(Address::Extended(
                    PanId(0x1234),
                    ExtendedAddress(0x1122334455667788),
                )),
                source: Some(Address::Short(PanId(0x4321), ShortAddress(0x9abc))),
                seq: 0xff,
            },
            content: FrameContent::Beacon(beacon::Beacon {
                superframe_spec: beacon::SuperframeSpecification {
                    beacon_order: beacon::BeaconOrder::OnDemand,
                    superframe_order: beacon::SuperframeOrder::Inactive,
                    final_cap_slot: 15,
                    battery_life_extension: false,
                    pan_coordinator: false,
                    association_permit: false,
                },
                guaranteed_time_slot_info: beacon::GuaranteedTimeSlotInformation::new(),
                pending_address: beacon::PendingAddress::new(),
            }),
            payload: &[0xde, 0xf0],
            footer: [0x00, 0x00],
        };
        let mut buf = BytesMut::with_capacity(32);
        frame.encode(&mut buf, WriteFooter::No);
        let encoded_buf = buf.freeze();
        assert_eq!(encoded_buf.len(), 23);
        assert_eq!(
            &encoded_buf[..],
            [
                0x10, 0x9c, 0xff, 0x34, 0x12, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x21,
                0x43, 0xbc, 0x9a, 0xff, 0x0f, 0x00, 0x00, 0xde, 0xf0
            ]
        );
    }

    #[test]
    fn encode_ver0_pan_compress() {
        let frame = Frame {
            header: Header {
                frame_control: FrameControl {
                    frame_type: FrameType::Acknowledgement,
                    security: false,
                    frame_pending: false,
                    ack_request: false,
                    pan_id_compress: true,
                    dest_addr_mode: AddressMode::Extended,
                    version: FrameVersion::Ieee802154_2003,
                    src_addr_mode: AddressMode::Short,
                },
                destination: Some(Address::Extended(
                    PanId(0x1234),
                    ExtendedAddress(0x1122334455667788),
                )),
                source: Some(Address::Short(PanId(0x1234), ShortAddress(0x9abc))),
                seq: 0xff,
            },
            content: FrameContent::Acknowledgement,
            payload: &[],
            footer: [0x00, 0x00],
        };
        let mut buf = BytesMut::with_capacity(32);
        frame.encode(&mut buf, WriteFooter::No);
        let encoded_buf = buf.freeze();
        assert_eq!(encoded_buf.len(), 15);
        assert_eq!(
            &encoded_buf[..],
            [
                0x42, 0x8c, 0xff, 0x34, 0x12, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0xbc,
                0x9a
            ]
        );
    }

    #[test]
    fn encode_ver2_none() {
        let frame = Frame {
            header: Header {
                frame_control: FrameControl {
                    frame_type: FrameType::MacCommand,
                    security: false,
                    frame_pending: false,
                    ack_request: true,
                    pan_id_compress: false,
                    dest_addr_mode: AddressMode::None,
                    version: FrameVersion::Ieee802154,
                    src_addr_mode: AddressMode::Short,
                },
                destination: None,
                source: Some(Address::Short(PanId(0x1234), ShortAddress(0x9abc))),
                seq: 0xff,
            },
            content: FrameContent::Command(command::Command::DataRequest),
            payload: &[],
            footer: [0x00, 0x00],
        };
        const BUF_SIZE: usize = 32;
        let mut buf = [0u8; BUF_SIZE];
        let mut sliced_buf = &mut buf[..];
        frame.encode(&mut sliced_buf, WriteFooter::No);
        let size = BUF_SIZE - sliced_buf.remaining_mut();
        assert_eq!(size, 8);
        assert_eq!(
            buf[..size],
            [0x23, 0xa0, 0xff, 0x34, 0x12, 0xbc, 0x9a, 0x04]
        );
    }
}
