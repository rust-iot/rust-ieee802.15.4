//! Partial implementation of the IEEE 802.15.4 frame Header
//!
//! The main type in this module is [`Header`], the header of 802.15.4 MAC frame.
//!
//! [`Header`]: struct.Header.html
use bytes::{Buf, BufMut};
use hash32_derive::Hash32;

use super::frame_control::*;
pub use super::frame_control::{AddressMode, FrameType, FrameVersion, Security};
use super::DecodeError;

/// MAC frame header
///
/// External documentation for [MAC frame format start at 5.2]
///
/// [MAC frame format start at 5.2]: http://ecee.colorado.edu/~liue/teaching/comm_standards/2015S_zigbee/802.15.4-2011.pdf
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Header {
    // * Frame Control Field * /
    /// Frame Type
    pub frame_type: FrameType,

    /// Auxiliary Security header
    pub security: Security,

    /// Frame Pending
    ///
    /// The Frame Pending field shall be set to `true` if the device sending the frame has more data
    /// for the recipient,as described in 5.1.6.3. This field shall be set to `false` otherwise.
    pub frame_pending: bool,

    /// Acknowledgement Request
    ///
    /// The AR field specifies whether an acknowledgment is required from the recipient device on receipt of a data
    /// or MAC command frame. If this field is set to `true`, the recipient device shall send an acknowledgment frame
    /// only if, upon reception, the frame passes the filtering described in 5.1.6.2. If this field is set to `false`, the
    /// recipient device shall not send an acknowledgment frame.
    pub ack_request: bool,

    /// PAN ID Compress
    ///
    /// The PAN ID Compression field specifies whether the MAC frame is to be sent containing only one of the
    /// PAN identifier fields when both src and destination addresses are present. If this field is set to `true` and
    /// both  the  src  and  destination  addresses  are  present,  the  frame  shall  contain  only  the  Destination  PAN
    /// Identifier field, and the Source PAN Identifier field shall be assumed equal to that of the destination. If this
    /// field is set to `false`, then the PAN Identifier field shall be present if and only if the corresponding address is
    /// present.
    pub pan_id_compress: bool,

    /// Frame version
    pub version: FrameVersion,

    // Destination address mode
    // use `destination` to determinate AddressMode

    // Source address mode
    // use `source` to determinate AddressMode

    // * End of Frame Control Field */
    /// Sequence Number
    pub seq: u8,

    /// Destination Address
    pub destination: Option<Address>,

    /// Source Address
    pub source: Option<Address>,
}

impl Header {
    /// Decodes a mac header from a byte buffer.
    ///
    /// This method is used by [`Frame::decode`] to decode the mac header.
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
    /// # fn main() -> Result<(), ::ieee802154::mac::frame::DecodeError> {
    /// // Construct a simple header.
    /// let mut bytes = &[
    ///     0x01, 0x98,             // frame control
    ///     0x00,                   // sequence number
    ///     0x12, 0x34, 0x56, 0x78, // PAN identifier and address of destination
    ///     0x12, 0x34, 0x9a, 0xbc, // PAN identifier and address of source
    /// ][..];
    ///
    /// let header = Header::decode(&mut bytes)?;
    ///
    /// assert_eq!(header.frame_type,      FrameType::Data);
    /// assert_eq!(header.security,        Security::None);
    /// assert_eq!(header.frame_pending,   false);
    /// assert_eq!(header.ack_request,     false);
    /// assert_eq!(header.pan_id_compress, false);
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
    ///
    /// [`Frame::decode`]: super::Frame
    pub fn decode(buf: &mut dyn Buf) -> Result<Self, DecodeError> {
        // Make sure we have enough buffer for the Frame Control field
        if buf.remaining() < 3 {
            return Err(DecodeError::NotEnoughBytes);
        }

        /* Decode Frame Control Field */
        let bits = buf.get_u16_le();

        let frame_type = ((bits & mask::FRAME_TYPE) >> offset::FRAME_TYPE) as u8;
        let security = ((bits & mask::SECURITY) >> offset::SECURITY) as u8;

        let frame_pending = ((bits & mask::PENDING) >> offset::PENDING) as u8;
        let ack_request = ((bits & mask::ACK) >> offset::ACK) as u8;
        let pan_id_compress = ((bits & mask::PAN_ID_COMPRESS) >> offset::PAN_ID_COMPRESS) as u8;

        let dest_addr_mode = ((bits & mask::DEST_ADDR_MODE) >> offset::DEST_ADDR_MODE) as u8;
        let version = ((bits & mask::VERSION) >> offset::VERSION) as u8;
        let src_addr_mode = ((bits & mask::SRC_ADDR_MODE) >> offset::SRC_ADDR_MODE) as u8;

        let version =
            FrameVersion::from_bits(version).ok_or(DecodeError::InvalidFrameVersion(version))?;
        let frame_type =
            FrameType::from_bits(frame_type).ok_or(DecodeError::InvalidFrameType(frame_type))?;
        let dest_addr_mode = AddressMode::from_bits(dest_addr_mode)?;
        let src_addr_mode = AddressMode::from_bits(src_addr_mode)?;

        // make bool values
        let security = if security > 0 {
            return Err(DecodeError::SecurityNotSupported);
        } else {
            Security::None
        };
        let frame_pending = frame_pending > 0;
        let ack_request = ack_request > 0;
        let pan_id_compress = pan_id_compress > 0;

        /* Decode header depending on Frame Control Fields */

        let seq = buf.get_u8();

        let destination = Address::decode(buf, &dest_addr_mode)?;

        let source = if !pan_id_compress {
            Address::decode(buf, &src_addr_mode)?
        } else {
            let pan_id = destination
                .ok_or(DecodeError::InvalidAddressMode(dest_addr_mode.as_u8()))?
                .pan_id();
            Address::decode_compress(buf, &src_addr_mode, pan_id)?
        };

        let header = Header {
            frame_type,
            security,
            frame_pending,
            ack_request,
            pan_id_compress,
            version,

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
    ///     Security,
    /// };
    ///
    /// let header = Header {
    ///     frame_type:      FrameType::Data,
    ///     security:        Security::None,
    ///     frame_pending:   false,
    ///     ack_request:     false,
    ///     pan_id_compress: false,
    ///     version:         FrameVersion::Ieee802154_2006,
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
        /* Encode Frame Control fields */
        let dest_addr_mode = AddressMode::from(self.destination);
        let src_addr_mode = AddressMode::from(self.source);

        let frame_control_raw = (self.frame_type as u16) << offset::FRAME_TYPE
            | (self.security as u16) << offset::SECURITY
            | (self.frame_pending as u16) << offset::PENDING
            | (self.ack_request as u16) << offset::ACK
            | (self.pan_id_compress as u16) << offset::PAN_ID_COMPRESS
            | (dest_addr_mode as u16) << offset::DEST_ADDR_MODE
            | (self.version as u16) << offset::VERSION
            | (src_addr_mode as u16) << offset::SRC_ADDR_MODE;

        buf.put_u16_le(frame_control_raw);

        // Write Sequence Number
        buf.put_u8(self.seq);

        // Write addresses
        if let Some(destination) = self.destination {
            destination.encode(buf);
        }

        match (self.source, self.pan_id_compress) {
            (Some(source), true) => {
                source.encode_compress(buf);
            }
            (Some(source), false) => {
                source.encode(buf);
            }
            (None, true) => {
                panic!("frame control request compress source address without contain this address")
            }
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
/// use ieee802154::mac::PanId;
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
    /// # fn main() -> Result<(), ::ieee802154::mac::frame::DecodeError> {
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
/// use ieee802154::mac::ShortAddress;
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
    /// use ieee802154::mac::frame::{DecodeError, header::ShortAddress};
    ///
    /// # fn main() -> Result<(), DecodeError> {
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
/// use ieee802154::mac::ExtendedAddress;
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
}
