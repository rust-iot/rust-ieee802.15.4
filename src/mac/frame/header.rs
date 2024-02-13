//! Partial implementation of the IEEE 802.15.4 frame Header
//!
//! The main type in this module is [`Header`], the header of 802.15.4 MAC frame.
//!
//! [`Header`]: struct.Header.html

use byte::{check_len, BytesExt, TryRead, TryWrite, LE};
use cipher::{consts::U16, BlockCipher, NewBlockCipher};
use hash32_derive::Hash32;

pub use super::frame_control::{AddressMode, FrameType, FrameVersion};
use super::DecodeError;
use super::{
    frame_control::{mask, offset},
    security::{KeyDescriptorLookup, SecurityContext},
};
use super::{security::AuxiliarySecurityHeader, EncodeError};

/// MAC frame header
///
/// External documentation for [MAC frame format start at 5.2]
///
/// [MAC frame format start at 5.2]: http://ecee.colorado.edu/~liue/teaching/comm_standards/2015S_zigbee/802.15.4-2011.pdf
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Header {
    // * Frame Control Field * /
    /// Frame Type
    pub frame_type: FrameType,

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

    /// Suppress sequence number
    pub seq_no_suppress: bool,

    /// Information element present
    pub ie_present: bool,

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

    /// Auxiliary security header. If security is enabled in this header,
    /// this field will be Some, else it will be None
    pub auxiliary_security_header: Option<AuxiliarySecurityHeader>,
}

impl Header {
    /// Get the size of this header in octets
    pub fn get_octet_size(&self) -> usize {
        // Frame control + sequence number
        let mut len = 3;

        for addr in [self.destination, self.source].iter().flatten() {
            // pan ID
            len += 2;
            // Address length
            match addr {
                Address::Short(..) => len += 2,
                Address::Extended(..) => len += 8,
            }
        }
        len
    }

    /// Whether this header has security enabled
    pub fn has_security(&self) -> bool {
        self.auxiliary_security_header.is_some()
    }
}

impl TryRead<'_> for Header {
    fn try_read(bytes: &[u8], _ctx: ()) -> byte::Result<(Self, usize)> {
        let offset = &mut 0;
        // Make sure we have enough buffer for the Frame Control field
        check_len(bytes, 3)?;

        /* Decode Frame Control Field */
        let bits: u16 = bytes.read_with(offset, LE)?;

        let frame_type =
            ((bits & mask::FRAME_TYPE) >> offset::FRAME_TYPE) as u8;
        let security = ((bits & mask::SECURITY) >> offset::SECURITY) as u8;

        let frame_pending = ((bits & mask::PENDING) >> offset::PENDING) as u8;
        let ack_request = ((bits & mask::ACK) >> offset::ACK) as u8;
        let pan_id_compress =
            ((bits & mask::PAN_ID_COMPRESS) >> offset::PAN_ID_COMPRESS) as u8;

        let seq_no_suppress =
            ((bits & mask::SEQ_NO_SUPPRESS) >> offset::SEQ_NO_SUPPRESS) as u8;
        let ie_present =
            ((bits & mask::IE_PRESENT) >> offset::IE_PRESENT) as u8;

        let dest_addr_mode =
            ((bits & mask::DEST_ADDR_MODE) >> offset::DEST_ADDR_MODE) as u8;

        let version = ((bits & mask::VERSION) >> offset::VERSION) as u8;
        let src_addr_mode =
            ((bits & mask::SRC_ADDR_MODE) >> offset::SRC_ADDR_MODE) as u8;

        let version = FrameVersion::from_bits(version)
            .ok_or(DecodeError::InvalidFrameVersion(version))?;
        let frame_type = FrameType::from_bits(frame_type)
            .ok_or(DecodeError::InvalidFrameType(frame_type))?;
        let dest_addr_mode = AddressMode::from_bits(dest_addr_mode)?;
        let src_addr_mode = AddressMode::from_bits(src_addr_mode)?;

        // make bool values
        let security = security > 0;
        let frame_pending = frame_pending > 0;
        let ack_request = ack_request > 0;
        let pan_id_compress = pan_id_compress > 0;
        let seq_no_suppress = seq_no_suppress > 0;
        let ie_present = ie_present > 0;

        /* Decode header depending on Frame Control Fields */

        let seq = bytes.read(offset)?;

        let destination = match dest_addr_mode {
            AddressMode::None => None,
            AddressMode::Short => {
                Some(Address::Short(bytes.read(offset)?, bytes.read(offset)?))
            }
            AddressMode::Extended => Some(Address::Extended(
                bytes.read(offset)?,
                bytes.read(offset)?,
            )),
        };

        if pan_id_compress {
            destination.ok_or(byte::Error::BadInput {
                err: "InvalidAddressMode",
            })?;
        }

        let source = match src_addr_mode {
            AddressMode::None => None,
            AddressMode::Short => {
                if pan_id_compress {
                    Some(Address::Short(
                        destination.unwrap().pan_id(),
                        bytes.read(offset)?,
                    ))
                } else {
                    Some(Address::Short(
                        bytes.read(offset)?,
                        bytes.read(offset)?,
                    ))
                }
            }
            AddressMode::Extended => {
                if pan_id_compress {
                    Some(Address::Extended(
                        destination.unwrap().pan_id(),
                        bytes.read(offset)?,
                    ))
                } else {
                    Some(Address::Extended(
                        bytes.read(offset)?,
                        bytes.read(offset)?,
                    ))
                }
            }
        };

        let auxiliary_security_header = match security {
            true => Some(bytes.read(offset)?),
            false => None,
        };

        let header = Header {
            frame_type,
            frame_pending,
            ack_request,
            pan_id_compress,
            seq_no_suppress,
            ie_present,
            version,
            seq,
            destination,
            source,
            auxiliary_security_header,
        };

        Ok((header, *offset))
    }
}

impl<AEADBLKCIPH, KEYDESCLO>
    TryWrite<&Option<&mut SecurityContext<AEADBLKCIPH, KEYDESCLO>>> for Header
where
    AEADBLKCIPH: NewBlockCipher + BlockCipher<BlockSize = U16>,
    KEYDESCLO: KeyDescriptorLookup<AEADBLKCIPH::KeySize>,
{
    fn try_write(
        self,
        bytes: &mut [u8],
        sec_ctx: &Option<&mut SecurityContext<AEADBLKCIPH, KEYDESCLO>>,
    ) -> byte::Result<usize> {
        let offset = &mut 0;
        let dest_addr_mode = AddressMode::from(self.destination);
        let src_addr_mode = AddressMode::from(self.source);

        let security = self.auxiliary_security_header.is_some();

        let frame_control_raw = (self.frame_type as u16) << offset::FRAME_TYPE
            | (security as u16) << offset::SECURITY
            | (self.frame_pending as u16) << offset::PENDING
            | (self.ack_request as u16) << offset::ACK
            | (self.pan_id_compress as u16) << offset::PAN_ID_COMPRESS
            | (dest_addr_mode as u16) << offset::DEST_ADDR_MODE
            | (self.version as u16) << offset::VERSION
            | (src_addr_mode as u16) << offset::SRC_ADDR_MODE;

        bytes.write_with(offset, frame_control_raw, LE)?;

        // Write Sequence Number
        bytes.write(offset, self.seq)?;

        if (self.destination.is_none() || self.source.is_none())
            && self.pan_id_compress
        {
            return Err(EncodeError::DisallowedPanIdCompress)?;
        }

        // Write addresses
        if let Some(destination) = self.destination {
            bytes.write_with(offset, destination, AddressEncoding::Normal)?;
        }

        match (self.source, self.pan_id_compress) {
            (Some(source), true) => {
                bytes.write_with(
                    offset,
                    source,
                    AddressEncoding::Compressed,
                )?;
            }
            (Some(source), false) => {
                bytes.write_with(offset, source, AddressEncoding::Normal)?;
            }
            (None, true) => {
                panic!("frame control request compress source address without contain this address")
            }
            (None, false) => (),
        }

        if security && sec_ctx.is_none() {
            return Err(EncodeError::MissingSecurityCtx)?;
        } else if security {
            match self.auxiliary_security_header {
                Some(aux_sec_head) => match sec_ctx {
                    Some(sec_ctx) => {
                        bytes.write_with(offset, aux_sec_head, sec_ctx)?;
                    }
                    None => return Err(EncodeError::UnknownError)?,
                },
                None => return Err(EncodeError::UnknownError)?,
            }
        }
        Ok(*offset)
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
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct PanId(pub u16);

impl PanId {
    /// Get the broadcast PAN identifier
    pub fn broadcast() -> Self {
        Self(0xffff)
    }
}

impl TryWrite for PanId {
    fn try_write(self, bytes: &mut [u8], _ctx: ()) -> byte::Result<usize> {
        let offset = &mut 0;
        bytes.write_with(offset, self.0, LE)?;
        Ok(*offset)
    }
}

impl TryRead<'_> for PanId {
    fn try_read(bytes: &[u8], _ctx: ()) -> byte::Result<(Self, usize)> {
        let offset = &mut 0;
        Ok((Self(bytes.read_with(offset, LE)?), *offset))
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
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]

pub struct ShortAddress(pub u16);

impl ShortAddress {
    /// An instance of `ShortAddress` that represents the broadcast address.
    pub const BROADCAST: Self = ShortAddress(0xffff);

    /// Creates an instance of `ShortAddress` that represents the broadcast address
    pub fn broadcast() -> Self {
        ShortAddress(0xffff)
    }
}

impl TryWrite for ShortAddress {
    fn try_write(self, bytes: &mut [u8], _ctx: ()) -> byte::Result<usize> {
        let offset = &mut 0;
        bytes.write_with(offset, self.0, LE)?;
        Ok(*offset)
    }
}

impl TryRead<'_> for ShortAddress {
    fn try_read(bytes: &[u8], _ctx: ()) -> byte::Result<(Self, usize)> {
        let offset = &mut 0;
        Ok((Self(bytes.read_with(offset, LE)?), *offset))
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
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]

pub struct ExtendedAddress(pub u64);

impl ExtendedAddress {
    /// An instance of `ExtendedAddress` that represents the broadcast address.
    pub const BROADCAST: Self = ExtendedAddress(0xffffffffffffffffu64);

    /// Creates an instance of `ExtendedAddress` that represents the broadcast address
    pub fn broadcast() -> Self {
        ExtendedAddress(0xffffffffffffffffu64)
    }
}

impl TryWrite for ExtendedAddress {
    fn try_write(self, bytes: &mut [u8], _ctx: ()) -> byte::Result<usize> {
        let offset = &mut 0;
        bytes.write_with(offset, self.0, LE)?;
        Ok(*offset)
    }
}

impl TryRead<'_> for ExtendedAddress {
    fn try_read(bytes: &[u8], _ctx: ()) -> byte::Result<(Self, usize)> {
        let offset = &mut 0;
        Ok((Self(bytes.read_with(offset, LE)?), *offset))
    }
}

/// An address that might contain an PAN ID and address
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum Address {
    /// Short (16-bit) address and PAN ID (16-bit)
    Short(PanId, ShortAddress),
    /// Extended (64-bit) address and PAN ID (16-bit)
    Extended(PanId, ExtendedAddress),
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
enum AddressEncoding {
    Normal,
    Compressed,
}

impl TryWrite<AddressEncoding> for Address {
    fn try_write(
        self,
        bytes: &mut [u8],
        enc: AddressEncoding,
    ) -> byte::Result<usize> {
        let offset = &mut 0;
        match (self, enc) {
            (Address::Short(pan_id, addr), AddressEncoding::Normal) => {
                bytes.write(offset, pan_id)?;
                bytes.write(offset, addr)?;
            }
            (Address::Short(_pan_id, addr), AddressEncoding::Compressed) => {
                bytes.write(offset, addr)?;
            }
            (Address::Extended(pan_id, addr), AddressEncoding::Normal) => {
                bytes.write(offset, pan_id)?;
                bytes.write(offset, addr)?;
            }
            (Address::Extended(_pan_id, addr), AddressEncoding::Compressed) => {
                bytes.write(offset, addr)?;
            }
        }
        Ok(*offset)
    }
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

    /// Get the PAN ID for this address
    pub fn pan_id(&self) -> PanId {
        match *self {
            Address::Short(pan_id, _) => pan_id,
            Address::Extended(pan_id, _) => pan_id,
        }
    }
}
