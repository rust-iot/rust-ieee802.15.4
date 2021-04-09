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

use crate::mac::beacon::Beacon;
use crate::mac::command::Command;

mod frame_control;
pub mod header;
pub mod security;
use byte::{ctx::Bytes, BytesExt, TryRead, TryWrite, LE};
use ccm::aead::generic_array::typenum::consts::U16;
use cipher::{BlockCipher, NewBlockCipher};
use header::FrameType;
pub use header::Header;
pub use security::AuxiliarySecurityHeader;

use self::security::{
    default::*, DeviceDescriptorLookup, KeyLookup, SecurityContext, SecurityError,
};

/// An IEEE 802.15.4 MAC frame
///
/// Represents a MAC frame. Can be used to [decode] a frame from bytes, or
/// [encode] a frame to bytes.
///
///
/// # Decode Errors
///
/// This function returns an error, if the bytes either don't encode a valid
/// IEEE 802.15.4 frame, or encode a frame that is not fully supported by
/// this implementation. Please refer to [`DecodeError`] for details.
///
/// # Example
///
/// ``` rust
/// use ieee802154::mac::{
///     Frame,
///     Address,
///     ShortAddress,
///     FrameType,
///     FooterMode,
///     PanId,
///     FrameSerDesContext,
/// };
/// use byte::BytesExt;
///
/// # fn main() -> Result<(), ::ieee802154::mac::frame::DecodeError> {
/// // Construct a simple MAC frame. The CRC checksum (the last 2 bytes) is
/// // invalid, for the sake of convenience.
/// let bytes = [
///     0x01u8, 0x98,             // frame control
///     0x00,                   // sequence number
///     0x12, 0x34, 0x56, 0x78, // PAN identifier and address of destination
///     0x12, 0x34, 0x9a, 0xbc, // PAN identifier and address of source
///     0xde, 0xf0,             // payload
///     0x12, 0x34,             // payload
/// ];
///
/// let frame: Frame = bytes.read_with(&mut 0, FooterMode::Explicit).unwrap();
/// let header = frame.header;
///
/// assert_eq!(frame.header.seq,       0x00);
/// assert_eq!(header.frame_type,      FrameType::Data);
/// assert_eq!(header.security,        false);
/// assert_eq!(header.frame_pending,   false);
/// assert_eq!(header.ack_request,     false);
/// assert_eq!(header.pan_id_compress, false);
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
///
/// assert_eq!(frame.footer, [0x12, 0x34]);
/// #
/// # Ok(())
/// # }
/// ```
/// Encodes the frame into a buffer
///
/// # Example
///
/// ## allocation allowed
/// ``` rust
/// use ieee802154::mac::{
///   Frame,
///   FrameContent,
///   FooterMode,
///   Address,
///   ShortAddress,
///   FrameType,
///   FrameVersion,
///   Header,
///   PanId,
///   FrameSerDesContext,
/// };
/// use byte::BytesExt;
///
/// let frame = Frame {
///     header: Header {
///         frame_type:      FrameType::Data,
///         security:        false,
///         frame_pending:   false,
///         ack_request:     false,
///         pan_id_compress: false,
///         version:         FrameVersion::Ieee802154_2006,
///
///         seq:             0x00,
///         destination: Some(Address::Short(PanId(0x1234), ShortAddress(0x5678))),
///         source:      Some(Address::Short(PanId(0x1234), ShortAddress(0x9abc))),
///         auxiliary_security_header: None,
///     },
///     content: FrameContent::Data,
///     payload: &[0xde, 0xf0],
///     footer:  [0x12, 0x34]
/// };
///
/// // Work also with `let mut bytes = Vec::new()`;
/// let mut bytes = [0u8; 32];
/// let mut len = 0usize;
///
/// bytes.write_with(&mut len, frame, &mut FrameSerDesContext::no_security(FooterMode::Explicit)).unwrap();
///
/// let expected_bytes = [
///     0x01, 0x98,             // frame control
///     0x00,                   // sequence number
///     0x34, 0x12, 0x78, 0x56, // PAN identifier and address of destination
///     0x34, 0x12, 0xbc, 0x9a, // PAN identifier and address of source
///     0xde, 0xf0,             // payload
///     0x12, 0x34              // footer
/// ];
/// assert_eq!(bytes[..len], expected_bytes);
/// ```
///
/// [decode]: #method.try_read
/// [encode]: #method.try_write
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
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

/// A context that is used for serializing and deserializing frames, which also
/// stores the frame counter
pub struct FrameSerDesContext<'a, AEADBLKCIPH, KEYDESCLO>
where
    AEADBLKCIPH: NewBlockCipher + BlockCipher<BlockSize = U16>,
    KEYDESCLO: KeyLookup<AEADBLKCIPH::KeySize>,
{
    /// The footer mode to use when handling frames
    footer_mode: FooterMode,
    /// The security context for handling frames (if any)
    security_ctx: Option<&'a mut SecurityContext<AEADBLKCIPH, KEYDESCLO>>,
}

impl<'a, AEADBLKCIPH, KEYDESCLO> FrameSerDesContext<'a, AEADBLKCIPH, KEYDESCLO>
where
    AEADBLKCIPH: NewBlockCipher + BlockCipher<BlockSize = U16>,
    KEYDESCLO: KeyLookup<AEADBLKCIPH::KeySize>,
{
    /// Create a new frame serialization/deserialization context with the specified footer mode
    /// and security context
    pub fn new(
        mode: FooterMode,
        security_ctx: Option<&'a mut SecurityContext<AEADBLKCIPH, KEYDESCLO>>,
    ) -> Self {
        FrameSerDesContext {
            footer_mode: mode,
            security_ctx,
        }
    }
}

impl FrameSerDesContext<'_, Unimplemented, Unimplemented> {
    /// Create a new frame serialization/deserialization context with the specified footer mode,
    /// that does not facilitate any security functionality
    pub fn no_security(mode: FooterMode) -> Self {
        FrameSerDesContext {
            footer_mode: mode,
            security_ctx: None,
        }
    }
}

impl<AEADBLKCIPH, KEYDESCLO> TryWrite<&mut FrameSerDesContext<'_, AEADBLKCIPH, KEYDESCLO>>
    for Frame<'_>
where
    AEADBLKCIPH: NewBlockCipher + BlockCipher<BlockSize = U16>,
    KEYDESCLO: KeyLookup<AEADBLKCIPH::KeySize>,
{
    fn try_write(
        self,
        bytes: &mut [u8],
        context: &mut FrameSerDesContext<AEADBLKCIPH, KEYDESCLO>,
    ) -> byte::Result<usize> {
        let mode = &context.footer_mode;
        let offset = &mut 0;

        if self.header.security && context.security_ctx.is_none() {
            return Err(EncodeError::MissingSecurityCtx)?;
        }

        bytes.write(offset, self.header)?;
        bytes.write(offset, self.content)?;

        let mut security_enabled = false;

        if let Some(ctx) = context.security_ctx.as_mut() {
            let write_secured =
                security::secure_frame(self, ctx, context.footer_mode, &mut bytes[*offset..]);
            match write_secured {
                Ok(len) => {
                    security_enabled = true;
                    *offset += len
                }
                Err(e) => match e {
                    SecurityError::SecurityNotEnabled => {}
                    _ => return Err(e)?,
                },
            }
        }

        if !security_enabled {
            bytes.write(offset, self.payload.as_ref())?;
        }

        match mode {
            FooterMode::None => {}
            // TODO: recalculate the footer after encryption?
            FooterMode::Explicit => bytes.write(offset, &self.footer[..])?,
        }

        Ok(*offset)
    }
}

impl<'a> Frame<'a> {
    /// Try to read a frame. If the frame is secured, it will be unsecured
    ///
    /// Currently, this function does not support the explicit footer mode,
    /// as the FCS has to be calculated over the payload before it is unsecured,
    /// which isn't implemented yet
    ///
    /// Use FrameSerDexContext::no_security() and [`security::default::Unimplemented`] if you
    /// do not want to use any security, or simply [`Frame::try_read`]
    pub fn try_read_and_unsecure<AEADBLKCIPH, KEYDESCLO, DEVDESCLO>(
        buf: &'a mut [u8],
        ctx: &mut FrameSerDesContext<'_, AEADBLKCIPH, KEYDESCLO>,
        dev_desc_lo: &mut DEVDESCLO,
    ) -> Result<(Frame<'a>, usize), SecurityError>
    where
        AEADBLKCIPH: NewBlockCipher + BlockCipher<BlockSize = U16>,
        KEYDESCLO: KeyLookup<AEADBLKCIPH::KeySize>,
        DEVDESCLO: DeviceDescriptorLookup,
    {
        match ctx.footer_mode {
            FooterMode::None => {}
            FooterMode::Explicit => {
                unimplemented!()
            }
        }

        let offset = &mut 0;
        let header: Header = buf.read(offset)?;
        let content = buf.read_with(offset, &header)?;

        let mut tag_size = 0;

        if header.security {
            if let Some(sec_ctx) = ctx.security_ctx.as_mut() {
                tag_size = match security::unsecure_frame(
                    &header,
                    &mut buf[*offset..],
                    sec_ctx,
                    ctx.footer_mode,
                    dev_desc_lo,
                ) {
                    Ok(size) => size,
                    Err(e) => match e {
                        SecurityError::SecurityNotEnabled => 0,
                        _ => return Err(e),
                    },
                };
            } else {
                return Err(SecurityError::InvalidSecContext);
            }
        }
        let payload = buf.read_with(offset, Bytes::Len(buf.len() - *offset - tag_size))?;

        let frame = Frame {
            header,
            content,
            payload,
            footer: [0, 0],
        };

        Ok((frame, *offset))
    }
}

impl<'a> TryRead<'a, FooterMode> for Frame<'a> {
    /// Try to read a frame
    ///
    /// Frames that have security enabled can not be processed by this function, and an
    /// error will be returned if the frame contained in `bytes` does have it enabled.
    ///
    /// If you expect to receive secured frames, use [`Frame::try_read_with_unsecure`] instead,
    fn try_read(bytes: &'a [u8], mode: FooterMode) -> byte::Result<(Self, usize)> {
        let offset = &mut 0;
        let header: Header = bytes.read(offset)?;
        let content = bytes.read_with(offset, &header)?;

        if header.security {
            return Err(DecodeError::SecurityEnabled)?;
        }

        let (payload, footer) = match mode {
            FooterMode::None => (
                bytes.read_with(offset, Bytes::Len(bytes.len() - *offset))?,
                0u16,
            ),
            FooterMode::Explicit => (
                bytes.read_with(offset, Bytes::Len(bytes.len() - *offset - 2))?,
                bytes.read_with(offset, LE)?,
            ),
        };

        let frame = Frame {
            header,
            content,
            payload,
            footer: footer.to_le_bytes(),
        };
        Ok((frame, *offset))
    }
}

///
/// Controls whether the footer is read/written with the frame
///
/// Eventually, this should support three options:
/// 1. Don't read or write the footer
/// 2. Calculate the 2-byte CRC checksum and write that as the footer or check against read value
/// 3. Read into or write the footer from the `footer` field
///
/// For now, only 1 and 3 are supported.
///
/// [`Frame::try_write`](Frame::try_write)
#[derive(Clone, Copy)]
pub enum FooterMode {
    /// Don't read/write the footer
    None,
    /// Read into or write the footer from the `footer` field
    Explicit,
}

impl Default for FooterMode {
    fn default() -> Self {
        Self::None
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

impl TryWrite for FrameContent {
    fn try_write(self, bytes: &mut [u8], _ctx: ()) -> byte::Result<usize> {
        let offset = &mut 0;
        match self {
            FrameContent::Beacon(beacon) => bytes.write(offset, beacon)?,
            FrameContent::Data | FrameContent::Acknowledgement => (),
            FrameContent::Command(command) => bytes.write(offset, command)?,
        };
        Ok(*offset)
    }
}

impl TryRead<'_, &Header> for FrameContent {
    fn try_read(bytes: &[u8], header: &Header) -> byte::Result<(Self, usize)> {
        let offset = &mut 0;
        Ok((
            match header.frame_type {
                FrameType::Beacon => FrameContent::Beacon(bytes.read(offset)?),
                FrameType::Data => FrameContent::Data,
                FrameType::Acknowledgement => FrameContent::Acknowledgement,
                FrameType::MacCommand => FrameContent::Command(bytes.read(offset)?),
            },
            *offset,
        ))
    }
}

/// Signals an error that occured while decoding bytes
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum DecodeError {
    /// Buffer does not contain enough bytes
    NotEnoughBytes,

    /// The frame type is invalid
    InvalidFrameType(u8),

    /// Security is enabled on the frame, and `try_read` is called. [`Frame::try_read_with_unsecure`] should be called instead.
    SecurityEnabled,

    /// The frame's address mode is invalid
    InvalidAddressMode(u8),

    /// The frame's version is invalid or not supported
    InvalidFrameVersion(u8),

    /// The auxiliary security header's security level is invalid
    InvalidSecurityLevel(u8),

    /// The auxiliary security header's key identifier mode is invalid
    InvalidKeyIdentifierMode(u8),

    /// Security is enabled, but no Securty Context is provided
    MissingSecurityCtx,

    /// Security is enabled, but no Auxiliary Security Header is present
    AuxSecHeaderAbsent,

    /// The data stream contains an invalid value
    InvalidValue,
}

impl From<DecodeError> for byte::Error {
    fn from(e: DecodeError) -> Self {
        match e {
            DecodeError::NotEnoughBytes => byte::Error::Incomplete,
            DecodeError::InvalidFrameType(_) => byte::Error::BadInput {
                err: "InvalidFrameType",
            },
            DecodeError::InvalidAddressMode(_) => byte::Error::BadInput {
                err: "InvalidAddressMode",
            },
            DecodeError::InvalidFrameVersion(_) => byte::Error::BadInput {
                err: "InvalidFrameVersion",
            },
            DecodeError::InvalidValue => byte::Error::BadInput {
                err: "InvalidValue",
            },
            DecodeError::InvalidSecurityLevel(_) => byte::Error::BadInput {
                err: "InvalidSecurityLevel",
            },
            DecodeError::InvalidKeyIdentifierMode(_) => byte::Error::BadInput {
                err: "InvalidKeyIdentifierMode",
            },
            DecodeError::MissingSecurityCtx => byte::Error::BadInput {
                err: "MissingSecurityCtx",
            },
            DecodeError::AuxSecHeaderAbsent => byte::Error::BadInput {
                err: "AuxSecHeaderAbsent",
            },
            DecodeError::SecurityEnabled => byte::Error::BadInput {
                err: "SecurityEnabled (use Frame::try_read_with_unsecure)",
            },
        }
    }
}

/// Errors that can occur while securing or unsecuring a frame
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum EncodeError {
    /// Something went wrong while writing a frame's bytes to the destination
    WriteError,
    /// Security is enabled but no security context is specified
    MissingSecurityCtx,
}

impl From<EncodeError> for byte::Error {
    fn from(e: EncodeError) -> Self {
        match e {
            EncodeError::WriteError => byte::Error::BadInput { err: "WriteError" },
            EncodeError::MissingSecurityCtx => byte::Error::BadInput {
                err: "MissingSecurityCtx",
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::mac::beacon;
    use crate::mac::command;
    use crate::mac::frame::*;
    use crate::mac::{Address, ExtendedAddress, FrameVersion, PanId, ShortAddress};

    #[test]
    fn decode_ver0_pan_id_compression() {
        let data = [
            0x41, 0x88, 0x91, 0x8f, 0x20, 0xff, 0xff, 0x33, 0x44, 0x00, 0x00,
        ];

        let frame: Frame = data.read_with(&mut 0, FooterMode::None).unwrap();
        let hdr = frame.header;
        assert_eq!(hdr.frame_type, FrameType::Data);
        assert_eq!(hdr.security, false);
        assert_eq!(hdr.frame_pending, false);
        assert_eq!(hdr.ack_request, false);
        assert_eq!(hdr.pan_id_compress, true);
        assert_eq!(hdr.version, FrameVersion::Ieee802154_2003);
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
        let frame = data.read_with::<Frame>(&mut 0, FooterMode::None);
        assert!(frame.is_err());
        if let Err(e) = frame {
            assert_eq!(e, DecodeError::InvalidAddressMode(0).into())
        }
    }

    #[test]
    fn decode_ver0_extended() {
        let data = [
            0x21, 0xc8, 0x8b, 0xff, 0xff, 0x02, 0x00, 0x23, 0x00, 0x60, 0xe2, 0x16, 0x21, 0x1c,
            0x4a, 0xc2, 0xae, 0xaa, 0xbb, 0xcc,
        ];
        let frame: Frame = data.read_with(&mut 0, FooterMode::None).unwrap();
        let hdr = frame.header;
        assert_eq!(hdr.frame_type, FrameType::Data);
        assert_eq!(hdr.security, false);
        assert_eq!(hdr.frame_pending, false);
        assert_eq!(hdr.ack_request, true);
        assert_eq!(hdr.pan_id_compress, false);
        assert_eq!(hdr.version, FrameVersion::Ieee802154_2003);
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
                frame_type: FrameType::Data,
                security: false,
                frame_pending: false,
                ack_request: false,
                pan_id_compress: false,
                version: FrameVersion::Ieee802154_2003,
                destination: Some(Address::Short(PanId(0x1234), ShortAddress(0x5678))),
                source: Some(Address::Short(PanId(0x4321), ShortAddress(0x9abc))),
                seq: 0x01,
                auxiliary_security_header: None,
            },
            content: FrameContent::Data,
            payload: &[0xde, 0xf0],
            footer: [0x00, 0x00],
        };
        let mut buf = [0u8; 32];
        let mut len = 0usize;
        buf.write_with(
            &mut len,
            frame,
            &mut FrameSerDesContext::no_security(FooterMode::None),
        )
        .unwrap();
        assert_eq!(len, 13);
        assert_eq!(
            buf[..len],
            [0x01, 0x88, 0x01, 0x34, 0x12, 0x78, 0x56, 0x21, 0x43, 0xbc, 0x9a, 0xde, 0xf0]
        );
    }

    #[test]
    fn encode_ver1_extended() {
        let frame = Frame {
            header: Header {
                frame_type: FrameType::Beacon,
                security: false,
                frame_pending: true,
                ack_request: false,
                pan_id_compress: false,
                version: FrameVersion::Ieee802154_2006,
                destination: Some(Address::Extended(
                    PanId(0x1234),
                    ExtendedAddress(0x1122334455667788),
                )),
                source: Some(Address::Short(PanId(0x4321), ShortAddress(0x9abc))),
                seq: 0xff,
                auxiliary_security_header: None,
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
        let mut buf = [0u8; 32];
        let mut len = 0usize;
        buf.write_with(
            &mut len,
            frame,
            &mut FrameSerDesContext::no_security(FooterMode::None),
        )
        .unwrap();
        assert_eq!(len, 23);
        assert_eq!(
            buf[..len],
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
                frame_type: FrameType::Acknowledgement,
                security: false,
                frame_pending: false,
                ack_request: false,
                pan_id_compress: true,
                version: FrameVersion::Ieee802154_2003,
                destination: Some(Address::Extended(
                    PanId(0x1234),
                    ExtendedAddress(0x1122334455667788),
                )),
                source: Some(Address::Short(PanId(0x1234), ShortAddress(0x9abc))),
                seq: 0xff,
                auxiliary_security_header: None,
            },
            content: FrameContent::Acknowledgement,
            payload: &[],
            footer: [0x00, 0x00],
        };
        let mut buf = [0u8; 32];
        let mut len = 0usize;
        buf.write_with(
            &mut len,
            frame,
            &mut FrameSerDesContext::no_security(FooterMode::None),
        )
        .unwrap();
        assert_eq!(len, 15);
        assert_eq!(
            buf[..len],
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
                frame_type: FrameType::MacCommand,
                security: false,
                frame_pending: false,
                ack_request: true,
                pan_id_compress: false,
                version: FrameVersion::Ieee802154,
                destination: None,
                source: Some(Address::Short(PanId(0x1234), ShortAddress(0x9abc))),
                seq: 0xff,
                auxiliary_security_header: None,
            },
            content: FrameContent::Command(command::Command::DataRequest),
            payload: &[],
            footer: [0x00, 0x00],
        };
        let mut buf = [0u8; 32];
        let mut len = 0usize;
        buf.write_with(
            &mut len,
            frame,
            &mut FrameSerDesContext::no_security(FooterMode::None),
        )
        .unwrap();
        assert_eq!(len, 8);
        assert_eq!(buf[..len], [0x23, 0xa0, 0xff, 0x34, 0x12, 0xbc, 0x9a, 0x04]);
    }
}
