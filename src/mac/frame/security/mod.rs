//! All of the fields and their contents that are used in the
//! Auxiliary Security header can be found in this module.
//!
//! All of the below data structures are defined in section 7.4 of the 802.15.4-2011 standard

use core::marker::PhantomData;

use byte::{BytesExt, TryRead, TryWrite, LE};
use ccm::{
    aead::{
        generic_array::{
            typenum::consts::{U13, U16, U4, U8},
            ArrayLength, GenericArray,
        },
        AeadInPlace, NewAead, Tag,
    },
    Ccm,
};
use cipher::BlockCipher;

use crate::mac::{Address, FrameType, FrameVersion};

use super::{Frame, Header};

pub(crate) mod default;
mod security_control;
pub use security_control::{KeyIdentifierMode, SecurityControl, SecurityLevel};

/// A struct describing the Auxiliary Security Header
/// See: section 7.4 of the 802.15.4-2011 standard
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct AuxiliarySecurityHeader {
    /// The control field in the Auxiliary Security Header
    pub control: SecurityControl,
    /// If the frame_counter_suppression field in [`AuxiliarySecurityHeader::control`] is not set, this field contains
    /// the frame counter
    pub frame_counter: u32,
    /// If the key_identifier field in [`AuxiliarySecurityHeader::control`] is set, this field contains the key identifier
    /// of this frame, otherwise it is None
    pub key_identifier: Option<KeyIdentifier>,
}

impl AuxiliarySecurityHeader {
    /// Get the size of this security header, in octets
    pub fn get_octet_size(&self) -> u8 {
        // SecurityControl length + FrameCounter length
        let length = 1
            + 4
            + match self.key_identifier {
                Some(key_id) => match key_id.key_source {
                    Some(source) => match source {
                        KeySource::Short(_) => 5,
                        KeySource::Long(_) => 9,
                    },
                    None => 1,
                },
                None => 0,
            };
        length
    }
}

impl TryRead<'_> for AuxiliarySecurityHeader {
    fn try_read(bytes: &[u8], _ctx: ()) -> byte::Result<(Self, usize)> {
        let offset = &mut 0;

        let control: SecurityControl = bytes.read(offset)?;
        let frame_counter = bytes.read_with(offset, LE)?;

        let mut header = AuxiliarySecurityHeader {
            control,
            frame_counter,
            key_identifier: None,
        };

        // Construct the KeyIdentifier in case the KeyIdentifierMode is not None
        if control.key_id_mode != KeyIdentifierMode::None {
            let mut key_identifier = KeyIdentifier {
                key_source: None,
                key_index: 0,
            };
            match control.key_id_mode {
                KeyIdentifierMode::KeySource4 => {
                    key_identifier.key_source = Some(KeySource::Short(bytes.read(offset)?));
                }
                KeyIdentifierMode::KeySource8 => {
                    key_identifier.key_source = Some(KeySource::Long(bytes.read(offset)?));
                }
                _ => {}
            }
            let key_index = bytes.read(offset)?;
            key_identifier.key_index = key_index;
            header.key_identifier = Some(key_identifier);
        }

        Ok((header, *offset))
    }
}

impl TryWrite for AuxiliarySecurityHeader {
    fn try_write(mut self, bytes: &mut [u8], _ctx: ()) -> byte::Result<usize> {
        let offset = &mut 0;

        // Set the key id mode to that corresponding to the configured
        // key identifier in the control field
        self.control.key_id_mode = match self.key_identifier {
            Some(key_id) => match key_id.key_source {
                Some(key_source) => match key_source {
                    KeySource::Short(_) => KeyIdentifierMode::KeySource4,
                    KeySource::Long(_) => KeyIdentifierMode::KeySource8,
                },
                None => KeyIdentifierMode::KeyIndex,
            },
            None => KeyIdentifierMode::None,
        };

        bytes.write(offset, self.control)?;
        bytes.write(offset, self.frame_counter)?;
        match self.key_identifier {
            Some(key_identifier) => {
                bytes.write(offset, key_identifier)?;
            }
            _ => {}
        }
        Ok(*offset)
    }
}

/// A key identifier
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct KeyIdentifier {
    /// The key source to be used for determining a key from this key identifier (if any)
    pub key_source: Option<KeySource>,
    /// The key index to use for determining a key from this key identifier
    pub key_index: u8,
}

impl TryWrite for KeyIdentifier {
    fn try_write(self, bytes: &mut [u8], _ctx: ()) -> byte::Result<usize> {
        let offset = &mut 0;
        match self.key_source {
            Some(source) => match source {
                KeySource::Short(src) => bytes.write(offset, src)?,
                KeySource::Long(src) => bytes.write(offset, src)?,
            },
            _ => {}
        }

        bytes.write(offset, self.key_index)?;

        Ok(*offset)
    }
}

/// A key source
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum KeySource {
    /// A key source that is 4 octets long
    Short(u32),
    /// A key source that is 8 octets long
    Long(u64),
}

/// The addressing mode to use during descriptor lookups
pub enum AddressingMode {
    /// Destination addressing mode
    DstAddrMode,
    /// Source addressing mode
    SrcAddrMode,
}

/// A partial key descriptor
pub struct KeyDescriptor {
    /// The key contained by this key descriptor
    pub key: [u8; 16],
}

/// A partial device descriptor
pub struct DeviceDescriptor {
    /// The address of this device
    pub address: Address,
    /// The frame counter associated with this device
    pub frame_counter: u32,
    /// Whether this device is allowed to override the minimum security level
    pub exempt: bool,
}

/// Used to create a KeyDescriptor from a KeyIdentifier and device address
pub trait KeyLookup<N>
where
    N: ArrayLength<u8>,
{
    /// Look up a key from a key identifier and a device address
    ///
    /// This function should return None if the key lookup fails (i.e. a failed status),
    /// and some if the lookup succeeds, where the Option contains the KeyDescriptor that was
    /// found according to the passed in parameters
    fn lookup_key(
        &self,
        address_mode: AddressingMode,
        key_identifier: Option<KeyIdentifier>,
        device_address: Option<Address>,
    ) -> Option<GenericArray<u8, N>>;
}

/// Perform a lookup of a device descriptor based on the provided address
pub trait DeviceDescriptorLookup {
    /// look up a device
    fn lookup_device(
        &self,
        addressing_mode: AddressingMode,
        address: Address,
    ) -> Option<&mut DeviceDescriptor>;
}

/// A context that used to keep track of cryptographic properties that
/// are necessary for securing/unsecuring frames
///
/// AEAD is the type that will provide an AEAD instance to be used for the
/// encryption/decryption process
///
/// NONCEGEN is the type that will convert the nonce created using the 802.15.4 standard
/// into a nonce of the size that can be accepted by the provided AEAD algorithm
pub struct SecurityContext<'a, AEADBLKCIPH, KEYDESCLO, KEYSIZE>
where
    KEYSIZE: ArrayLength<u8>,
    AEADBLKCIPH: BlockCipher<BlockSize = U16>,
    KEYDESCLO: KeyLookup<KEYSIZE>,
{
    /// The current frame counter
    pub frame_counter: u32,
    /// The key descriptor lookup to use to look up keys
    pub key_provider: &'a KEYDESCLO,
    /// This is phantom data as we use AEAD to actually instantiate an instance
    /// of AEAD, as opposed to actually using a provided AEAD instance somewhere
    ///
    /// The NONCEGEN is phantom data as well
    phantom_data: PhantomData<(AEADBLKCIPH, KEYSIZE)>,
}

/// Appends the auxiliary security header and
/// secured payload of a [Frame] to the provided buffer, secured according to the security settings specified in
/// the [Frame]'s [`super::Header`] and [AuxiliarySecurityHeader].
///
/// Offset is updated with the amount of bytes that is written
///
/// Currently only supports the securing of Data frames with extended addresses
///
/// Partial implementation of 7.2.1
pub fn secure_frame<'a, AEADBLKCIPH, KEYDESCLO, KEYSIZE>(
    frame: Frame<'_>,
    context: &mut SecurityContext<AEADBLKCIPH, KEYDESCLO, KEYSIZE>,
    offset: &mut usize,
    buffer: &mut [u8],
) -> Result<(), SecurityError>
where
    AEADBLKCIPH: BlockCipher<BlockSize = U16>,
    KEYSIZE: ArrayLength<u8>,
    KEYDESCLO: KeyLookup<KEYSIZE>,
{
    let header = frame.header;

    if header.security {
        let frame_counter = &mut context.frame_counter;
        let destination = match header.destination {
            Some(addr) => addr,
            _ => return Err(SecurityError::NoSourceAddress),
        };

        // Check for unimplemented behaviour before performing any operations on the buffer
        match header.frame_type {
            FrameType::Data => {}
            _ => return Err(SecurityError::NotImplemented),
        }

        let mut input_nonce = [0u8; 13];
        match destination {
            // Not implemented because currently no functionality for determining the
            // extended address with which a short address is associated exists
            Address::Short(..) => return Err(SecurityError::NotImplemented),
            Address::Extended(_, addr) => {
                // Generate the nonce as described in 7.2.2
                for i in 0..7 {
                    input_nonce[i] = (addr.0 >> (8 * i) & 0xFF) as u8;
                }
            }
        };

        // Procedure 7.2.1
        if let Some(aux_sec_header) = header.auxiliary_security_header {
            let auth_len = aux_sec_header.control.security_level.get_mic_octet_count();
            let aux_len = aux_sec_header.get_octet_size();

            // If frame size plus AuthLen plus AuxLen plus FCS is bigger than aMaxPHYPacketSize
            // 7.2.1b4
            if !(frame.header.get_octet_size() + aux_len + auth_len + 2 <= 127) {
                return Err(SecurityError::FrameTooLong);
            }

            // Write auxilary authentication header to buffer
            // This is technically only 7.2.1f, but if we perform 7.1.2c first, it would mean that
            // no auxiliary security header is present even if Security Enabled is set to 1
            if let Err(_) = buffer.write(offset, aux_sec_header) {
                return Err(SecurityError::WriteError);
            }

            // Write unencrypted data to the buffer, 7.2.1c, preparation for in-place AEAD in 7.2.1g
            if let Err(_) = buffer.write(offset, frame.payload) {
                return Err(SecurityError::WriteError);
            }

            // Success if the security level is none (7.2.1c)
            if aux_sec_header.control.security_level == SecurityLevel::None {
                return Ok(());
            }

            // 7.2.1d
            if *frame_counter == 0xFFFFFFFF {
                return Err(SecurityError::CounterError);
            }

            // Partial 7.2.1e, 7.2.2 is only partially implemented
            if let Some(key) = context.key_provider.lookup_key(
                AddressingMode::DstAddrMode,
                aux_sec_header.key_identifier,
                header.destination,
            ) {
                let aead = match aux_sec_header.control.security_level {
                    SecurityLevel::None => None,
                    SecurityLevel::ENC => Ccm::new(&key),
                    SecurityLevel::MIC32 | SecurityLevel::ENCMIC32 => {
                        Ccm::<AEAD32, U4, U13>::new(&key)
                    }
                    SecurityLevel::MIC64 | SecurityLevel::ENCMIC64 => Ccm::new(&key),
                    SecurityLevel::MIC128 | SecurityLevel::ENCMIC128 => Ccm::new(&key),
                };

                // 7.2.1g
                let tag = match aux_sec_header.control.security_level {
                    SecurityLevel::None => None,
                    SecurityLevel::MIC32 | SecurityLevel::MIC64 | SecurityLevel::MIC128 => {
                        Some(aead.encrypt_in_place_detached(&nonce, buffer, &mut []))
                    }
                    SecurityLevel::ENC
                    | SecurityLevel::ENCMIC32
                    | SecurityLevel::ENCMIC64
                    | SecurityLevel::ENCMIC128 => {
                        Some(aead.encrypt_in_place_detached(&nonce, &mut [], buffer))
                    }
                };

                // Encrypt the payload (excluding the FCR)
                if let Some(Ok(tag)) = tag {
                    let mic = get_truncated_mic::<AEAD, AEAD::TagSize>(&tag);
                    if let Err(_) = buffer.write(offset, mic.as_slice()) {
                        return Err(SecurityError::TagWriteError);
                    }
                    return Ok(());
                } else {
                    return Err(SecurityError::TransformationError);
                }
            } else {
                return Err(SecurityError::UnavailableKey);
            }
        } else {
            return Err(SecurityError::AuxSecHeaderAbsent);
        }
    } else {
        if header.auxiliary_security_header.is_some() {
            return Err(SecurityError::AuxSecHeaderPresent);
        } else {
            return Err(SecurityError::SecurityNotEnabled);
        }
    }
}

/// Unsecure a currently secured frame, based on the
/// settings found in the header of `frame`
///
/// Replaces the payload of `frame` with the unsecured version
///
/// Partial implementation of 7.2.3
/// Currently not implemented: 7.2.3h, 7.2.3i, 7.2.3j, 7.2.3k, 7.2.3n
fn unsecure_frame<'a, AEADBLKCIPH, KEYDESCLO, KEYSIZE, DEVDESCLO>(
    header: &mut Header,
    offset: &mut usize,
    bytes: &mut [u8],
    context: &mut SecurityContext<AEADBLKCIPH, KEYDESCLO, KEYSIZE>,
    dev_desc_lo: DEVDESCLO,
) -> Result<(), SecurityError>
where
    KEYSIZE: ArrayLength<u8>,
    AEADBLKCIPH: BlockCipher<BlockSize = U16>,
    KEYDESCLO: KeyLookup<KEYSIZE>,
{
    if header.security {
        let source = match header.source {
            Some(addr) => addr,
            _ => return Err(SecurityError::NoDestinationAddress),
        };

        // Check for unimplemented behaviour before performing any operations on the buffer
        match header.frame_type {
            FrameType::Data => {}
            _ => return Err(SecurityError::NotImplemented),
        }

        let mut input_nonce = [0u8; 13];
        match source {
            // Not implemented because currently no functionality for determining the
            // extended address with which a short address is associated exists
            Address::Short(..) => return Err(SecurityError::NotImplemented),
            Address::Extended(_, addr) => {
                // Generate the nonce as described in 7.2.2
                for i in 0..7 {
                    input_nonce[i] = (addr.0 >> (8 * i) & 0xFF) as u8;
                }
            }
        };
        // 7.2.3b
        if header.version == FrameVersion::Ieee802154_2003 {
            return Err(SecurityError::UnsupportedLegacy);
        }

        let aux_sec_header = match header.auxiliary_security_header {
            Some(header) => header,
            None => return Err(SecurityError::AuxSecHeaderAbsent),
        };

        // 7.2.3c/d (partial)
        if aux_sec_header.control.security_level == SecurityLevel::None {
            return Err(SecurityError::UnsupportedSecurity);
        }

        // 7.2.3f
        if let Some(key) = context.key_provider.lookup_key(
            AddressingMode::SrcAddrMode,
            aux_sec_header.key_identifier,
            header.source,
        ) {
            if let Some(device) = dev_desc_lo.lookup_device(AddressingMode::SrcAddrMode, source) {
                let frame_counter = &mut device.frame_counter;
                // 7.2.3l, 7.2.3m
                if *frame_counter == 0xFFFFFFFF || aux_sec_header.frame_counter < *frame_counter {
                    return Err(SecurityError::CounterError);
                }

                let aead_in_place = match AEAD::new_varkey(&key.as_slice()) {
                    Ok(key) => key,
                    Err(_) => return Err(SecurityError::KeyFailure)?,
                };

                // 7.2.1o, 7.2.3p
                let tag =
                    match aux_sec_header.control.security_level {
                        SecurityLevel::None => None,
                        SecurityLevel::MIC32 | SecurityLevel::MIC64 | SecurityLevel::MIC128 => {
                            Some(aead_in_place.decrypt_in_place(&nonce, bytes, &mut []))
                        }
                        SecurityLevel::ENC
                        | SecurityLevel::ENCMIC32
                        | SecurityLevel::ENCMIC64
                        | SecurityLevel::ENCMIC128 => Some(
                            aead_in_place.decrypt_in_place_detached(&nonce, &mut [], frame.payload),
                        ),
                    };
            } else {
                return Err(SecurityError::UnavailableDevice);
            }
        } else {
            return Err(SecurityError::UnavailableKey);
        }

        return Ok(());
    } else {
        if header.auxiliary_security_header.is_some() {
            return Err(SecurityError::AuxSecHeaderPresent);
        } else {
            return Err(SecurityError::SecurityNotEnabled);
        }
    }
}

fn get_truncated_mic<AEAD, LEN>(input_tag: &Tag<AEAD::TagSize>) -> GenericArray<u8, LEN>
where
    AEAD: AeadInPlace,
    LEN: ArrayLength<u8>,
{
    let mut finished_mic = GenericArray::default();
    let start = input_tag.len() - LEN::to_usize();
    let end = LEN::to_usize();
    finished_mic.copy_from_slice(&input_tag[start..end]);
    finished_mic
}

/// Errors that can occur while performing security operations on frames
pub enum SecurityError {
    /// Security is not enabled for this frame
    SecurityNotEnabled,
    /// The provided security context cannot be used to secure the frame
    InvalidSecContext,
    /// The frame is too long after appending all security data
    FrameTooLong,
    /// The counter used for securing a frame is invalid (0xFFFFFFFF)
    CounterError,
    /// No key could be found for the provided context
    UnavailableKey,
    /// The key could not be used in an adequate manner
    KeyFailure,
    /// The frame to be unsecured has no source address specified. The source
    /// address is necessary to calculate the nonce, in some cases
    NoSourceAddress,
    /// The frame to be secured has no destination address specified. The destination
    /// address is necessary to calculate the nonce, in some cases
    NoDestinationAddress,
    /// The security (CCM*) transformation could not be completed successfully
    TransformationError,
    /// Something went wrong while writing the frame's payload bytes to the buffer
    WriteError,
    /// Something went wrong while writing a frame's tag to the buffer
    TagWriteError,
    /// When functionality that is not implemented is used
    NotImplemented,
    /// Security is enabled, but no auxiliary security header is present
    AuxSecHeaderAbsent,
    /// Security is disabled, but an auxiliary security header is present
    AuxSecHeaderPresent,
    /// The type of key identifier mode specified in the security control differs from
    /// the type of key identifier present in the key_identifier field
    KeyIdentifierMismatch,
    /// When a frame with an unsupported legacy version is passed to the unsecuring function
    UnsupportedLegacy,
    /// The security level of an incomin frame is zero
    UnsupportedSecurity,
    /// The device descriptor that belongs to an address can not be found
    UnavailableDevice,
}

impl From<SecurityError> for byte::Error {
    fn from(e: SecurityError) -> Self {
        match e {
            SecurityError::InvalidSecContext => byte::Error::BadInput {
                err: "InvalidSecContext",
            },
            SecurityError::FrameTooLong => byte::Error::BadInput {
                err: "FrameTooLong",
            },
            SecurityError::CounterError => byte::Error::BadInput {
                err: "CounterError",
            },
            SecurityError::UnavailableKey => byte::Error::BadInput {
                err: "UnavailableKey",
            },
            SecurityError::KeyFailure => byte::Error::BadInput { err: "KeyFailure" },
            SecurityError::NoSourceAddress => byte::Error::BadInput {
                err: "NoSourceAddress",
            },
            SecurityError::NoDestinationAddress => byte::Error::BadInput {
                err: "NoDstAddress",
            },
            SecurityError::TransformationError => byte::Error::BadInput {
                err: "TransformationError",
            },
            SecurityError::TagWriteError => byte::Error::BadInput {
                err: "TagWriteError",
            },
            SecurityError::SecurityNotEnabled => byte::Error::BadInput {
                err: "SecurityNotEnabled",
            },
            SecurityError::WriteError => byte::Error::BadInput { err: "WriteError" },
            SecurityError::NotImplemented => byte::Error::BadInput {
                err: "NotImplemented",
            },
            SecurityError::AuxSecHeaderAbsent => byte::Error::BadInput {
                err: "AuxSecHeaderAbsent",
            },
            SecurityError::AuxSecHeaderPresent => byte::Error::BadInput {
                err: "WriteErAuxSecHeaderPresentror",
            },
            SecurityError::KeyIdentifierMismatch => byte::Error::BadInput {
                err: "KeyIdentifierMismatch",
            },
            SecurityError::UnsupportedLegacy => byte::Error::BadInput {
                err: "UnsupportedLegacy",
            },
            SecurityError::UnsupportedSecurity => byte::Error::BadInput {
                err: "UnsupportedSecurity",
            },
            SecurityError::UnavailableDevice => byte::Error::BadInput {
                err: "UnavailableDevice",
            },
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate ccm;
    extern crate chacha20poly1305;
    use crate::mac::frame::header::*;
    use crate::mac::frame::security::{security_control::*, *};
    use crate::mac::frame::*;
    use crate::mac::{frame::frame_control::*, FooterMode};
    use ccm::aead::generic_array::typenum::Unsigned;
    use chacha20poly1305::ChaCha8Poly1305;

    type KeySize = <ChaCha8Poly1305 as NewAead>::KeySize;
    type NonceSize = <ChaCha8Poly1305 as AeadInPlace>::NonceSize;
    struct StaticKeyLookup();

    impl KeyLookup<KeySize> for StaticKeyLookup {
        fn lookup_key(
            &self,
            _address_mode: AddressingMode,
            _key_identifier: Option<KeyIdentifier>,
            _device_address: Option<Address>,
        ) -> Option<GenericArray<u8, KeySize>> {
            let mut key = GenericArray::default();
            key[0] = 0x01;
            key[2] = 0x02;
            key[3] = 0x03;
            for i in 4..KeySize::to_usize() {
                key[i] = 0x00;
            }
            Some(key)
        }
    }

    const STATIC_KEY_LOOKUP: StaticKeyLookup = StaticKeyLookup();

    fn c8p1305_sec_ctx<'a>(
        frame_counter: u32,
    ) -> SecurityContext<'a, ChaCha8Poly1305, StaticKeyLookup, ChaCha8Poly1305NonceGenerator> {
        SecurityContext {
            frame_counter,
            key_provider: &STATIC_KEY_LOOKUP,
            phantom_data: PhantomData,
        }
    }

    fn frame_serdes_ctx<'a>(
        security_ctx: &'a mut SecurityContext<
            'a,
            ChaCha8Poly1305,
            StaticKeyLookup,
            ChaCha8Poly1305NonceGenerator,
        >,
    ) -> FrameSerDesContext<'a, ChaCha8Poly1305, StaticKeyLookup, ChaCha8Poly1305NonceGenerator>
    {
        FrameSerDesContext {
            security_ctx: Some(security_ctx),
            footer_mode: FooterMode::None,
        }
    }

    fn get_frame<'a>(
        security: bool,
        auxiliary_security_header: Option<AuxiliarySecurityHeader>,
    ) -> Frame<'a> {
        Frame {
            header: Header {
                frame_type: FrameType::Data,
                security,
                frame_pending: false,
                ack_request: false,
                pan_id_compress: false,
                version: FrameVersion::Ieee802154,
                seq: 127,
                destination: Some(Address::Extended(
                    PanId(255),
                    ExtendedAddress(0xFFAAFFAAFFAAu64),
                )),
                source: Some(Address::Extended(
                    PanId(511),
                    ExtendedAddress(0xAAFFAAFFAAFFu64),
                )),
                auxiliary_security_header: auxiliary_security_header,
            },
            content: FrameContent::Data,
            payload: &[0xAA, 0xBB, 0xCC, 0xDD, 0xFE, 0xDE],
            footer: [0x00, 0x00],
        }
    }

    #[test]
    fn encode_unsecured() {
        let frame = get_frame(false, None);

        let offset = &mut 0;
        let mut buf = [0u8; 127];
        let mut sec_ctx = c8p1305_sec_ctx(1000);
        let write_res = security::secure_frame(frame, &mut sec_ctx, offset, &mut buf);
        if let Err(SecurityError::SecurityNotEnabled) = write_res {
        } else {
            assert!(
                false,
                "Security was not enabled, but securing payload succeeded!"
            );
        }
    }
    #[test]
    fn encode_secured() {
        let aux_sec_header = Some(AuxiliarySecurityHeader {
            control: SecurityControl {
                security_level: SecurityLevel::None,
                key_id_mode: KeyIdentifierMode::None,
            },
            frame_counter: 1337,
            key_identifier: Some(KeyIdentifier {
                key_source: None,
                key_index: 0,
            }),
        });

        let frame = get_frame(true, aux_sec_header);

        let mut buf = [0u8; 127];
        let mut sec_ctx = c8p1305_sec_ctx(1000);
        let frame_serdes_ctx = frame_serdes_ctx(&mut sec_ctx);
        let write_res = frame.try_write(&mut buf, frame_serdes_ctx);
        assert!(write_res.is_ok());
    }
}
