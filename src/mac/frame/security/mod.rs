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
        AeadInPlace, NewAead,
    },
    Ccm,
};
use cipher::{BlockCipher, NewBlockCipher};

use crate::mac::{Address, FrameType, FrameVersion};

use super::{FooterMode, Frame};

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
        &mut self,
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
#[derive(Clone, Copy)]
pub struct SecurityContext<'a, AEADBLKCIPH, KEYDESCLO>
where
    AEADBLKCIPH: NewBlockCipher + BlockCipher<BlockSize = U16>,
    KEYDESCLO: KeyLookup<AEADBLKCIPH::KeySize>,
{
    /// The current frame counter
    pub frame_counter: u32,
    /// The key descriptor lookup to use to look up keys
    pub key_provider: &'a KEYDESCLO,
    /// This is phantom data as we use AEAD to actually instantiate an instance
    /// of AEAD, as opposed to actually using a provided AEAD instance somewhere
    ///
    /// The NONCEGEN is phantom data as well
    phantom_data: PhantomData<AEADBLKCIPH>,
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
pub fn secure_frame<'a, AEADBLKCIPH, KEYDESCLO>(
    frame: Frame<'_>,
    context: &mut SecurityContext<AEADBLKCIPH, KEYDESCLO>,
    offset: &mut usize,
    buffer: &mut [u8],
) -> Result<(), SecurityError>
where
    AEADBLKCIPH: NewBlockCipher + BlockCipher<BlockSize = U16>,
    KEYDESCLO: KeyLookup<AEADBLKCIPH::KeySize>,
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

        let mut nonce = [0u8; 13];
        match destination {
            // Not implemented because currently no functionality for determining the
            // extended address with which a short address is associated exists
            Address::Short(..) => return Err(SecurityError::NotImplemented),
            Address::Extended(_, addr) => {
                // Generate the nonce as described in 7.2.2
                for i in 0..7 {
                    nonce[i] = (addr.0 >> (8 * i) & 0xFF) as u8;
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
            if let Err(e) = buffer.write(offset, aux_sec_header) {
                return Err(SecurityError::WriteError(e));
            }

            // Write unencrypted data to the buffer, 7.2.1c, preparation for in-place AEAD in 7.2.1g
            if let Err(e) = buffer.write(offset, frame.payload) {
                return Err(SecurityError::WriteError(e));
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
                // 7.2.1g
                let sec_l = aux_sec_header.control.security_level;
                let aux_sec_header_len = aux_sec_header.get_octet_size() as usize;
                match sec_l {
                    SecurityLevel::None => {}
                    SecurityLevel::ENC => {
                        // No support for encryption without authentication
                        return Err(SecurityError::NotImplemented);
                    }
                    SecurityLevel::MIC32 | SecurityLevel::ENCMIC32 => {
                        let aead = Ccm::<AEADBLKCIPH, U4, U13>::new(&key);

                        let auth_enc_part = &mut buffer[aux_sec_header_len + 1..*offset];

                        let tag = match sec_l {
                            SecurityLevel::MIC32 => aead.encrypt_in_place_detached(
                                &GenericArray::from_slice(&nonce),
                                auth_enc_part,
                                &mut [],
                            ),
                            SecurityLevel::ENCMIC32 => aead.encrypt_in_place_detached(
                                &GenericArray::from_slice(&nonce),
                                &mut [],
                                auth_enc_part,
                            ),
                            _ => {
                                panic!("Impossible")
                            }
                        };
                        if let Ok(tag) = tag {
                            if let Err(e) = buffer.write(offset, tag.as_slice()) {
                                return Err(SecurityError::WriteError(e));
                            }
                        } else {
                            return Err(SecurityError::TransformationError);
                        }
                    }
                    SecurityLevel::MIC64 | SecurityLevel::ENCMIC64 => {
                        let aead = Ccm::<AEADBLKCIPH, U8, U13>::new(&key);

                        let auth_enc_part = &mut buffer[aux_sec_header_len + 1..*offset];

                        let tag = match sec_l {
                            SecurityLevel::MIC64 => aead.encrypt_in_place_detached(
                                &GenericArray::from_slice(&nonce),
                                auth_enc_part,
                                &mut [],
                            ),
                            SecurityLevel::ENCMIC64 => aead.encrypt_in_place_detached(
                                &GenericArray::from_slice(&nonce),
                                &mut [],
                                auth_enc_part,
                            ),
                            _ => {
                                panic!("Impossible")
                            }
                        };
                        if let Ok(tag) = tag {
                            if let Err(e) = buffer.write(offset, tag.as_slice()) {
                                return Err(SecurityError::WriteError(e));
                            }
                        } else {
                            return Err(SecurityError::TransformationError);
                        }
                    }
                    SecurityLevel::MIC128 | SecurityLevel::ENCMIC128 => {
                        let aead = Ccm::<AEADBLKCIPH, U16, U13>::new(&key);

                        let auth_enc_part = &mut buffer[aux_sec_header_len + 1..*offset];

                        let tag = match sec_l {
                            SecurityLevel::MIC128 => aead.encrypt_in_place_detached(
                                &GenericArray::from_slice(&nonce),
                                auth_enc_part,
                                &mut [],
                            ),
                            SecurityLevel::ENCMIC128 => aead.encrypt_in_place_detached(
                                &GenericArray::from_slice(&nonce),
                                &mut [],
                                auth_enc_part,
                            ),
                            _ => {
                                panic!("Impossible")
                            }
                        };
                        if let Ok(tag) = tag {
                            if let Err(e) = buffer.write(offset, tag.as_slice()) {
                                return Err(SecurityError::WriteError(e));
                            }
                        } else {
                            return Err(SecurityError::TransformationError);
                        }
                    }
                    #[allow(unreachable_patterns)]
                    _ => {}
                };
                return Ok(());
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
fn unsecure_frame<'a, AEADBLKCIPH, KEYDESCLO, DEVDESCLO>(
    frame: &mut Frame<'a>,
    offset: &mut usize,
    buffer: &'a mut [u8],
    context: &mut SecurityContext<AEADBLKCIPH, KEYDESCLO>,
    footer_mode: FooterMode,
    dev_desc_lo: &mut DEVDESCLO,
) -> Result<(), SecurityError>
where
    AEADBLKCIPH: NewBlockCipher + BlockCipher<BlockSize = U16>,
    KEYDESCLO: KeyLookup<AEADBLKCIPH::KeySize>,
    DEVDESCLO: DeviceDescriptorLookup,
{
    let header = frame.header;
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

        let mut nonce = [0u8; 13];
        match source {
            // Not implemented because currently no functionality for determining the
            // extended address with which a short address is associated exists
            Address::Short(..) => return Err(SecurityError::NotImplemented),
            Address::Extended(_, addr) => {
                // Generate the nonce as described in 7.2.2
                for i in 0..7 {
                    nonce[i] = (addr.0 >> (8 * i) & 0xFF) as u8;
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
            match dev_desc_lo.lookup_device(AddressingMode::SrcAddrMode, source) {
                Some(device) => {
                    let frame_counter = &mut device.frame_counter;
                    // 7.2.3l, 7.2.3m
                    if *frame_counter == 0xFFFFFFFF || aux_sec_header.frame_counter < *frame_counter
                    {
                        return Err(SecurityError::CounterError);
                    }

                    let buffer_len = buffer.len();

                    let buffer_slice = match footer_mode {
                        FooterMode::None => &mut buffer[*offset..],
                        FooterMode::Explicit => &mut buffer[*offset..buffer_len - 2],
                    };

                    let sec_l = aux_sec_header.control.security_level;
                    match sec_l {
                        SecurityLevel::None => {}
                        SecurityLevel::ENC => {
                            // No support for encryption without authentication
                            return Err(SecurityError::NotImplemented);
                        }
                        SecurityLevel::MIC32 | SecurityLevel::ENCMIC32 => {
                            let aead = Ccm::<AEADBLKCIPH, U4, U13>::new(&key);
                            let taglen = sec_l.get_mic_octet_count() as usize;

                            // Copy the tag out of the aead slice
                            let buffer_len = buffer_slice.len();
                            let tag = GenericArray::from_slice(
                                &buffer_slice[buffer_len - taglen..buffer_len],
                            )
                            .clone();

                            let auth_enc_part = &mut buffer_slice[..buffer_len - taglen];

                            let verify = match sec_l {
                                SecurityLevel::MIC32 => aead.decrypt_in_place_detached(
                                    &GenericArray::from_slice(&nonce),
                                    auth_enc_part,
                                    &mut [],
                                    &tag,
                                ),
                                SecurityLevel::ENCMIC32 => aead.decrypt_in_place_detached(
                                    &GenericArray::from_slice(&nonce),
                                    &mut [],
                                    auth_enc_part,
                                    &tag,
                                ),
                                _ => {
                                    panic!("Impossible")
                                }
                            };
                            if let Ok(_) = verify {
                                frame.payload = auth_enc_part;
                            } else {
                                return Err(SecurityError::TransformationError);
                            }
                        }
                        SecurityLevel::MIC64 | SecurityLevel::ENCMIC64 => {}
                        SecurityLevel::MIC128 | SecurityLevel::ENCMIC128 => {}
                        #[allow(unreachable_patterns)]
                        _ => {}
                    };
                }
                None => return Err(SecurityError::UnavailableDevice),
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

/// Errors that can occur while performing security operations on frames
#[derive(Debug, Copy, Clone)]
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
    WriteError(byte::Error),
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
            SecurityError::WriteError(e) => e,
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
    extern crate aes_soft;
    extern crate ccm;
    use crate::mac::frame::header::*;
    use crate::mac::frame::security::{security_control::*, *};
    use crate::mac::frame::*;
    use crate::mac::{frame::frame_control::*, FooterMode};
    use aes_soft::Aes128;
    use cipher::generic_array::typenum::Unsigned;

    struct StaticKeyLookup();

    impl KeyLookup<U16> for StaticKeyLookup {
        fn lookup_key(
            &self,
            _address_mode: AddressingMode,
            _key_identifier: Option<KeyIdentifier>,
            _device_address: Option<Address>,
        ) -> Option<GenericArray<u8, U16>> {
            let mut key = GenericArray::default();
            key[0] = 0x01;
            key[2] = 0x02;
            key[3] = 0x03;
            for i in 0..U16::to_usize() {
                key[i] = 0x00;
            }
            Some(key)
        }
    }
    struct BasicDevDescriptorLookup {
        list: [DeviceDescriptor; 1],
    }

    impl BasicDevDescriptorLookup {
        pub fn new(desc: DeviceDescriptor) -> Self {
            Self { list: [desc] }
        }
    }

    impl DeviceDescriptorLookup for BasicDevDescriptorLookup {
        fn lookup_device(
            &mut self,
            _addressing_mode: AddressingMode,
            _address: Address,
        ) -> Option<&mut DeviceDescriptor> {
            Some(&mut self.list[0])
        }
    }

    const STATIC_KEY_LOOKUP: StaticKeyLookup = StaticKeyLookup();

    fn c8p1305_sec_ctx<'a>(frame_counter: u32) -> SecurityContext<'a, Aes128, StaticKeyLookup> {
        SecurityContext {
            frame_counter,
            key_provider: &STATIC_KEY_LOOKUP,
            phantom_data: PhantomData,
        }
    }

    fn get_frame<'a>(
        security: bool,
        payload: &'a [u8],
        auxiliary_security_header: Option<AuxiliarySecurityHeader>,
        send: bool,
    ) -> Frame<'a> {
        let mut destination = Some(Address::Extended(
            PanId(255),
            ExtendedAddress(0xFFAAFFAAFFAAu64),
        ));
        let mut source = Some(Address::Extended(
            PanId(511),
            ExtendedAddress(0xAAFFAAFFAAFFu64),
        ));
        if send {
            let backup = source.clone();
            source = destination;
            destination = backup;
        }

        Frame {
            header: Header {
                frame_type: FrameType::Data,
                security,
                frame_pending: false,
                ack_request: false,
                pan_id_compress: false,
                version: FrameVersion::Ieee802154,
                seq: 127,
                destination,
                source,
                auxiliary_security_header: auxiliary_security_header,
            },
            content: FrameContent::Data,
            payload,
            footer: [0x00, 0x00],
        }
    }

    #[test]
    fn encode_unsecured() {
        let frame = get_frame(false, &[0xAA, 0xBB, 0xCC, 0xDD, 0xFE, 0xDE], None, true);

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
                security_level: SecurityLevel::MIC32,
                key_id_mode: KeyIdentifierMode::None,
            },
            frame_counter: 1337,
            key_identifier: Some(KeyIdentifier {
                key_source: None,
                key_index: 0,
            }),
        });
        let aux_sec_len = aux_sec_header.unwrap().get_octet_size() as usize;

        let plaintext_payload = &mut [0xFF, 0x00, 0xFF, 0x00, 0xFF, 0x00];
        let plaintext_len = plaintext_payload.len();

        let frame = get_frame(true, plaintext_payload, aux_sec_header, true);

        let mut storage = [0u8; 32];

        let buf = &mut storage[..aux_sec_len + plaintext_len + 5];

        let mut sec_ctx = c8p1305_sec_ctx(1000);
        let offset = &mut 0;
        let write_res = security::secure_frame(frame, &mut sec_ctx, offset, buf);

        match write_res {
            Err(e) => {
                assert!(false, "Failed to secure frame {:?}!", e);
            }
            _ => {}
        }

        let mut frame = get_frame(true, &[], aux_sec_header, false);

        let device_desc = DeviceDescriptor {
            address: Address::Extended(PanId(511), ExtendedAddress(0xAAFFAAFFAAFFu64)),
            frame_counter: 999,
            exempt: false,
        };

        let offset = &mut (aux_sec_len + 1);

        let read_res = security::unsecure_frame(
            &mut frame,
            offset,
            buf,
            &mut sec_ctx,
            FooterMode::None,
            &mut BasicDevDescriptorLookup::new(device_desc),
        );

        match read_res {
            Err(e) => match e {
                SecurityError::WriteError(err) => {
                    assert!(
                        false,
                        "Write error occured while unsecuring frame. {:?}",
                        err
                    );
                }
                _ => assert!(false, "Failed to unsecure frame {:?}! ", e),
            },
            _ => {}
        }

        assert_eq!(frame.payload, *plaintext_payload);
    }
}
