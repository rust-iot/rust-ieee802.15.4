//! All of the fields and their contents that are used in the
//! Auxiliary Security header can be found in this module.
//!
//! All of the below data structures are defined in section 7.4 of the 802.15.4-2011 standard

use core::marker::PhantomData;

use aead::{
    generic_array::{ArrayLength, GenericArray},
    AeadCore, AeadInPlace, NewAead, Tag,
};
use byte::{check_len, BytesExt, TryRead, LE};

use crate::mac::{Address, FrameType};

use super::{
    security_control::{KeyIdentifierMode, SecurityControl, SecurityLevel},
    Frame,
};

pub mod mock;

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
            + match self.control.key_id_mode {
                KeyIdentifierMode::None => 0,
                KeyIdentifierMode::KeyIndex => 1,
                KeyIdentifierMode::KeySource4 => 5,
                KeyIdentifierMode::KeySource8 => 9,
            };
        length
    }
}

impl TryRead<'_> for AuxiliarySecurityHeader {
    fn try_read(bytes: &[u8], _ctx: ()) -> byte::Result<(Self, usize)> {
        let offset = &mut 0;
        check_len(bytes, 1)?;

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

/// A key identifier
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct KeyIdentifier {
    /// The key source to be used for determining a key from this key identifier (if any)
    pub key_source: Option<KeySource>,
    /// The key index to use for determining a key from this key identifier
    pub key_index: u8,
}

/// A key source
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum KeySource {
    /// A key source that is 4 octets long
    Short(u32),
    /// A key source that is 8 octets long
    Long(u64),
}

/// The addressing mode to use during key descriptor lookups
pub enum KeyAddressMode {
    /// Destination addressing mode
    DstAddrMode,
    /// Source addressing mode
    SrcAddrMode,
}

/// A key descriptor
pub struct KeyDescriptor {
    /// The key contained by this key descriptor
    pub key: [u8; 16],
}

/// Used to create a KeyDescriptor from a KeyIdentifier and device address
pub trait KeyDescriptorLookup {
    /// Look up a key from a key identifier and a device address
    ///
    /// This function should return None if the key lookup fails (i.e. a failed status),
    /// and some if the lookup succeeds, where the Option contains the KeyDescriptor that was
    /// found according to the passed in parameters
    fn lookup_key(
        &self,
        address_mode: KeyAddressMode,
        key_identifier: Option<KeyIdentifier>,
        device_address: Option<Address>,
    ) -> Option<KeyDescriptor>;
}

/// Generates a nonce from the 13-byte nonce that the standard provides.
/// The generated nonce must be deterministic
pub trait NonceGenerator<N>
where
    N: ArrayLength<u8>,
{
    /// Generate an N-length nonce from the 13 byte nonce generated using the method provided
    /// by the 802.15.4 standard
    fn generate_nonce(input_nonce: [u8; 13], destination: &mut GenericArray<u8, N>);
}

/// A context that used to keep track of cryptographic properties that
/// are necessary for securing/unsecuring frames
///
/// AEAD is the type that will provide an AEAD instance to be used for the
/// encryption/decryption process
///
/// NONCEGEN is the type that will convert the nonce created using the 802.15.4 standard
/// into a nonce of the size that can be accepted by the provided AEAD algorithm
pub struct SecurityContext<'a, AEAD, KEYDESCLO, NONCEGEN>
where
    AEAD: NewAead + AeadInPlace,
    KEYDESCLO: KeyDescriptorLookup,
    NONCEGEN: NonceGenerator<AEAD::NonceSize>,
{
    /// The current frame counter
    pub frame_counter: u32,
    /// The key descriptor lookup to use to look up keys
    pub key_provider: &'a KEYDESCLO,
    /// This is phantom data as we use AEAD to actually instantiate an instance
    /// of AEAD, as opposed to actually using a provided AEAD instance somewhere
    ///
    /// The NONCEGEN is phantom data as well
    phanom_data: PhantomData<(AEAD, NONCEGEN)>,
}

/// Appends the payload of a [Frame] to the provided buffer, secured according to the security settings specified in
/// the [Frame]'s [`super::Header`] and [AuxiliarySecurityHeader].
///
/// Offset is updated with the amount of bytes that is written
///
/// Currently only supports the securing of Data frames with extended addresses
///
/// # Panics
/// If the security field in the frame's [`super::Header`] is true in the frame's header, but no [AuxiliarySecurityHeader] is present.
///
/// If security is false in the [`super::Header`] header, but an [AuxiliarySecurityHeader] is present.
///
/// If an unsupported frame type is used (i.e. anything that doesn't have an extended [Address] and the Data [FrameType])
///
/// If the provided security context is None, while security is enabled on the frame
pub fn write_payload<'a, AEAD, KEYDESCLO, NONCEGEN>(
    frame: Frame<'_>,
    context: Option<&mut SecurityContext<AEAD, KEYDESCLO, NONCEGEN>>,
    offset: &mut usize,
    buffer: &mut [u8],
) -> Result<(), SecurityError>
where
    AEAD: NewAead + AeadInPlace,
    KEYDESCLO: KeyDescriptorLookup,
    NONCEGEN: NonceGenerator<AEAD::NonceSize>,
{
    let header = frame.header;

    if header.security {
        let context = match context {
            Some(context) => context,
            None => panic!("Missing security context"),
        };
        let frame_counter = &mut context.frame_counter;
        let source = match header.source {
            Some(addr) => addr,
            // Maybe this should panic instead
            _ => return Err(SecurityError::NoSourceAddress),
        };

        match header.frame_type {
            FrameType::Data => {}
            _ => {
                unimplemented!()
            }
        }
        // Procedure 7.2.1
        if let Some(aux_sec_header) = header.auxiliary_security_header {
            let auth_len = aux_sec_header.control.security_level.get_mic_octet_count();
            let aux_len = aux_sec_header.get_octet_size();

            // If AuthLen plus AuxLen plus FCS is bigger than aMaxPHYPacketSize
            // 7.2.1 b4
            if auth_len + aux_len + 2 > 127 {
                return Err(SecurityError::FrameTooLong);
            }

            if aux_sec_header.control.security_level == SecurityLevel::None {}

            if *frame_counter == 0xFFFFFFFF {
                return Err(SecurityError::CounterError);
            }

            if let Some(key) = context.key_provider.lookup_key(
                KeyAddressMode::DstAddrMode,
                aux_sec_header.key_identifier,
                header.destination,
            ) {
                let mut input_nonce = [0u8; 13];

                match source {
                    Address::Short(_, _) => {
                        unimplemented!();
                    }
                    Address::Extended(_, addr) => {
                        for i in 0..7 {
                            input_nonce[i] = (addr.0 >> (8 * i) & 0xFF) as u8;
                        }
                    }
                };

                if let Err(_) = buffer.write(offset, frame.payload) {
                    return Err(SecurityError::WriteError);
                }

                let mut nonce = GenericArray::default();
                NONCEGEN::generate_nonce(input_nonce, &mut nonce);

                let aead_in_place = match AEAD::new_from_slice(&key.key) {
                    Ok(key) => key,
                    Err(_) => return Err(SecurityError::KeyFailure)?,
                };

                let tag = match aux_sec_header.control.security_level {
                    SecurityLevel::None => None,
                    SecurityLevel::MIC32 | SecurityLevel::MIC64 | SecurityLevel::MIC128 => {
                        Some(aead_in_place.encrypt_in_place_detached(&nonce, buffer, &mut []))
                    }
                    SecurityLevel::ENC
                    | SecurityLevel::ENCMIC32
                    | SecurityLevel::ENCMIC64
                    | SecurityLevel::ENCMIC128 => {
                        Some(aead_in_place.encrypt_in_place_detached(&nonce, &mut [], buffer))
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
            panic!("Security on but AuxSecHeader absent")
        }
    } else {
        // Not a fan of the fact that we can't pass some actually
        // useful information to the layer above this, only byte::Result
        if header.auxiliary_security_header.is_some() {
            panic!("Security off but AuxSecHeader present")
        } else {
            return Err(SecurityError::SecurityNotEnabled);
        }
    }
}

fn get_truncated_mic<AEAD, LEN>(input_tag: &Tag<AEAD>) -> GenericArray<u8, LEN>
where
    AEAD: AeadCore,
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
    /// The frame to be secured has no source address specified. The source
    /// address is necessary to calculate the nonce, in some cases
    NoSourceAddress,
    /// The security (CCM*) transformation could not be completed successfully
    TransformationError,
    /// Something went wrong while writing the frame's payload bytes to the buffer
    WriteError,
    /// Something went wrong while writing a frame's tag to the buffer
    TagWriteError,
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
        }
    }
}
