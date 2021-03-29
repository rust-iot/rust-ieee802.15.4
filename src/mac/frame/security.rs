//! All of the fields and their contents that are used in the
//! Auxiliary Security header can be found in this module.
//!
//! All of the below data structures are defined in section 7.4 of the 802.15.4-2011 standard

use core::marker::PhantomData;

use aead::{AeadInPlace, NewAead, consts::U13, generic_array::ArrayLength};
use byte::{check_len, BytesExt, TryRead, LE};

use crate::mac::Address;

use super::security_control::{KeyIdentifierMode, SecurityControl};

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

/// Errors that can occur while securing or unsecuring a frame
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum SecurityError {
    /// The frame is too long after appending all security data
    FrameTooLong,
    /// The counter used for securing a frame is invalid (0xFFFFFFFF)
    CounterError,
    /// No key could be found for the provided context
    UnavailableKey,
    /// The key could not be used in an adequate manner
    KeyFailure,
}

impl From<SecurityError> for byte::Error {
    fn from(e: SecurityError) -> Self {
        match e {
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
        }
    }
}

/// A trait that is used to create a KeyDescriptor from a KeyIdentifier and device address
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


/// A context that used to keep track of cryptographic properties that
/// are necessary for securing/unsecuring frames
///
/// AEAD is the type that will provide an AEAD instance to be used for the
/// encryption/decryption process
pub struct SecurityContext<'a, AEAD, KEYDESCLO>
where
    AEAD: NewAead + AeadInPlace,
    KEYDESCLO: KeyDescriptorLookup,
    AEAD::NonceSize: ArrayLength<U13>,
{
    /// The current frame counter
    pub frame_counter: u32,
    /// The key descriptor lookup to use to look up keys
    pub key_provider: &'a KEYDESCLO,
    /// This is phantom data as we use AEAD to actually instantiate an instance
    /// of AEAD, as opposed to actually using a provided AEAD instance somewhere
    phanom_data: PhantomData<AEAD>,
}
