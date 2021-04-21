//! All auxiliary security header structs and functions

use super::{KeyDescriptorLookup, KeyIdentifierMode, SecurityContext, SecurityControl};
use byte::{BytesExt, TryRead, TryWrite, LE};
use cipher::{consts::U16, BlockCipher, NewBlockCipher};

/// A struct describing the Auxiliary Security Header
///
/// See: section 7.4
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct AuxiliarySecurityHeader {
    /// The control field in the Auxiliary Security Header
    pub control: SecurityControl,
    /// The frame counter. This is automatically determined when running [`super::unsecure_frame`] and/or [`super::secure_frame`]
    pub(crate) frame_counter: u32,
    /// If the key_identifier field in [`AuxiliarySecurityHeader::control`] is not set to None, this field contains the key identifier
    /// of this frame, otherwise it is None
    pub key_identifier: Option<KeyIdentifier>,
}

impl AuxiliarySecurityHeader {
    /// Get the size of this security header, in octets
    pub fn get_octet_size(&self) -> usize {
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

    /// Create a new Auxiliary Security Header with the specified control and key identifier
    pub fn new(control: SecurityControl, key_identifier: Option<KeyIdentifier>) -> Self {
        Self {
            control,
            key_identifier,
            frame_counter: 0,
        }
    }

    /// Create a new Auxiliary Security Header with the specified control, key identifier, and frame counter.
    ///
    /// This function is unsafe because the frame_counter is almost always set when parsing a frame from a buffer,
    /// or by the security context at the time of actually writing a secured frame.
    pub unsafe fn new_unsafe(
        control: SecurityControl,
        key_identifier: Option<KeyIdentifier>,
        frame_counter: u32,
    ) -> Self {
        Self {
            control,
            key_identifier,
            frame_counter,
        }
    }

    /// Get the frame counter of this auxiliary security header.
    ///
    /// This will be 0 on a non-parsed Auxiliary Security Header
    pub fn get_frame_counter(&self) -> u32 {
        self.frame_counter
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

impl<AEADBLKCIPH, KEYDESCLO> TryWrite<&SecurityContext<AEADBLKCIPH, KEYDESCLO>>
    for AuxiliarySecurityHeader
where
    AEADBLKCIPH: NewBlockCipher + BlockCipher<BlockSize = U16>,
    KEYDESCLO: KeyDescriptorLookup<AEADBLKCIPH::KeySize>,
{
    fn try_write(
        mut self,
        bytes: &mut [u8],
        sec_ctx: &SecurityContext<AEADBLKCIPH, KEYDESCLO>,
    ) -> byte::Result<usize> {
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
        bytes.write(offset, sec_ctx.frame_counter)?;
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
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
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
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum KeySource {
    /// A key source that is 4 octets long
    Short(u32),
    /// A key source that is 8 octets long
    Long(u64),
}
