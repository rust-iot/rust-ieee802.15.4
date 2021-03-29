//! The security control header is described here

use byte::{BytesExt, TryRead, LE};

use super::DecodeError;

/// The Security Control header
///
/// Contains fields describing the security applied to the incoming frame
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct SecurityControl {
    /// The security level applied to the incoming frame
    pub security_level: SecurityLevel,
    /// The mode used to identify the key used to secure the incoming frame
    pub key_id_mode: KeyIdentifierMode,
    // The below fields are present only in the 802.15.4-2020 version of the standard
    /*
    /// Whether or not the frame counter is present in the auxiliary security header
    pub frame_counter_suppression: bool,
    /// Whether the ASN is present in the nonce supplied
    pub asn_in_nonce: bool,
     */
}

impl TryRead<'_> for SecurityControl {
    fn try_read(bytes: &[u8], _ctx: ()) -> byte::Result<(Self, usize)> {
        let offset = &mut 0;
        let bits: u8 = bytes.read_with(offset, LE)?;

        let security_level = (bits & mask::SECURITY_LEVEL) >> offset::SECURITY_LEVEL;
        let key_id_mode = (bits & mask::KEY_IDENTIFIER_MODE) >> offset::KEY_IDENTIFIER_MODE;

        let security_level = SecurityLevel::from_bits(security_level)
            .ok_or(DecodeError::InvalidSecurityLevel(security_level))?;
        let key_id_mode = KeyIdentifierMode::from_bits(key_id_mode)
            .ok_or(DecodeError::InvalidKeyIdentifierMode(key_id_mode))?;

        let control = SecurityControl {
            security_level,
            key_id_mode,
        };

        Ok((control, *offset))
    }
}

/// The level of security applied to the payload
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum SecurityLevel {
    /// No encryption and no data authentication
    None = 0b000,
    /// No encryption and a 32 bit value to verify data authenticity
    MIC32 = 0b001,
    /// No encryption and a 64 bit value to verify data authenticity
    MIC64 = 0b010,
    /// No encryption and a 128 bit value to verify data authenticity
    MIC128 = 0b011,
    /// Encryption and no data authentication
    ENC = 0b100,
    /// Encryption and a 32 bit value to verify data authenticity
    ENCMIC32 = 0b101,
    /// Encryption and a 64 bit value to verify data authenticity
    ENCMIC64 = 0b110,
    /// Encryption and a 128 bit value to verify data authenticity
    ENCMIC128 = 0b111,
}

impl SecurityLevel {
    fn from_bits(bits: u8) -> Option<Self> {
        match bits {
            0b000 => Some(SecurityLevel::None),
            0b001 => Some(SecurityLevel::MIC32),
            0b010 => Some(SecurityLevel::MIC64),
            0b011 => Some(SecurityLevel::MIC128),
            0b100 => Some(SecurityLevel::ENC),
            0b101 => Some(SecurityLevel::ENCMIC32),
            0b110 => Some(SecurityLevel::ENCMIC64),
            0b111 => Some(SecurityLevel::ENCMIC128),
            _ => None,
        }
    }
}

/// The key identifier mode
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum KeyIdentifierMode {
    /// No key identifier
    None = 0b00,
    /// A key index is present
    KeyIndex = 0b01,
    /// A key source of 4 octets and key index are present
    KeySource4 = 0b10,
    /// A key source of 8 octets and key index are present
    KeySource8 = 0b11,
}

impl KeyIdentifierMode {
    fn from_bits(bits: u8) -> Option<Self> {
        match bits {
            0b00 => Some(KeyIdentifierMode::None),
            0b01 => Some(KeyIdentifierMode::KeyIndex),
            0b10 => Some(KeyIdentifierMode::KeySource4),
            0b11 => Some(KeyIdentifierMode::KeySource8),
            _ => None,
        }
    }
}

mod mask {
    pub const SECURITY_LEVEL: u8 = 0x07;
    pub const KEY_IDENTIFIER_MODE: u8 = 0x18;

    // The below fields are present only in the 802.15.4-2020 version of the standard
    /*
    pub const FRAME_COUNTER_SUPPRESSION: u8 = 0x20;
    pub const ASN_IN_NONCE: u8 = 0x40;
    */
}

mod offset {
    pub const SECURITY_LEVEL: u8 = 0;
    pub const KEY_IDENTIFIER_MODE: u8 = 2;

    // The below fields are present only in the 802.15.4-2020 version of the standard
    /*
    pub const FRAME_COUNTER_SUPPRESSION: u8 = 4;
    pub const ASN_IN_NONCE: u8 = 5;
    */
}
