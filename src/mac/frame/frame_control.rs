//! This module contains definition of Frame Control field that is defined int 5.2.1.1 section.
use super::header::Address;
use super::DecodeError;

/// Defines the type of a MAC frame
///
/// Part of [`Header`].
///
/// [`Header`]: super::header::Header
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum FrameType {
    /// Beacon
    Beacon = 0b000,

    /// Data
    Data = 0b001,

    /// Acknowledgement
    Acknowledgement = 0b010,

    /// MAC command
    MacCommand = 0b011,
}

impl FrameType {
    /// Creates an instance of [`FrameType`] from the provided bits
    ///
    /// Returns `None`, if the provided bits don't encode a valid frame type.
    ///
    /// # Example
    ///
    /// ``` rust
    /// use ieee802154::mac::FrameType;
    ///
    /// let frame_type = FrameType::from_bits(0b001);
    /// assert_eq!(frame_type, Some(FrameType::Data));
    /// ```
    pub fn from_bits(bits: u8) -> Option<Self> {
        match bits {
            0b000 => Some(FrameType::Beacon),
            0b001 => Some(FrameType::Data),
            0b010 => Some(FrameType::Acknowledgement),
            0b011 => Some(FrameType::MacCommand),
            _ => None,
        }
    }
}

/// Defines version information for a frame
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum FrameVersion {
    /// A frame conforming to the 802.15.4-2003 standard
    Ieee802154_2003 = 0b00,
    /// A frame conforming to the 802.15.4-2006 standard
    Ieee802154_2006 = 0b01,
    /// A frame conforming to the current 802.15.4 standard
    Ieee802154 = 0b10,
}

impl FrameVersion {
    /// Creates an instance of [`FrameVersion`] from the provided bits
    ///
    /// Returns `None`, if the provided bits don't encode a valid value of
    /// `FrameVersion`.
    ///
    /// # Example
    ///
    /// ``` rust
    /// use ieee802154::mac::FrameVersion;
    ///
    /// let version = FrameVersion::from_bits(0b0);
    /// assert_eq!(version, Some(FrameVersion::Ieee802154_2003));
    /// ```
    pub fn from_bits(bits: u8) -> Option<Self> {
        match bits {
            0b00 => Some(FrameVersion::Ieee802154_2003),
            0b01 => Some(FrameVersion::Ieee802154_2006),
            0b10 => Some(FrameVersion::Ieee802154),
            _ => None,
        }
    }
}

/// Defines the type of Address
///
/// # Example
/// ```rust
/// use ieee802154::mac::{Address, AddressMode, PanId, ShortAddress};
///
/// let example_addr = Some(Address::Short(PanId(0x3412), ShortAddress(0x7856)));
/// let address_mode = AddressMode::from(example_addr);
/// assert_eq!(address_mode, AddressMode::Short);
/// ```
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum AddressMode {
    /// PAN identifier and address field are not present
    None = 0b00,
    /// Address field contains a 16 bit short address
    Short = 0b10,
    /// Address field contains a 64 bit extended address
    Extended = 0b11,
}

impl From<Option<Address>> for AddressMode {
    fn from(opt_addr: Option<Address>) -> Self {
        match opt_addr {
            Some(Address::Short(..)) => Self::Short,
            Some(Address::Extended(..)) => Self::Extended,
            None => Self::None,
        }
    }
}

impl From<Address> for AddressMode {
    fn from(addr: Address) -> Self {
        match addr {
            Address::Short(_, _) => Self::Short,
            Address::Extended(_, _) => Self::Extended,
        }
    }
}

impl AddressMode {
    /// Creates an instance of [`AddressMode`] from the provided bits
    ///
    /// Returns `None`, if the provided bits don't encode a valid value of
    /// `AddressMode`.
    ///
    /// # Example
    ///
    /// ``` rust
    /// use ieee802154::mac::AddressMode;
    /// // decode
    /// let address_mode = AddressMode::from_bits(0b10).unwrap();
    /// assert_eq!(address_mode, AddressMode::Short);
    /// ```
    pub fn from_bits(bits: u8) -> Result<Self, DecodeError> {
        match bits {
            0b00 => Ok(AddressMode::None),
            0b10 => Ok(AddressMode::Short),
            0b11 => Ok(AddressMode::Extended),
            _ => Err(DecodeError::InvalidAddressMode(bits)),
        }
    }
}

pub mod offset {
    pub const FRAME_TYPE: u16 = 0;
    pub const SECURITY: u16 = 3;
    pub const PENDING: u16 = 4;
    pub const ACK: u16 = 5;
    pub const PAN_ID_COMPRESS: u16 = 6;
    pub const DEST_ADDR_MODE: u16 = 10;
    pub const VERSION: u16 = 12;
    pub const SRC_ADDR_MODE: u16 = 14u16;
}

pub mod mask {
    pub const FRAME_TYPE: u16 = 0x0007;
    pub const SECURITY: u16 = 0x0008;
    pub const PENDING: u16 = 0x0010;
    pub const ACK: u16 = 0x0020;
    pub const PAN_ID_COMPRESS: u16 = 0x0040;
    pub const DEST_ADDR_MODE: u16 = 0x0C00;
    pub const VERSION: u16 = 0x3000;
    pub const SRC_ADDR_MODE: u16 = 0xC000;
}
