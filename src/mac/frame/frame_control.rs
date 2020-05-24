//! This module contains definition of Frame Control field that is defined int 5.2.1.1 section.
use super::DecodeError;

/// Defines the type of a MAC frame
///
/// Part of [`Header`].
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
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum AddressMode {
    /// PAN identifier and address field are not present
    None = 0b00,
    /// Address field contains a 16 bit short address
    Short = 0b10,
    /// Address field contains a 64 bit extended address
    Extended = 0b11,
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
    ///
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

    pub(crate) fn as_u8(self) -> u8 {
        match self {
            Self::None => 0,
            Self::Short => 0b10,
            Self::Extended => 0b11,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
/// Frame Control begin of MAC header
pub struct FrameControl {
    /// Frame Type
    pub frame_type: FrameType,

    /// Auxiliary Security header
    pub security: bool,

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

    /// Destination address mode
    pub dest_addr_mode: AddressMode,

    /// Frame version
    pub version: FrameVersion,

    /// Source address mode
    pub src_addr_mode: AddressMode,
}

mod offset {
    pub const frame_type: u16 = 0;
    pub const security: u16 = 3;
    pub const pending: u16 = 4;
    pub const ack: u16 = 5;
    pub const pan_id_compress: u16 = 6;
    pub const dest_addr_mode: u16 = 10;
    pub const version: u16 = 12;
    pub const src_addr_mode: u16 = 14u16;
}

mod mask {
    pub const frame_type: u16 = 0x0007;
    pub const security: u16 = 0x0008;
    pub const pending: u16 = 0x0010;
    pub const ack: u16 = 0x0020;
    pub const pan_id_compress: u16 = 0x0040;
    pub const dest_addr_mode: u16 = 0x0C00;
    pub const version: u16 = 0x3000;
    pub const src_addr_mode: u16 = 0xC000;
}

impl FrameControl {
    /// Try converrt from bits into FrameControl
    pub fn try_from_bits(bits: u16) -> Result<Self, DecodeError> {
        /* Parse raw data */
        let frame_type = ((bits & mask::frame_type) >> offset::frame_type) as u8;
        let security = ((bits & mask::security) >> offset::security) as u8;

        let frame_pending = ((bits & mask::pending) >> offset::pending) as u8;
        let ack_request = ((bits & mask::ack) >> offset::ack) as u8;
        let pan_id_compress = ((bits & mask::pan_id_compress) >> offset::pan_id_compress) as u8;

        let dest_addr_mode = ((bits & mask::dest_addr_mode) >> offset::dest_addr_mode) as u8;
        let version = ((bits & mask::version) >> offset::version) as u8;
        let src_addr_mode = ((bits & mask::src_addr_mode) >> offset::src_addr_mode) as u8;

        /* Make rust struct */
        let version =
            FrameVersion::from_bits(version).ok_or(DecodeError::InvalidFrameVersion(version))?;
        let frame_type =
            FrameType::from_bits(frame_type).ok_or(DecodeError::InvalidFrameType(frame_type))?;
        let dest_addr_mode = AddressMode::from_bits(dest_addr_mode)?;
        let src_addr_mode = AddressMode::from_bits(src_addr_mode)?;
        // make bool values
        let security = security > 0;
        let frame_pending = frame_pending > 0;
        let ack_request = ack_request > 0;
        let pan_id_compress = pan_id_compress > 0;

        Ok(Self {
            frame_type,
            security,
            frame_pending,
            ack_request,
            pan_id_compress,
            dest_addr_mode,
            version,
            src_addr_mode,
        })
    }

    /// Convert Frame Control into bits.
    pub fn to_bits(&self) -> u16 {
        let frame_control = (self.frame_type as u16) << offset::frame_type
            | (self.security as u16) << offset::security
            | (self.frame_pending as u16) << offset::pending
            | (self.ack_request as u16) << offset::ack
            | (self.pan_id_compress as u16) << offset::pan_id_compress
            | (self.dest_addr_mode as u16) << offset::dest_addr_mode
            | (self.version as u16) << offset::version
            | (self.src_addr_mode as u16) << offset::src_addr_mode;

        frame_control
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Buf;

    #[test]
    fn frame_control_from_bits() {
        let mut fctl_bytes = &[0x00, 0x10][..];
        let fctl = FrameControl::try_from_bits(fctl_bytes.get_u16_le()).expect("correct bytes");
        assert_eq!(fctl.frame_type, FrameType::Beacon);
        assert_eq!(fctl.version, FrameVersion::Ieee802154_2006);
        assert_eq!(fctl.security, false);
        assert_eq!(fctl.frame_pending, false);
        assert_eq!(fctl.ack_request, false);
        assert_eq!(fctl.pan_id_compress, false);
        assert_eq!(fctl.src_addr_mode, AddressMode::None);
        assert_eq!(fctl.dest_addr_mode, AddressMode::None);
    }
}
