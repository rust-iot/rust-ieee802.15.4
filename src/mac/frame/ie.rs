//! Information Elements (IEEE 802.15.4-2020, section 7.4)
//!
//! Frames with the IE Present field set carry Header IEs after the MHR's
//! addressing fields, and Payload IEs at the start of the MAC payload. A
//! [`Frame`] keeps both lists as [`InformationElements`], without their
//! termination IEs; iterate them with [`InformationElements::header`] and
//! [`InformationElements::payload`], and the nested IEs of an MLME IE with
//! [`NestedIes`].
//!
//! [`Frame`]: super::Frame

use byte::{check_len, BytesExt, TryRead, TryWrite, LE};

/// Header IE element IDs (Table 7-7) this crate gives a name.
pub mod header_id {
    /// Header Termination 1: Payload IEs follow.
    pub const TERMINATION_1: u8 = 0x7e;
    /// Header Termination 2: the MAC payload follows, without Payload IEs.
    pub const TERMINATION_2: u8 = 0x7f;
}

/// Payload IE group IDs (Table 7-17) this crate gives a name.
pub mod group_id {
    /// Encapsulated Service Data Unit IE.
    pub const ESDU: u8 = 0x0;
    /// MLME IE, holding nested IEs.
    pub const MLME: u8 = 0x1;
    /// Vendor Specific Payload IE.
    pub const VENDOR_SPECIFIC: u8 = 0x2;
    /// Payload Termination IE: the MAC payload follows.
    pub const TERMINATION: u8 = 0xf;
}

/// Nested IE sub-IDs (Tables 7-18 and 7-19) this crate gives a name.
pub mod sub_id {
    /// SUN Device Capabilities IE (short): [`super::SunDeviceCapabilities`].
    pub const SUN_DEVICE_CAPABILITIES: u8 = 0x22;
    /// Vendor Specific Nested IE (long): [`super::VendorSpecific`].
    pub const VENDOR_SPECIFIC: u8 = 0x08;
}

/// The Header IEs and Payload IEs of a frame, as encoded, each list without
/// its termination IE
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct InformationElements<'a> {
    header: &'a [u8],
    payload: &'a [u8],
}

impl<'a> InformationElements<'a> {
    /// No IEs
    pub const EMPTY: Self = Self {
        header: &[],
        payload: &[],
    };

    /// IEs from encoded lists of Header IEs and Payload IEs, without
    /// termination IEs: written with [`HeaderIe`] and [`PayloadIe`]
    pub const fn new(header: &'a [u8], payload: &'a [u8]) -> Self {
        Self { header, payload }
    }

    /// Whether there are no IEs
    pub fn is_empty(&self) -> bool {
        self.header.is_empty() && self.payload.is_empty()
    }

    /// The Header IEs
    pub fn header(&self) -> HeaderIes<'a> {
        HeaderIes(self.header)
    }

    /// The Payload IEs
    pub fn payload(&self) -> PayloadIes<'a> {
        PayloadIes(self.payload)
    }

    /// The encoded Header IEs
    pub fn header_bytes(&self) -> &'a [u8] {
        self.header
    }

    /// The encoded Payload IEs
    pub fn payload_bytes(&self) -> &'a [u8] {
        self.payload
    }
}

/// Where the IEs of a frame end (section 7.4.1)
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Ending {
    /// At the end of the frame
    End,
    /// At a Header Termination 1 IE: Payload IEs follow
    PayloadIes,
    /// At a Header Termination 2 or Payload Termination IE: the MAC payload
    /// follows
    Payload,
}

impl<'a> InformationElements<'a> {
    /// Reads the IEs at the start of `bytes`, and their termination IEs,
    /// returning the IEs and the octets read
    pub(crate) fn read(bytes: &'a [u8]) -> byte::Result<(Self, usize)> {
        let offset = &mut 0;
        let (header, ending) = read_list(bytes, offset, false)?;
        let payload = if ending == Ending::PayloadIes {
            read_list(bytes, offset, true)?.0
        } else {
            &[]
        };
        Ok((Self { header, payload }, *offset))
    }

    /// Writes the IEs and the termination IEs a frame needs: Header
    /// Termination 1 before Payload IEs, and, when a MAC payload `follows`,
    /// Header Termination 2 or Payload Termination
    pub(crate) fn write(
        &self,
        bytes: &mut [u8],
        follows: bool,
    ) -> byte::Result<usize> {
        let offset = &mut 0;
        bytes.write(offset, self.header)?;
        if !self.payload.is_empty() {
            bytes
                .write(offset, HeaderIe::new(header_id::TERMINATION_1, &[]))?;
            bytes.write(offset, self.payload)?;
            if follows {
                bytes.write(
                    offset,
                    PayloadIe::new(group_id::TERMINATION, &[]),
                )?;
            }
        } else if !self.header.is_empty() && follows {
            bytes
                .write(offset, HeaderIe::new(header_id::TERMINATION_2, &[]))?;
        }
        Ok(*offset)
    }
}

/// Reads a list of Header IEs (or of Payload IEs) up to its termination IE or
/// the end of `bytes`, returning the list without the termination
fn read_list<'a>(
    bytes: &'a [u8],
    offset: &mut usize,
    payload: bool,
) -> byte::Result<(&'a [u8], Ending)> {
    let start = *offset;
    while *offset < bytes.len() {
        let at = *offset;
        let ending = if payload {
            let ie: PayloadIe<'_> = bytes.read(offset)?;
            (ie.group_id == group_id::TERMINATION).then_some(Ending::Payload)
        } else {
            let ie: HeaderIe<'_> = bytes.read(offset)?;
            match ie.id {
                header_id::TERMINATION_1 => Some(Ending::PayloadIes),
                header_id::TERMINATION_2 => Some(Ending::Payload),
                _ => None,
            }
        };
        if let Some(ending) = ending {
            return Ok((&bytes[start..at], ending));
        }
    }
    Ok((&bytes[start..], Ending::End))
}

/// A Header IE (section 7.4.2): Length (7 bits), Element ID (8 bits), and
/// Type 0
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct HeaderIe<'a> {
    /// The Element ID (Table 7-7)
    pub id: u8,
    /// The Content field, at most 127 octets
    pub content: &'a [u8],
}

impl<'a> HeaderIe<'a> {
    /// A Header IE
    pub const fn new(id: u8, content: &'a [u8]) -> Self {
        Self { id, content }
    }
}

impl<'a> TryRead<'a> for HeaderIe<'a> {
    fn try_read(bytes: &'a [u8], _ctx: ()) -> byte::Result<(Self, usize)> {
        let offset = &mut 0;
        let d: u16 = bytes.read_with(offset, LE)?;
        if d & 0x8000 != 0 {
            return Err(byte::Error::BadInput {
                err: "not a Header IE",
            });
        }
        let len = usize::from(d & 0x7f);
        check_len(&bytes[*offset..], len)?;
        let content = &bytes[*offset..*offset + len];
        *offset += len;
        Ok((Self::new((d >> 7) as u8, content), *offset))
    }
}

impl TryWrite for HeaderIe<'_> {
    fn try_write(self, bytes: &mut [u8], _ctx: ()) -> byte::Result<usize> {
        if self.content.len() > 0x7f {
            return Err(byte::Error::BadInput {
                err: "Header IE content longer than 127 octets",
            });
        }
        let offset = &mut 0;
        let d = self.content.len() as u16 | u16::from(self.id) << 7;
        bytes.write_with(offset, d, LE)?;
        bytes.write(offset, self.content)?;
        Ok(*offset)
    }
}

/// A Payload IE (section 7.4.3): Length (11 bits), Group ID (4 bits), and
/// Type 1
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct PayloadIe<'a> {
    /// The Group ID (Table 7-17)
    pub group_id: u8,
    /// The Content field, at most 2047 octets
    pub content: &'a [u8],
}

impl<'a> PayloadIe<'a> {
    /// A Payload IE
    pub const fn new(group_id: u8, content: &'a [u8]) -> Self {
        Self { group_id, content }
    }

    /// The nested IEs of an MLME IE
    pub fn nested(&self) -> NestedIes<'a> {
        NestedIes(self.content)
    }
}

impl<'a> TryRead<'a> for PayloadIe<'a> {
    fn try_read(bytes: &'a [u8], _ctx: ()) -> byte::Result<(Self, usize)> {
        let offset = &mut 0;
        let d: u16 = bytes.read_with(offset, LE)?;
        if d & 0x8000 == 0 {
            return Err(byte::Error::BadInput {
                err: "not a Payload IE",
            });
        }
        let len = usize::from(d & 0x07ff);
        check_len(&bytes[*offset..], len)?;
        let content = &bytes[*offset..*offset + len];
        *offset += len;
        Ok((Self::new((d >> 11 & 0x0f) as u8, content), *offset))
    }
}

impl TryWrite for PayloadIe<'_> {
    fn try_write(self, bytes: &mut [u8], _ctx: ()) -> byte::Result<usize> {
        if self.content.len() > 0x07ff || self.group_id > 0x0f {
            return Err(byte::Error::BadInput {
                err: "Payload IE content or Group ID too large",
            });
        }
        let offset = &mut 0;
        let d =
            0x8000 | self.content.len() as u16 | u16::from(self.group_id) << 11;
        bytes.write_with(offset, d, LE)?;
        bytes.write(offset, self.content)?;
        Ok(*offset)
    }
}

/// A nested IE (section 7.4.4.1), in an MLME IE
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum NestedIe<'a> {
    /// Type short: Length (8 bits), Sub-ID (7 bits) and Type 0
    Short {
        /// The Sub-ID (Table 7-18)
        sub_id: u8,
        /// The Content field, at most 255 octets
        content: &'a [u8],
    },
    /// Type long: Length (11 bits), Sub-ID (4 bits) and Type 1
    Long {
        /// The Sub-ID (Table 7-19)
        sub_id: u8,
        /// The Content field, at most 2047 octets
        content: &'a [u8],
    },
}

impl<'a> NestedIe<'a> {
    /// The Content field
    pub fn content(&self) -> &'a [u8] {
        match *self {
            NestedIe::Short { content, .. }
            | NestedIe::Long { content, .. } => content,
        }
    }
}

impl<'a> TryRead<'a> for NestedIe<'a> {
    fn try_read(bytes: &'a [u8], _ctx: ()) -> byte::Result<(Self, usize)> {
        let offset = &mut 0;
        let d: u16 = bytes.read_with(offset, LE)?;
        let (len, ie) = if d & 0x8000 == 0 {
            (usize::from(d & 0xff), (d >> 8 & 0x7f) as u8)
        } else {
            (usize::from(d & 0x07ff), (d >> 11 & 0x0f) as u8)
        };
        check_len(&bytes[*offset..], len)?;
        let content = &bytes[*offset..*offset + len];
        *offset += len;
        let nested = if d & 0x8000 == 0 {
            NestedIe::Short {
                sub_id: ie,
                content,
            }
        } else {
            NestedIe::Long {
                sub_id: ie,
                content,
            }
        };
        Ok((nested, *offset))
    }
}

impl TryWrite for NestedIe<'_> {
    fn try_write(self, bytes: &mut [u8], _ctx: ()) -> byte::Result<usize> {
        let offset = &mut 0;
        let d = match self {
            NestedIe::Short { sub_id, content }
                if content.len() <= 0xff && sub_id <= 0x7f =>
            {
                content.len() as u16 | u16::from(sub_id) << 8
            }
            NestedIe::Long { sub_id, content }
                if content.len() <= 0x07ff && sub_id <= 0x0f =>
            {
                0x8000 | content.len() as u16 | u16::from(sub_id) << 11
            }
            _ => {
                return Err(byte::Error::BadInput {
                    err: "nested IE content or Sub-ID too large",
                })
            }
        };
        bytes.write_with(offset, d, LE)?;
        bytes.write(offset, self.content())?;
        Ok(*offset)
    }
}

macro_rules! ie_iterator {
    ($(#[$doc:meta])* $name:ident, $item:ident) => {
        $(#[$doc])*
        #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
        #[cfg_attr(feature = "defmt", derive(defmt::Format))]
        pub struct $name<'a>(pub &'a [u8]);

        impl<'a> Iterator for $name<'a> {
            type Item = $item<'a>;

            fn next(&mut self) -> Option<Self::Item> {
                let (ie, len) = $item::try_read(self.0, ()).ok()?;
                self.0 = &self.0[len..];
                Some(ie)
            }
        }
    };
}

ie_iterator!(
    /// The Header IEs of a list; it stops at the first malformed one
    HeaderIes,
    HeaderIe
);
ie_iterator!(
    /// The Payload IEs of a list; it stops at the first malformed one
    PayloadIes,
    PayloadIe
);
ie_iterator!(
    /// The nested IEs of an MLME IE; it stops at the first malformed one
    NestedIes,
    NestedIe
);

/// The SUN Device Capabilities IE's content (section 7.4.4.10)
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct SunDeviceCapabilities<'a> {
    /// The SUN Features field (Figure 7-63): [`SunDeviceCapabilities::MODE_SWITCH`]
    /// and the others; its Extended Band Identifier bit is set from `bands`
    /// when written
    pub features: u8,
    /// The Frequency Bands Supported bitmap, by band identifier (Tables 7-21
    /// and 7-22)
    pub bands: u32,
    /// The encoded PHY Type Descriptors: written with [`PhyTypeDescriptor`],
    /// read with [`SunDeviceCapabilities::descriptors`]
    pub descriptors: &'a [u8],
}

impl SunDeviceCapabilities<'_> {
    /// SUN Features: Enh-Ack supported
    pub const ENH_ACK: u8 = 1 << 0;
    /// SUN Features: data whitening supported
    pub const DATA_WHITENING: u8 = 1 << 1;
    /// SUN Features: interleaving supported
    pub const INTERLEAVING: u8 = 1 << 2;
    /// SUN Features: SFD group 1 supported
    pub const SFD_G1: u8 = 1 << 3;
    /// SUN Features: NRNSC FEC supported
    pub const NRNSC_FEC: u8 = 1 << 4;
    /// SUN Features: RSC FEC supported
    pub const RSC_FEC: u8 = 1 << 5;
    /// SUN Features: the mode switch mechanism (section 19.5) supported
    pub const MODE_SWITCH: u8 = 1 << 6;
    /// SUN Features: the band fields are 4 octets (Table 7-22's identifiers)
    pub const EXTENDED_BAND_IDENTIFIER: u8 = 1 << 7;

    fn extended(&self) -> bool {
        self.features & Self::EXTENDED_BAND_IDENTIFIER != 0
    }

    /// The PHY Type Descriptors
    pub fn descriptors(&self) -> PhyTypeDescriptors<'_> {
        PhyTypeDescriptors {
            bytes: self.descriptors,
            extended: self.extended(),
        }
    }
}

impl<'a> TryRead<'a> for SunDeviceCapabilities<'a> {
    fn try_read(bytes: &'a [u8], _ctx: ()) -> byte::Result<(Self, usize)> {
        let offset = &mut 0;
        let features: u8 = bytes.read(offset)?;
        let bands = if features & Self::EXTENDED_BAND_IDENTIFIER != 0 {
            bytes.read_with(offset, LE)?
        } else {
            u32::from(bytes.read_with::<u16>(offset, LE)?)
        };
        let descriptors = &bytes[*offset..];
        *offset = bytes.len();
        Ok((
            Self {
                features,
                bands,
                descriptors,
            },
            *offset,
        ))
    }
}

impl TryWrite for SunDeviceCapabilities<'_> {
    fn try_write(self, bytes: &mut [u8], _ctx: ()) -> byte::Result<usize> {
        let offset = &mut 0;
        let extended = self.bands > 0xffff;
        let features = if extended {
            self.features | Self::EXTENDED_BAND_IDENTIFIER
        } else {
            self.features & !Self::EXTENDED_BAND_IDENTIFIER
        };
        bytes.write(offset, features)?;
        if extended {
            bytes.write_with(offset, self.bands, LE)?;
        } else {
            bytes.write_with(offset, self.bands as u16, LE)?;
        }
        bytes.write(offset, self.descriptors)?;
        Ok(*offset)
    }
}

/// A PHY Type Descriptor (Figure 7-64)
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct PhyTypeDescriptor {
    /// The PHY Type (Table 7-23): 1 for FSK-B, 5 to 8 for OFDM options 1 to
    /// 4, and so on
    pub phy_type: u8,
    /// The PHY Modes Supported bitmap: bit n for PHY Mode ID n (Tables 7-24
    /// to 7-30)
    pub modes: u16,
    /// The bands the PHY type is supported in, or `None` for all those of the
    /// SUN Device Capabilities IE
    pub bands: Option<u32>,
}

impl TryRead<'_, bool> for PhyTypeDescriptor {
    /// `extended` is the IE's Extended Band Identifier
    fn try_read(bytes: &[u8], extended: bool) -> byte::Result<(Self, usize)> {
        let offset = &mut 0;
        let d: u16 = bytes.read_with(offset, LE)?;
        let bands = if d & 0x10 != 0 {
            None
        } else if extended {
            Some(bytes.read_with(offset, LE)?)
        } else {
            Some(u32::from(bytes.read_with::<u16>(offset, LE)?))
        };
        Ok((
            Self {
                phy_type: (d & 0x0f) as u8,
                modes: d >> 5,
                bands,
            },
            *offset,
        ))
    }
}

impl TryWrite<bool> for PhyTypeDescriptor {
    /// `extended` is the IE's Extended Band Identifier
    fn try_write(
        self,
        bytes: &mut [u8],
        extended: bool,
    ) -> byte::Result<usize> {
        if self.phy_type > 0x0f || self.modes > 0x07ff {
            return Err(byte::Error::BadInput {
                err: "PHY Type or PHY Modes Supported too large",
            });
        }
        let offset = &mut 0;
        let all = u16::from(self.bands.is_none()) << 4;
        let d = u16::from(self.phy_type) | all | self.modes << 5;
        bytes.write_with(offset, d, LE)?;
        match self.bands {
            None => {}
            Some(b) if extended => bytes.write_with(offset, b, LE)?,
            Some(b) => bytes.write_with(offset, b as u16, LE)?,
        }
        Ok(*offset)
    }
}

/// The PHY Type Descriptors of a SUN Device Capabilities IE
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct PhyTypeDescriptors<'a> {
    bytes: &'a [u8],
    extended: bool,
}

impl Iterator for PhyTypeDescriptors<'_> {
    type Item = PhyTypeDescriptor;

    fn next(&mut self) -> Option<Self::Item> {
        let (d, len) =
            PhyTypeDescriptor::try_read(self.bytes, self.extended).ok()?;
        self.bytes = &self.bytes[len..];
        Some(d)
    }
}

/// A Vendor Specific Nested IE's content (section 7.4.4.30), or a Vendor
/// Specific Header or Payload IE's
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct VendorSpecific<'a> {
    /// The vendor's OUI, in the order it is sent
    pub oui: [u8; 3],
    /// The Vendor Specific Information
    pub information: &'a [u8],
}

impl<'a> TryRead<'a> for VendorSpecific<'a> {
    fn try_read(bytes: &'a [u8], _ctx: ()) -> byte::Result<(Self, usize)> {
        check_len(bytes, 3)?;
        Ok((
            Self {
                oui: [bytes[0], bytes[1], bytes[2]],
                information: &bytes[3..],
            },
            bytes.len(),
        ))
    }
}

impl TryWrite for VendorSpecific<'_> {
    fn try_write(self, bytes: &mut [u8], _ctx: ()) -> byte::Result<usize> {
        let offset = &mut 0;
        bytes.write(offset, &self.oui[..])?;
        bytes.write(offset, self.information)?;
        Ok(*offset)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_ie_round_trip() {
        let mut buf = [0u8; 8];
        let n = HeaderIe::new(0x2a, &[1, 2, 3])
            .try_write(&mut buf, ())
            .unwrap();
        // Length 3, Element ID 0x2a: 0x2a << 7 | 3 = 0x1503.
        assert_eq!(&buf[..n], &[0x03, 0x15, 1, 2, 3]);
        let (ie, len) = HeaderIe::try_read(&buf[..n], ()).unwrap();
        assert_eq!((ie.id, ie.content, len), (0x2a, &[1u8, 2, 3][..], 5));
    }

    #[test]
    fn termination_ies_encode_as_the_standard_gives_them() {
        let mut buf = [0u8; 2];
        HeaderIe::new(header_id::TERMINATION_1, &[])
            .try_write(&mut buf, ())
            .unwrap();
        assert_eq!(buf, [0x00, 0x3f]);
        HeaderIe::new(header_id::TERMINATION_2, &[])
            .try_write(&mut buf, ())
            .unwrap();
        assert_eq!(buf, [0x80, 0x3f]);
        PayloadIe::new(group_id::TERMINATION, &[])
            .try_write(&mut buf, ())
            .unwrap();
        assert_eq!(buf, [0x00, 0xf8]);
    }

    #[test]
    fn nested_ies_short_and_long() {
        let mut buf = [0u8; 16];
        let o = &mut 0;
        buf.write(
            o,
            NestedIe::Short {
                sub_id: sub_id::SUN_DEVICE_CAPABILITIES,
                content: &[0x40, 0x10, 0x00],
            },
        )
        .unwrap();
        buf.write(
            o,
            NestedIe::Long {
                sub_id: sub_id::VENDOR_SPECIFIC,
                content: &[0x00, 0x0b, 0x57, 0x99],
            },
        )
        .unwrap();
        assert_eq!(&buf[..5], &[0x03, 0x22, 0x40, 0x10, 0x00]);
        // Long: 0x8000 | 4 | 0x8 << 11 = 0xc004.
        assert_eq!(&buf[5..*o], &[0x04, 0xc0, 0x00, 0x0b, 0x57, 0x99]);
        let ies: [_; 2] = {
            let mut it = NestedIes(&buf[..*o]);
            [it.next().unwrap(), it.next().unwrap()]
        };
        assert!(matches!(ies[0], NestedIe::Short { sub_id: 0x22, .. }));
        let v: VendorSpecific<'_> = ies[1].content().read(&mut 0).unwrap();
        assert_eq!((v.oui, v.information), ([0x00, 0x0b, 0x57], &[0x99][..]));
    }

    #[test]
    fn sun_device_capabilities_round_trip() {
        let mut d = [0u8; 8];
        let o = &mut 0;
        // FSK-B modes 7 and 8 (Wi-SUN 2a and 1a), OFDM option 4 MCS 2 to 6.
        for desc in [
            PhyTypeDescriptor {
                phy_type: 1,
                modes: 1 << 7 | 1 << 8,
                bands: None,
            },
            PhyTypeDescriptor {
                phy_type: 8,
                modes: 0b111_1100,
                bands: Some(1 << 4),
            },
        ] {
            d.write_with(o, desc, false).unwrap();
        }
        let caps = SunDeviceCapabilities {
            features: SunDeviceCapabilities::MODE_SWITCH,
            bands: 1 << 4,
            descriptors: &d[..*o],
        };
        let mut buf = [0u8; 16];
        let n = caps.try_write(&mut buf, ()).unwrap();
        assert_eq!(&buf[..3], &[0x40, 0x10, 0x00]);
        let (back, _) = SunDeviceCapabilities::try_read(&buf[..n], ()).unwrap();
        assert_eq!(back, caps);
        let mut it = back.descriptors();
        assert_eq!(it.next().unwrap().modes, 0x180);
        assert_eq!(it.next().unwrap().bands, Some(0x10));
        assert_eq!(it.next(), None);
    }

    #[test]
    fn lists_and_their_terminations() {
        let mut header = [0u8; 4];
        HeaderIe::new(0x2a, &[7, 8])
            .try_write(&mut header, ())
            .unwrap();
        let mut payload = [0u8; 3];
        PayloadIe::new(group_id::MLME, &[9])
            .try_write(&mut payload, ())
            .unwrap();
        let ies = InformationElements::new(&header, &payload);
        let mut buf = [0u8; 16];
        // A MAC payload follows: HT1 after the Header IEs, PT after the
        // Payload IEs.
        let n = ies.write(&mut buf, true).unwrap();
        assert_eq!(n, 4 + 2 + 3 + 2);
        let (back, len) = InformationElements::read(&buf[..n]).unwrap();
        assert_eq!((back, len), (ies, n));
        // Nothing follows: no Payload Termination.
        assert_eq!(ies.write(&mut buf, false).unwrap(), 4 + 2 + 3);
        // Header IEs only, then a MAC payload: HT2.
        let only = InformationElements::new(&header, &[]);
        let n = only.write(&mut buf, true).unwrap();
        assert_eq!(&buf[4..n], &[0x80, 0x3f]);
        assert_eq!(InformationElements::read(&buf[..n]).unwrap(), (only, n));
    }
}
