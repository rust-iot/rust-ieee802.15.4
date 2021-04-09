//! All of the fields and their contents that are used in the
//! Auxiliary Security header can be found in this module.
//!
//! All of the below data structures are defined in section 7.4 of the 802.15.4-2011 standard

use core::marker::PhantomData;

use byte::BytesExt;
use ccm::{
    aead::{
        generic_array::{
            typenum::consts::{U13 as CcmU13, U16 as CcmU16, U4, U8},
            ArrayLength, GenericArray,
        },
        AeadInPlace, NewAead,
    },
    Ccm,
};

use crate::mac::{Address, FrameType, FrameVersion};

use super::{FooterMode, Frame, Header};

mod auxiliary_security_header;
pub use auxiliary_security_header::{
    AuxiliarySecurityHeader, KeyDescriptor, KeyIdentifier, KeySource,
};

pub(crate) mod default;

mod security_control;
pub use security_control::{KeyIdentifierMode, SecurityControl, SecurityLevel};

pub use cipher::{generic_array::typenum::consts::U16, BlockCipher, NewBlockCipher};

/// The addressing mode to use during descriptor lookups
pub enum AddressingMode {
    /// Destination addressing mode
    DstAddrMode,
    /// Source addressing mode
    SrcAddrMode,
}

#[derive(Clone)]
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
pub struct SecurityContext<AEADBLKCIPH, KEYDESCLO>
where
    AEADBLKCIPH: NewBlockCipher + BlockCipher<BlockSize = U16>,
    KEYDESCLO: KeyLookup<AEADBLKCIPH::KeySize>,
{
    /// The current frame counter
    pub frame_counter: u32,
    /// The key descriptor lookup to use to look up keys
    pub key_provider: KEYDESCLO,
    /// This is phantom data as we use AEAD to actually instantiate an instance
    /// of AEAD, as opposed to actually using a provided AEAD instance somewhere
    ///
    /// The NONCEGEN is phantom data as well
    pub phantom_data: PhantomData<AEADBLKCIPH>,
}

fn calculate_nonce(source_addr: u64, frame_counter: u32, sec_level: SecurityLevel) -> [u8; 13] {
    let mut output = [0u8; 13];
    for i in 0..8 {
        output[i] = (source_addr >> (8 * i) & 0xFF) as u8;
    }

    for i in 0..4 {
        output[i + 8] = (frame_counter >> (8 * i) & 0xFF) as u8;
    }

    output[12] = sec_level.to_bits();
    output
}

/// Appends the secured payload of a [Frame] to the provided buffer, secured according to the
/// security settings specified in the [Frame]'s [`super::Header`] and [AuxiliarySecurityHeader].
///
/// Offset is updated with the amount of bytes that is written
///
/// Currently only supports the securing of Data frames with extended addresses
///
/// Partial implementation of 7.2.1
pub(crate) fn secure_frame<'a, AEADBLKCIPH, KEYDESCLO>(
    frame: Frame<'_>,
    context: &mut SecurityContext<AEADBLKCIPH, KEYDESCLO>,
    footer_mode: FooterMode,
    buffer: &mut [u8],
) -> Result<usize, SecurityError>
where
    AEADBLKCIPH: NewBlockCipher + BlockCipher<BlockSize = U16>,
    KEYDESCLO: KeyLookup<AEADBLKCIPH::KeySize>,
{
    let mut offset = 0 as usize;
    let header = frame.header;

    if header.has_security() {
        let frame_counter = &mut context.frame_counter;
        let source = match header.source {
            Some(addr) => match addr {
                Address::Short(_, _) => {
                    return Err(SecurityError::NotImplemented);
                }
                Address::Extended(_, ext_addr) => ext_addr.0,
            },
            _ => return Err(SecurityError::NoSourceAddress),
        };

        // Check for unimplemented behaviour before performing any operations on the buffer
        match header.frame_type {
            FrameType::Data => {}
            _ => return Err(SecurityError::NotImplemented),
        }

        // Procedure 7.2.1
        if let Some(aux_sec_header) = header.auxiliary_security_header {
            let auth_len = aux_sec_header.control.security_level.get_mic_octet_size();
            let aux_len = aux_sec_header.get_octet_size();

            // If frame size plus AuthLen plus AuxLen plus FCS is bigger than aMaxPHYPacketSize
            // 7.2.1b4
            if !(frame.header.get_octet_size() + aux_len + auth_len + 2 <= 127) {
                return Err(SecurityError::FrameTooLong);
            }

            // Write unencrypted data to the buffer, 7.2.1c, preparation for in-place AEAD in 7.2.1g
            if let Err(e) = buffer.write(&mut offset, frame.payload) {
                return Err(SecurityError::WriteError(e));
            }

            // Success if the security level is none (7.2.1c)
            if aux_sec_header.control.security_level == SecurityLevel::None {
                return Ok(offset);
            }

            // 7.2.1d
            if *frame_counter == 0xFFFFFFFF {
                return Err(SecurityError::CounterError);
            }

            let nonce = calculate_nonce(
                source,
                *frame_counter,
                aux_sec_header.control.security_level,
            );

            *frame_counter += 1;

            // Partial 7.2.1e, 7.2.2 is only partially implemented
            if let Some(key) = context.key_provider.lookup_key(
                AddressingMode::DstAddrMode,
                aux_sec_header.key_identifier,
                header.destination,
            ) {
                // 7.2.1g
                let sec_l = aux_sec_header.control.security_level;

                // Macro that invokes the security procedure for block ciphers with different tag
                // sizes
                macro_rules! do_secure {
                    ($tag_size:ty, $mic:pat, $encmic:pat) => {
                        let aead = Ccm::<AEADBLKCIPH, $tag_size, CcmU13>::new(&key);

                        let auth_enc_part = match footer_mode {
                            FooterMode::None => &mut buffer[..offset],
                            FooterMode::Explicit => return Err(SecurityError::NotImplemented),
                        };

                        let tag = match sec_l {
                            $mic => aead.encrypt_in_place_detached(
                                &GenericArray::from_slice(&nonce),
                                auth_enc_part,
                                &mut [],
                            ),
                            $encmic => aead.encrypt_in_place_detached(
                                &GenericArray::from_slice(&nonce),
                                &mut [],
                                auth_enc_part,
                            ),
                            _ => {
                                panic!("Impossible")
                            }
                        };

                        if let Ok(tag) = tag {
                            if let Err(e) = buffer.write(&mut offset, tag.as_slice()) {
                                return Err(SecurityError::WriteError(e));
                            }
                        } else {
                            return Err(SecurityError::TransformationError);
                        }
                    };
                }

                match sec_l {
                    SecurityLevel::None => {}
                    SecurityLevel::ENC => {
                        // No support for encryption without authentication
                        return Err(SecurityError::NotImplemented);
                    }
                    SecurityLevel::MIC32 | SecurityLevel::ENCMIC32 => {
                        do_secure!(U4, SecurityLevel::MIC32, SecurityLevel::ENCMIC32);
                    }
                    SecurityLevel::MIC64 | SecurityLevel::ENCMIC64 => {
                        do_secure!(U8, SecurityLevel::MIC64, SecurityLevel::ENCMIC64);
                    }
                    SecurityLevel::MIC128 | SecurityLevel::ENCMIC128 => {
                        do_secure!(CcmU16, SecurityLevel::MIC128, SecurityLevel::ENCMIC128);
                    }
                    #[allow(unreachable_patterns)]
                    _ => {}
                };
                return Ok(offset);
            } else {
                return Err(SecurityError::UnavailableKey);
            }
        } else {
            return Err(SecurityError::AuxSecHeaderAbsent);
        }
    } else {
        return Err(SecurityError::SecurityNotEnabled);
    }
}

/// Unsecure a currently secured frame, based on the
/// settings found in the header of `frame`. `buffer` should be
/// the slice containing the authenticated and possibly encrypted data,
/// and its tag.
///
/// # Returns
/// In case of success, the function returns the length of the authentication tag,
/// i.e. the amount of bytes at the end of the payload that should be ignored
///
/// Replaces the payload of `frame` with the unsecured version
///
/// Partial implementation of 7.2.3
/// Currently not implemented: 7.2.3h, 7.2.3i, 7.2.3j, 7.2.3k, 7.2.3n
pub(crate) fn unsecure_frame<'a, AEADBLKCIPH, KEYDESCLO, DEVDESCLO>(
    header: &Header,
    buffer: &mut [u8],
    context: &mut SecurityContext<AEADBLKCIPH, KEYDESCLO>,
    footer_mode: FooterMode,
    dev_desc_lo: &mut DEVDESCLO,
) -> Result<usize, SecurityError>
where
    AEADBLKCIPH: NewBlockCipher + BlockCipher<BlockSize = U16>,
    KEYDESCLO: KeyLookup<AEADBLKCIPH::KeySize>,
    DEVDESCLO: DeviceDescriptorLookup,
{
    if header.has_security() {
        let (source, source_u64) = match header.source {
            Some(addr) => match addr {
                Address::Short(_, _) => {
                    return Err(SecurityError::NotImplemented);
                }
                Address::Extended(_, ext_addr) => (addr, ext_addr.0),
            },
            _ => return Err(SecurityError::NoSourceAddress),
        };

        // Check for unimplemented behaviour before performing any operations on the buffer
        match header.frame_type {
            FrameType::Data => {}
            _ => return Err(SecurityError::NotImplemented),
        }

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

        let mut taglen = 0;
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

                    let nonce = calculate_nonce(
                        source_u64,
                        aux_sec_header.frame_counter,
                        aux_sec_header.control.security_level,
                    );

                    let data_and_tag = match footer_mode {
                        FooterMode::None => buffer,
                        FooterMode::Explicit => unimplemented!(),
                    };

                    let sec_l = aux_sec_header.control.security_level;
                    macro_rules! do_unsecure {
                        ($tag_size:ty, $mic:pat, $encmic:pat) => {
                            let aead = Ccm::<AEADBLKCIPH, $tag_size, CcmU13>::new(&key);
                            taglen = sec_l.get_mic_octet_size() as usize;
                            // Copy the tag out of the aead slice
                            let buffer_len = data_and_tag.len();
                            let tag = GenericArray::from_slice(
                                &data_and_tag[buffer_len - taglen..buffer_len],
                            )
                            .clone();

                            let auth_enc_part = &mut data_and_tag[..buffer_len - taglen];

                            let verify = match sec_l {
                                $mic => aead.decrypt_in_place_detached(
                                    &GenericArray::from_slice(&nonce),
                                    auth_enc_part,
                                    &mut [],
                                    &tag,
                                ),
                                $encmic => aead.decrypt_in_place_detached(
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
                                *frame_counter = aux_sec_header.frame_counter + 1;
                            } else {
                                return Err(SecurityError::TransformationError);
                            }
                        };
                    }
                    match sec_l {
                        SecurityLevel::None => {}
                        SecurityLevel::ENC => {
                            // No support for encryption without authentication
                            return Err(SecurityError::NotImplemented);
                        }
                        SecurityLevel::MIC32 | SecurityLevel::ENCMIC32 => {
                            do_unsecure!(U4, SecurityLevel::MIC32, SecurityLevel::ENCMIC32);
                        }
                        SecurityLevel::MIC64 | SecurityLevel::ENCMIC64 => {
                            do_unsecure!(U8, SecurityLevel::MIC64, SecurityLevel::ENCMIC64);
                        }
                        SecurityLevel::MIC128 | SecurityLevel::ENCMIC128 => {
                            do_unsecure!(U16, SecurityLevel::MIC128, SecurityLevel::ENCMIC128);
                        }
                        #[allow(unreachable_patterns)]
                        _ => {}
                    };
                }
                None => return Err(SecurityError::UnavailableDevice),
            }
        } else {
            return Err(SecurityError::UnavailableKey);
        }
        return Ok(taglen);
    } else {
        return Err(SecurityError::SecurityNotEnabled);
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

impl From<byte::Error> for SecurityError {
    fn from(e: byte::Error) -> Self {
        SecurityError::WriteError(e)
    }
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
    extern crate rand;
    use crate::mac::frame::header::*;
    use crate::mac::frame::security::{security_control::*, *};
    use crate::mac::frame::*;
    use crate::mac::{frame::frame_control::*, FooterMode};
    use aes_soft::Aes128;
    use rand::Rng;

    struct StaticKeyLookup();

    impl KeyLookup<U16> for StaticKeyLookup {
        fn lookup_key(
            &self,
            _address_mode: AddressingMode,
            _key_identifier: Option<KeyIdentifier>,
            _device_address: Option<Address>,
        ) -> Option<GenericArray<u8, U16>> {
            let key = GenericArray::default();
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
    const FRAME_CTR: u32 = 0x03030303;

    fn aes_sec_ctx<'a>(frame_counter: u32) -> SecurityContext<Aes128, StaticKeyLookup> {
        SecurityContext {
            frame_counter,
            key_provider: STATIC_KEY_LOOKUP,
            phantom_data: PhantomData,
        }
    }

    fn get_frame<'a>(
        source: Option<Address>,
        destination: Option<Address>,
        payload: &'a [u8],
        auxiliary_security_header: Option<AuxiliarySecurityHeader>,
    ) -> Frame<'a> {
        Frame {
            header: Header {
                frame_type: FrameType::Data,
                frame_pending: false,
                ack_request: false,
                pan_id_compress: false,
                version: FrameVersion::Ieee802154,
                seq: 127,
                destination,
                source,
                auxiliary_security_header,
            },
            content: FrameContent::Data,
            payload,
            footer: [0x00, 0x00],
        }
    }

    fn get_rand_addrpair() -> (Address, Address) {
        let src_u64: u64 = rand::thread_rng().gen();
        let dest_u64: u64 = rand::thread_rng().gen();
        let source = Address::Extended(PanId(0x111), ExtendedAddress(src_u64));
        let destination = Address::Extended(PanId(0x2222), ExtendedAddress(dest_u64));
        (source, destination)
    }

    macro_rules! test_security_level {
        ($level:expr) => {
            let (source, destination) = get_rand_addrpair();

            let aux_sec_header = Some(AuxiliarySecurityHeader {
                control: SecurityControl::new($level),
                frame_counter: FRAME_CTR,
                key_identifier: Some(KeyIdentifier {
                    key_source: None,
                    key_index: 0,
                }),
            });

            let plaintext_payload = &mut [0xFF, 0x00, 0xFF, 0x00, 0xFF, 0x00];
            let plaintext_len = plaintext_payload.len();

            let frame = get_frame(
                Some(source),
                Some(destination),
                plaintext_payload,
                aux_sec_header,
            );

            let mut storage = [0u8; 64];

            let buf = &mut storage[..plaintext_len + $level.get_mic_octet_size() as usize];

            let mut sec_ctx = aes_sec_ctx(FRAME_CTR);
            let write_res = security::secure_frame(frame, &mut sec_ctx, FooterMode::None, buf);

            match write_res {
                Err(e) => {
                    assert!(false, "Failed to secure frame {:?}!", e);
                }
                Ok(_) => {}
            }

            let mut frame = get_frame(Some(source), Some(destination), &[], aux_sec_header);

            let device_desc = DeviceDescriptor {
                address: Address::Extended(PanId(511), ExtendedAddress(0xAAFFAAFFAAFFu64)),
                frame_counter: FRAME_CTR,
                exempt: false,
            };

            let read_res = security::unsecure_frame(
                &mut frame.header,
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
            assert_eq!(buf[..plaintext_payload.len()], *plaintext_payload);
        };
    }

    #[test]
    fn encode_unsecured() {
        let (source, destination) = get_rand_addrpair();
        let frame = get_frame(
            Some(source),
            Some(destination),
            &[0xAA, 0xBB, 0xCC, 0xDD, 0xFE, 0xDE],
            None,
        );

        let mut buf = [0u8; 127];
        let mut sec_ctx = aes_sec_ctx(FRAME_CTR);
        let write_res = security::secure_frame(frame, &mut sec_ctx, FooterMode::None, &mut buf);
        match write_res {
            Ok(_) => {}
            Err(e) => match e {
                SecurityError::SecurityNotEnabled => {}
                _ => {
                    assert!(
                        false,
                        "Security was not enabled, but securing payload succeeded!"
                    )
                }
            },
        }
    }

    #[test]
    #[should_panic]
    fn test_enc() {
        test_security_level!(SecurityLevel::ENC);
    }
    #[test]
    fn test_mic32() {
        test_security_level!(SecurityLevel::MIC32);
    }
    #[test]
    fn test_mic64() {
        test_security_level!(SecurityLevel::MIC64);
    }
    #[test]
    fn test_mic128() {
        test_security_level!(SecurityLevel::MIC128);
    }
    #[test]
    fn test_encmic32() {
        test_security_level!(SecurityLevel::ENCMIC32);
    }
    #[test]
    fn test_encmic64() {
        test_security_level!(SecurityLevel::ENCMIC64);
    }
    #[test]
    fn test_encmic128() {
        test_security_level!(SecurityLevel::ENCMIC128);
    }

    #[test]
    fn encode_decode_secured_frame() {
        let (source, destination) = (
            Address::Extended(PanId(0x111), ExtendedAddress(0x08)),
            Address::Extended(PanId(0x2222), ExtendedAddress(0x09)),
        );

        let aux_sec_header = Some(AuxiliarySecurityHeader {
            control: SecurityControl::new(SecurityLevel::ENCMIC32),
            frame_counter: FRAME_CTR,
            key_identifier: None,
        });

        let plaintext_payload = &mut [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
        let plaintext_len = plaintext_payload.len();

        let plaintext_clone = plaintext_payload.clone();

        let frame = get_frame(
            Some(source),
            Some(destination),
            plaintext_payload,
            aux_sec_header,
        );

        let mut buf = [0u8; 127];
        let mut sec_ctx = aes_sec_ctx(FRAME_CTR);

        let len = match frame.try_write(
            &mut buf,
            &mut FrameSerDesContext::new(FooterMode::None, Some(&mut sec_ctx)),
        ) {
            Ok(size) => size,
            Err(e) => {
                assert!(false, "Failed to write secured frame! {:?}", e);
                // Panic to make the match-arm matcher happy
                panic!();
            }
        };

        // Assert that the length is correct (header field lengths, etc)
        assert_eq!(len, 2 + 1 + 2 + 8 + 2 + 8 + 1 + 4 + 0 + plaintext_len + 4);

        assert_eq!(
            &buf[..len],
            &[
                0x9, 0xEC, 0x7F, 0x22, 0x22, 0x9, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x11, 0x1,
                0x8, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x5, 0x3, 0x3, 0x3, 0x3, 0x7D, 0xE8, 0x2C,
                0xC9, 0xD7, 0xA8, 0x9D, 0x4D, 0xD, 0x6,
            ]
        );

        let device_desc = DeviceDescriptor {
            address: Address::Extended(PanId(511), ExtendedAddress(0xAAFFAAFFAAFFu64)),
            frame_counter: FRAME_CTR,
            exempt: false,
        };

        let frame = match Frame::try_read_and_unsecure(
            &mut buf[..len],
            &mut FrameSerDesContext::new(FooterMode::None, Some(&mut sec_ctx)),
            &mut BasicDevDescriptorLookup::new(device_desc),
        ) {
            Ok((frame, _)) => frame,
            Err(e) => {
                assert!(false, "Could not unsecure frame! {:?}", e);
                panic!();
            }
        };

        assert_eq!(plaintext_clone, frame.payload);
    }

    #[test]
    fn encode_fail_decode_secured_frame() {
        let (source, destination) = (
            Address::Extended(PanId(0x111), ExtendedAddress(0x08)),
            Address::Extended(PanId(0x2222), ExtendedAddress(0x09)),
        );

        let aux_sec_header = Some(AuxiliarySecurityHeader {
            control: SecurityControl::new(SecurityLevel::MIC128),
            frame_counter: FRAME_CTR,
            key_identifier: None,
        });

        let plaintext_payload = &mut [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
        let plaintext_len = plaintext_payload.len();

        let frame = get_frame(
            Some(source),
            Some(destination),
            plaintext_payload,
            aux_sec_header,
        );

        let mut buf = [0u8; 127];
        let mut sec_ctx = aes_sec_ctx(FRAME_CTR);

        let len = match frame.try_write(
            &mut buf,
            &mut FrameSerDesContext::new(FooterMode::None, Some(&mut sec_ctx)),
        ) {
            Ok(size) => size,
            Err(e) => {
                assert!(false, "Failed to write secured frame! {:?}", e);
                // Panic to make the match-arm matcher happy
                panic!();
            }
        };

        // Assert that the length is correct (header field lengths, etc)
        assert_eq!(len, 2 + 1 + 2 + 8 + 2 + 8 + 1 + 4 + 0 + plaintext_len + 16);
        let buf = &mut buf[..len];

        //
        // Test that authentication of frames works
        //

        // Simulate a bit change
        buf[33] ^= 0x01;

        let device_desc = DeviceDescriptor {
            address: Address::Extended(PanId(511), ExtendedAddress(0xAAFFAAFFAAFFu64)),
            frame_counter: FRAME_CTR,
            exempt: false,
        };

        match Frame::try_read_and_unsecure(
            buf,
            &mut FrameSerDesContext::new(FooterMode::None, Some(&mut sec_ctx)),
            &mut BasicDevDescriptorLookup::new(device_desc.clone()),
        ) {
            Ok(_) => assert!(false, "Successfully unsecured an altered frame!"),
            Err(e) => match e {
                SecurityError::TransformationError => {}
                _ => {
                    assert!(false, "Got an error different from TransformationError");
                    // Panic to make the match-arm matcher happy
                    panic!();
                }
            },
        };

        // Unflip bit
        buf[33] ^= 0x01;

        //
        // Test counter errors
        //
        let device_desc = DeviceDescriptor {
            address: Address::Extended(PanId(511), ExtendedAddress(0xAAFFAAFFAAFFu64)),
            frame_counter: FRAME_CTR + 5,
            exempt: false,
        };

        match Frame::try_read_and_unsecure(
            buf,
            &mut FrameSerDesContext::new(FooterMode::None, Some(&mut sec_ctx)),
            &mut BasicDevDescriptorLookup::new(device_desc),
        ) {
            Ok(_) => assert!(false, "Successfully unsecured a replayed frame!"),
            Err(e) => match e {
                SecurityError::CounterError => {}
                _ => {
                    assert!(false, "Got an error different from CounterError");
                    // Panic to make the match-arm matcher happy
                    panic!();
                }
            },
        };

        let device_desc = DeviceDescriptor {
            address: Address::Extended(PanId(511), ExtendedAddress(0xAAFFAAFFAAFFu64)),
            frame_counter: 0xFFFFFFFF,
            exempt: false,
        };

        match Frame::try_read_and_unsecure(
            buf,
            &mut FrameSerDesContext::new(FooterMode::None, Some(&mut sec_ctx)),
            &mut BasicDevDescriptorLookup::new(device_desc),
        ) {
            Ok(_) => assert!(
                false,
                "Successfully unsecured a frame with overflowing counter!"
            ),
            Err(e) => match e {
                SecurityError::CounterError => {}
                _ => {
                    assert!(false, "Got an error different from CounterError");
                    // Panic to make the match-arm matcher happy
                    panic!();
                }
            },
        };
    }
}
