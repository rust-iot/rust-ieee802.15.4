//! Provides a fake/mock AEAD to satisfy the type requirements for (de-)serializing frames without
//! any security

use aead::{consts::U0, AeadCore, AeadInPlace, NewAead};

use crate::mac::{frame::FrameSerDesContext, FooterMode};

use super::{KeyDescriptorLookup, NonceGenerator};

/// An AEAD struct that will panic if it is attempted to be used
/// for actual AEAD operations
///
/// # Panics
///
/// Any functions implemented for this struct panic if they are called
pub struct Unimplemented();
impl AeadCore for Unimplemented {
    type NonceSize = U0;

    type TagSize = U0;

    type CiphertextOverhead = U0;
}

impl NewAead for Unimplemented {
    type KeySize = U0;
    fn new(_: &aead::Key<Self>) -> Self {
        unimplemented!()
    }
}

impl AeadInPlace for Unimplemented {
    fn encrypt_in_place_detached(
        &self,
        _nonce: &aead::Nonce<Self>,
        _associated_data: &[u8],
        _buffer: &mut [u8],
    ) -> Result<aead::Tag<Self>, aead::Error> {
        unimplemented!()
    }

    fn decrypt_in_place_detached(
        &self,
        _nonce: &aead::Nonce<Self>,
        _associated_data: &[u8],
        _buffer: &mut [u8],
        _tag: &aead::Tag<Self>,
    ) -> Result<(), aead::Error> {
        unimplemented!()
    }
}

impl NonceGenerator<U0> for Unimplemented {
    fn generate_nonce(
        _input_nonce: [u8; 13],
        _destination: &mut aead::generic_array::GenericArray<u8, U0>,
    ) {
        unimplemented!()
    }
}

impl KeyDescriptorLookup for Unimplemented {
    fn lookup_key(
        &self,
        _address_mode: super::KeyAddressMode,
        _key_identifier: Option<super::KeyIdentifier>,
        _device_address: Option<crate::mac::Address>,
    ) -> Option<super::KeyDescriptor> {
        unimplemented!();
    }
}
