//! Provides a default AEAD to satisfy the type requirements for (de-)serializing frames without
//! any security

use aead::{consts::U0, generic_array::GenericArray, AeadInPlace, NewAead};

use super::{KeyLookup, NonceGenerator};

/// An AEAD struct that will panic if it is attempted to be used
/// for actual AEAD operations
///
/// # Panics
///
/// Any functions implemented for this struct panic if they are called
pub struct Unimplemented();
impl AeadInPlace for Unimplemented {
    type NonceSize = U0;

    type TagSize = U0;

    type CiphertextOverhead = U0;

    fn encrypt_in_place_detached(
        &self,
        _nonce: &aead::Nonce<Self::NonceSize>,
        _associated_data: &[u8],
        _buffer: &mut [u8],
    ) -> Result<aead::Tag<Self::TagSize>, aead::Error> {
        unimplemented!()
    }

    fn decrypt_in_place_detached(
        &self,
        _nonce: &aead::Nonce<Self::NonceSize>,
        _associated_data: &[u8],
        _buffer: &mut [u8],
        _tag: &aead::Tag<Self::TagSize>,
    ) -> Result<(), aead::Error> {
        unimplemented!()
    }
}

impl NewAead for Unimplemented {
    type KeySize = U0;
    fn new(_: &aead::Key<Self>) -> Self {
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

impl KeyLookup<U0> for Unimplemented {
    fn lookup_key(
        &self,
        _address_mode: super::KeyAddressMode,
        _key_identifier: Option<super::KeyIdentifier>,
        _device_address: Option<crate::mac::Address>,
    ) -> Option<GenericArray<u8, U0>> {
        unimplemented!();
    }
}
