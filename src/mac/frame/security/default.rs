//! Provides a default AEAD to satisfy the type requirements for (de-)serializing frames without
//! any security

use ccm::aead::{
    generic_array::{
        typenum::consts::{U0, U13, U16, U4, U8},
        GenericArray,
    },
    AeadInPlace, Error, Key, NewAead, Nonce, Tag,
};

use super::{KeyLookup};

macro_rules! unimplemented_aead {
    ($name: ident, $nonce_size: ty, $tag_size: ty) => {
        pub struct $name();
        impl AeadInPlace for $name {
            type NonceSize = $nonce_size;
            type TagSize = $tag_size;
            type CiphertextOverhead = U0;

            fn encrypt_in_place_detached(
                &self,
                _: &Nonce<Self::NonceSize>,
                _: &[u8],
                _: &mut [u8],
            ) -> Result<Tag<Self::TagSize>, ccm::aead::Error> {
                Err(Error)
            }
            fn decrypt_in_place_detached(
                &self,
                _: &Nonce<Self::NonceSize>,
                _: &[u8],
                _: &mut [u8],
                _: &Tag<Self::TagSize>,
            ) -> Result<(), ccm::aead::Error> {
                Err(Error)
            }
        }

        impl NewAead for $name {
            type KeySize = U16;

            fn new(_: &Key<Self>) -> Self {
                Self {}
            }
        }
    };
}

unimplemented_aead!(UnimplementedAead32, U13, U4);
unimplemented_aead!(UnimplementedAead64, U13, U8);
unimplemented_aead!(UnimplementedAead128, U13, U16);

pub struct Unimplemented();

impl KeyLookup<U16> for Unimplemented {
    fn lookup_key(
        &self,
        _address_mode: super::AddressingMode,
        _key_identifier: Option<super::KeyIdentifier>,
        _device_address: Option<crate::mac::Address>,
    ) -> Option<GenericArray<u8, U16>> {
        None
    }
}
