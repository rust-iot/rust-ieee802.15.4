//! Provides a default AEAD to satisfy the type requirements for (de-)serializing frames without
//! any security

use ccm::aead::generic_array::{
    typenum::consts::{U1, U16},
    GenericArray,
};
use cipher::{BlockCipher, NewBlockCipher};

use super::KeyLookup;

/// A struct that fullfills all of the type checks, but is not actually capable of
/// performing any of the operations
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

impl BlockCipher for Unimplemented {
    type BlockSize = U16;

    type ParBlocks = U1;

    fn encrypt_block(&self, _block: &mut cipher::block::Block<Self>) {}

    fn decrypt_block(&self, _block: &mut cipher::block::Block<Self>) {}
}

impl NewBlockCipher for Unimplemented {
    type KeySize = U16;

    fn new(_key: &cipher::block::Key<Self>) -> Self {
        Unimplemented {}
    }
}
