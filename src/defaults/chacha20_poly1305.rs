use crate::{cryptosystem::SymmetricCryptosystem, symmetric_cryptosystem_tests};
use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Key, XChaCha20Poly1305,
};
use std::convert::Infallible;
use thiserror::Error;

pub type C7P7Cryptosystem = ChaCha20Poly1305Cryptosystem;

/// A cryptosystem using ChaCha20Poly1305 for symmetric encryption.
pub struct ChaCha20Poly1305Cryptosystem;
impl SymmetricCryptosystem for ChaCha20Poly1305Cryptosystem {
    type Key = Key;
    type Error = ChaCha20Poly1305Error;
    type IoError = Infallible;

    fn generate_key() -> Self::Key {
        XChaCha20Poly1305::generate_key(&mut OsRng)
    }
    fn encrypt(msg: &[u8], key: &Self::Key) -> Result<Vec<u8>, Self::Error> {
        let cipher = XChaCha20Poly1305::new(key);
        let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
        let ciphertext = cipher
            .encrypt(&nonce, msg)
            .map_err(|_| ChaCha20Poly1305Error::EncryptionFailed)?;

        let mut ciphertext_with_nonce = Vec::with_capacity(nonce.len() + ciphertext.len());
        ciphertext_with_nonce.extend_from_slice(&nonce);
        ciphertext_with_nonce.extend_from_slice(&ciphertext);
        Ok(ciphertext_with_nonce)
    }
    fn decrypt(ciphertext: &[u8], key: &Self::Key) -> Result<Vec<u8>, Self::Error> {
        // Nonce is the first 24 bytes
        let extracted_nonce = &ciphertext[..24];
        let cipher = XChaCha20Poly1305::new(key);
        let plaintext_bytes = cipher
            .decrypt(extracted_nonce.into(), &ciphertext[24..])
            .map_err(|_| ChaCha20Poly1305Error::DecryptionFailed)?;
        Ok(plaintext_bytes)
    }
    fn export_key(key: &Self::Key) -> &[u8] {
        key.as_ref()
    }
    fn import_key(key: &[u8]) -> Result<Self::Key, Self::IoError> {
        // Infallible, symmetric keys for ChaCha are just raw bytes with no particular structure
        Ok(*Key::from_slice(key))
    }
}

#[derive(Error, Debug)]
pub enum ChaCha20Poly1305Error {
    #[error("failed to encrypt given message")]
    EncryptionFailed,
    #[error("failed to decrypt given message with given key")]
    DecryptionFailed,
}

symmetric_cryptosystem_tests!(super::ChaCha20Poly1305Cryptosystem);
