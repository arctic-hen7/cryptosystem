#[cfg(feature = "serde")]
use crate::error::CryptoError;
use crate::{
    crypto_io::{CryptoExport, CryptoImport},
    SymmetricCryptosystem,
};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// A symmetric key, which can be used to encrypt and decrypt messages.
#[derive(Clone)]
pub struct SymmetricKey<C: SymmetricCryptosystem> {
    key: C::Key,
}
impl<C: SymmetricCryptosystem> CryptoImport for SymmetricKey<C> {
    type Error = C::IoError;

    fn from_bytes(bytes: &[u8]) -> Result<Self, Self::Error> {
        C::import_key(bytes).map(|key| Self { key })
    }
}
impl<C: SymmetricCryptosystem> CryptoExport for SymmetricKey<C> {
    fn to_bytes(&self) -> &[u8] {
        C::export_key(&self.key)
    }
}
impl<C: SymmetricCryptosystem> SymmetricKey<C> {
    /// Generates a new symmetric key.
    pub fn generate() -> Self {
        Self {
            key: C::generate_key(),
        }
    }

    /// Encrypts the given message bytes, returning the bytes of the ciphertext.
    pub fn encrypt_bytes(&self, msg: &[u8]) -> Result<Vec<u8>, C::Error> {
        C::encrypt(msg, &self.key)
    }
    /// Decrypts the given ciphertext bytes, returning the bytes of the plaintext.
    pub fn decrypt_bytes(&self, ciphertext: &[u8]) -> Result<Vec<u8>, C::Error> {
        C::decrypt(ciphertext, &self.key)
    }

    /// Encrypts the given message, returning the bytes of the ciphertext, but first serializing
    /// the message to bytes with [`bincode`].
    ///
    /// Note that encryption done this way is intended for decryption by these same systems, as
    /// [`bincode`]'s serialization format is not standardised! If you want to decrypt messages on
    /// different systems, first serialize your message to bytes in some standardised way the other
    /// system can do too, and then use [`Self::encrypt_bytes`].
    #[cfg(feature = "serde")]
    pub fn encrypt<T: Serialize>(&self, msg: &T) -> Result<Vec<u8>, CryptoError<C::Error>> {
        let msg_bytes = bincode::serialize(msg)
            .map_err(|source| CryptoError::SerializationFailed { source })?;
        self.encrypt_bytes(&msg_bytes)
            .map_err(|source| CryptoError::ImplementationError { source })
    }
    /// Decrypts the given ciphertext, deserializing the resulting plaintext bytes into the given
    /// type. This is intended for decrypting messages created with this same system, as
    /// [`bincode`]'s serialization format is not standardised!
    #[cfg(feature = "serde")]
    pub fn decrypt<T: for<'de> Deserialize<'de>>(
        &self,
        ciphertext: &[u8],
    ) -> Result<T, CryptoError<C::Error>> {
        let plaintext_bytes = self
            .decrypt_bytes(ciphertext)
            .map_err(|source| CryptoError::ImplementationError { source })?;
        bincode::deserialize(&plaintext_bytes)
            .map_err(|source| CryptoError::DeserializationFailed { source })
    }
}
