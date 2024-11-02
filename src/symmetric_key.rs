#[cfg(feature = "base64")]
use crate::base64_utils::{base64_to_bytes, bytes_to_base64};
use crate::cryptosystem::SymmetricCryptosystem;
#[cfg(feature = "serde")]
use crate::error::CryptoError;
#[cfg(feature = "base64")]
use crate::error::FromBase64Error;
#[cfg(feature = "hex")]
use crate::error::FromHexError;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// A symmetric key, which can be used to encrypt and decrypt messages.
pub struct SymmetricKey<C: SymmetricCryptosystem> {
    key: C::Key,
}
impl<C: SymmetricCryptosystem> SymmetricKey<C> {
    /// Generates a new symmetric key.
    pub fn generate() -> Self {
        Self {
            key: C::generate_key(),
        }
    }

    /// Imports the given bytes as a symmetric key.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, C::IoError> {
        C::import_key(bytes).map(|key| Self { key })
    }
    /// Exports this symmetric key to bytes.
    pub fn to_bytes(&self) -> &[u8] {
        C::export_key(&self.key)
    }

    /// Imports the given hex-encoded string as a symmetric key.
    #[cfg(feature = "hex")]
    pub fn from_hex(hex: &str) -> Result<Self, FromHexError<C::IoError>> {
        let bytes = hex::decode(hex).map_err(|source| FromHexError::DecodeError(source))?;
        Self::from_bytes(&bytes).map_err(|source| FromHexError::ConvertError(source))
    }
    /// Exports this symmetric key to a hex-encoded string.
    #[cfg(feature = "hex")]
    pub fn to_hex(&self) -> String {
        let bytes = self.to_bytes();
        hex::encode(bytes)
    }

    /// Imports the given base64-encoded string as a symmetric key.
    #[cfg(feature = "base64")]
    pub fn from_base64(base64: &str, url_safe: bool) -> Result<Self, FromBase64Error<C::IoError>> {
        let bytes = base64_to_bytes(base64, url_safe)
            .map_err(|source| FromBase64Error::DecodeError(source))?;
        Self::from_bytes(&bytes).map_err(|source| FromBase64Error::ConvertError(source))
    }
    /// Exports this symmetric key to a base64-encoded string.
    #[cfg(feature = "base64")]
    pub fn to_base64(&self, url_safe: bool) -> String {
        let bytes = self.to_bytes();
        bytes_to_base64(bytes, url_safe)
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
