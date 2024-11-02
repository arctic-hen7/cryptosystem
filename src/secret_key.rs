#[cfg(feature = "base64")]
use crate::base64_utils::{base64_to_bytes, bytes_to_base64};
use crate::cryptosystem::KeyExchangeCryptosystem;
#[cfg(feature = "base64")]
use crate::error::FromBase64Error;
#[cfg(feature = "hex")]
use crate::error::FromHexError;
#[cfg(feature = "pem")]
use crate::error::FromPemError;
use crate::CryptoError;
use crate::{
    cryptosystem::{AsymmetricCryptosystem, PublicKeyCryptosystem, SigningCryptosystem},
    PublicKey,
};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// A secret key, which should be kept secret by some party to either decrypt messages encrypted by
/// others for them with their public key, or to create signatures on messages that will be
/// verifiable by others with their public key. The capabilities of this key depend on whether the
/// type parameter `C` implements [`crate::SigningCryptosystem`],
/// [`crate::AsymmetricCryptosystem`], [`crate::KeyExchangeCryptosystem`], or some combination of
/// the three.
pub struct SecretKey<C: PublicKeyCryptosystem> {
    key: C::SecretKey,
}

impl<C: PublicKeyCryptosystem> SecretKey<C> {
    /// Generates a new asymmetric keypair of a public key and secret key.
    pub fn generate_keypair() -> (PublicKey<C>, Self) {
        let (pubkey, key) = C::generate_keypair();
        (PublicKey { key: pubkey }, Self { key })
    }

    /// Imports the given raw bytes as a secret key. Use [`Self::from_der`] if these bytes are
    /// encoded as DER (if they've come from just about any other program, they probably are).
    pub fn from_raw_bytes(bytes: &[u8]) -> Result<Self, C::IoError> {
        C::import_secret_key_raw(bytes).map(|key| Self { key })
    }
    /// Exports this secret key to raw bytes, without any special formatting. Use [`Self::to_der`]
    /// if you need to export this key in a format that other programs can read.
    pub fn to_raw_bytes(&self) -> &[u8] {
        C::export_secret_key_raw(&self.key)
    }

    /// Imports the given DER-encoded bytes as a secret key.
    #[cfg(feature = "der")]
    pub fn from_der(der: &[u8]) -> Result<Self, C::IoError> {
        C::import_secret_key_der(der).map(|key| Self { key })
    }
    /// Exports this secret key to DER-encoded bytes. Use [`Self::to_raw_bytes`] if you don't need
    /// other programs to be able to read this key.
    #[cfg(feature = "der")]
    pub fn to_der(&self) -> Result<Vec<u8>, C::IoError> {
        C::export_secret_key_der(&self.key)
    }

    /// Imports the given PEM-encoded string as a secret key.
    #[cfg(feature = "pem")]
    pub fn from_pem(pem: &str) -> Result<Self, FromPemError<C::IoError>> {
        let pem = pem.trim();
        if !pem.starts_with("-----BEGIN PRIVATE KEY-----")
            || !pem.ends_with("-----END PRIVATE KEY-----")
        {
            return Err(FromPemError::InvalidFormat);
        }

        let pem = pem.strip_prefix("-----BEGIN PRIVATE KEY-----").unwrap();
        let pem = pem.strip_suffix("-----END PRIVATE KEY-----").unwrap();
        let base64 = pem.trim();

        let bytes =
            base64_to_bytes(&base64, false).map_err(|source| FromPemError::DecodeError(source))?;
        Self::from_raw_bytes(&bytes).map_err(|source| FromPemError::ConvertError(source))
    }
    /// Exports this secret key to a PEM-encoded string.
    #[cfg(feature = "pem")]
    pub fn to_pem(&self) -> Result<String, C::IoError> {
        let der_bytes = self.to_der();
        let base64 = bytes_to_base64(&der_bytes?, false);
        Ok(format!(
            "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----",
            base64
        ))
    }

    /// Imports the given hex string as a secret key. This expects a hex encoding of the raw secret
    /// key bytes, which is not the same as the hex encoding of the DER bytes!
    #[cfg(feature = "hex")]
    pub fn from_hex(hex: &str) -> Result<Self, FromHexError<C::IoError>> {
        let bytes = hex::decode(hex).map_err(|source| FromHexError::DecodeError(source))?;
        Self::from_raw_bytes(&bytes).map_err(|source| FromHexError::ConvertError(source))
    }
    /// Exports this secret key to a hex-encoded string. This is a hex encoding of the raw secret
    /// key bytes, and will not be readable by most other programs (consider [`Self::to_pem`]
    /// instead).
    #[cfg(feature = "hex")]
    pub fn to_hex(&self) -> String {
        let bytes = self.to_raw_bytes();
        hex::encode(bytes)
    }

    /// Imports the given base64 string as a secret key. This expects a base64 encoding of the raw
    /// secret key bytes, which is not the same as the base64 encoding of the DER bytes!
    #[cfg(feature = "base64")]
    pub fn from_base64(base64: &str, url_safe: bool) -> Result<Self, FromBase64Error<C::IoError>> {
        let bytes = base64_to_bytes(base64, url_safe)
            .map_err(|source| FromBase64Error::DecodeError(source))?;
        Self::from_raw_bytes(&bytes).map_err(|source| FromBase64Error::ConvertError(source))
    }
    /// Exports this secret key to a base64-encoded string. This is a base64 encoding of the raw
    /// secret key bytes, and will not be readable by most other programs (consider
    /// [`Self::to_pem`] instead).
    #[cfg(feature = "base64")]
    pub fn to_base64(&self, url_safe: bool) -> String {
        let bytes = self.to_raw_bytes();
        bytes_to_base64(bytes, url_safe)
    }
}

impl<C: SigningCryptosystem> SecretKey<C> {
    /// Signs the given message bytes with this secret key.
    pub fn sign_bytes(&self, msg: &[u8]) -> Result<C::Signature, C::Error> {
        C::sign(msg, &self.key)
    }
    /// Signs the given message with this secret key, first serializing the message to bytes with
    /// [`bincode`].
    ///
    /// Note that signing done this way is designed for verification by these same systems. If you
    /// need to sign data for another program, you should use some standardised way to convert
    /// your message to bytes, and then use [`Self::sign_bytes`] instead.
    #[cfg(feature = "serde")]
    pub fn sign<T: Serialize>(&self, msg: T) -> Result<C::Signature, CryptoError<C::Error>> {
        let msg_bytes = bincode::serialize(&msg)
            .map_err(|source| CryptoError::SerializationFailed { source })?;
        self.sign_bytes(&msg_bytes)
            .map_err(|source| CryptoError::ImplementationError { source })
    }
}

impl<C: KeyExchangeCryptosystem> SecretKey<C> {
    /// Generates a shared secret for communication with some other party, given their public key.
    /// This could then be used to seed a symmetric encryption key, for example.
    pub fn generate_shared_secret(
        &self,
        public_key: &PublicKey<C>,
    ) -> Result<C::SharedSecret, C::Error> {
        C::generate_shared_secret(&self.key, &public_key.key)
    }
}

impl<C: AsymmetricCryptosystem> SecretKey<C> {
    /// Decrypts the given ciphertext bytes with this secret key, returning the raw plaintext
    /// bytes.
    pub fn decrypt_bytes(&self, ciphertext: &[u8]) -> Result<Vec<u8>, C::Error> {
        C::decrypt(ciphertext, &self.key)
    }
    /// Decrypts the given ciphertext with this secret key, deserializing the resulting plaintext
    /// bytes into the provided type.
    ///
    /// Note that the deserialization this performs after decryption will likely only work with
    /// messages that were encrypted using these same systems, as [`bincode`]'s serialization
    /// format is not standardised.
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
