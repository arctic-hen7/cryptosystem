#[cfg(feature = "base64")]
use crate::base64_utils::{base64_to_bytes, bytes_to_base64};
#[cfg(feature = "base64")]
use crate::error::FromBase64Error;
#[cfg(feature = "hex")]
use crate::error::FromHexError;
#[cfg(feature = "pem")]
use crate::error::FromPemError;
use crate::CryptoError;
use crate::{
    cryptosystem::{PublicKeyCryptosystem, SigningCryptosystem},
    signature::Signature,
};
#[cfg(feature = "serde")]
use serde::Serialize;

/// A public key, which can be shared with the world to either encrypt messages to the holder of
/// the secret key, or to verify signatures which they have created. The capabilities of this key
/// depend on whether the type parameter `C` implements [`crate::SigningCryptosystem`],
/// [`crate::AsymmetricCryptosystem`], or both. (Public keys are essential for key exchange, but
/// have no operations performed on them beyond sending them to the other party, so implementing
/// [`KeyExchangeCryptosystem`] doesn't provide any additional capabilities for this type.)
pub struct PublicKey<C: PublicKeyCryptosystem> {
    pub(crate) key: C::PublicKey,
}

impl<C: PublicKeyCryptosystem> PublicKey<C> {
    /// Imports the given raw bytes as a public key. Use [`Self::from_der`] if these bytes are
    /// encoded as DER (if they've come from just about any other program, they probably are).
    pub fn from_raw_bytes(bytes: &[u8]) -> Result<Self, C::IoError> {
        C::import_public_key_raw(bytes).map(|key| Self { key })
    }
    /// Exports this public key to raw bytes, without any special formatting. Use [`Self::to_der`]
    /// if you need to export this key in a format that other programs can read.
    pub fn to_raw_bytes(&self) -> &[u8] {
        C::export_public_key_raw(&self.key)
    }

    /// Imports the given DER-encoded bytes as a public key. Use [`Self::from_raw_bytes`] if these
    /// bytes are not encoded as DER.
    #[cfg(feature = "der")]
    pub fn from_der(der: &[u8]) -> Result<Self, C::IoError> {
        C::import_public_key_der(der).map(|key| Self { key })
    }
    /// Exports this public key to DER-encoded bytes. Use [`Self::to_raw_bytes`] if you don't need
    /// other programs to be able to read this key.
    #[cfg(feature = "der")]
    pub fn to_der(&self) -> Result<Vec<u8>, C::IoError> {
        C::export_public_key_der(&self.key)
    }

    /// Imports the given PEM-encoded string as a public key.
    #[cfg(feature = "pem")]
    pub fn from_pem(pem: &str) -> Result<Self, FromPemError<C::IoError>> {
        let pem = pem.trim();
        if !pem.starts_with("-----BEGIN PUBLIC KEY-----")
            || !pem.ends_with("-----END PUBLIC KEY-----")
        {
            return Err(FromPemError::InvalidFormat);
        }

        let pem = pem.strip_prefix("-----BEGIN PUBLIC KEY-----").unwrap();
        let pem = pem.strip_suffix("-----END PUBLIC KEY-----").unwrap();
        let base64 = pem.trim();

        let bytes =
            base64_to_bytes(base64, false).map_err(FromPemError::DecodeError)?;
        Self::from_raw_bytes(&bytes).map_err(FromPemError::ConvertError)
    }
    /// Exports this public key to a PEM-encoded string.
    #[cfg(feature = "pem")]
    pub fn to_pem(&self) -> Result<String, C::IoError> {
        let der_bytes = self.to_der();
        let base64 = bytes_to_base64(&der_bytes?, false);
        Ok(format!(
            "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----",
            base64
        ))
    }

    /// Imports the given hex string as a public key. This expects a hex encoding of the raw public
    /// key bytes, which is not the same as the hex encoding of the DER bytes!
    #[cfg(feature = "hex")]
    pub fn from_hex(hex: &str) -> Result<Self, FromHexError<C::IoError>> {
        let bytes = hex::decode(hex).map_err(FromHexError::DecodeError)?;
        Self::from_raw_bytes(&bytes).map_err(FromHexError::ConvertError)
    }
    /// Exports this public key to a hex string. This is a hex encoding of the raw public key
    /// bytes, and will not be readable by most other programs (consider [`Self::to_pem`] instead).
    #[cfg(feature = "hex")]
    pub fn to_hex(&self) -> String {
        let bytes = self.to_raw_bytes();
        hex::encode(bytes)
    }

    /// Imports the given base64 string as a public key. This expects a base64 encoding of the raw
    /// public key bytes, which is not the same as the base64 encoding of the DER bytes!
    #[cfg(feature = "base64")]
    pub fn from_base64(base64: &str, url_safe: bool) -> Result<Self, FromBase64Error<C::IoError>> {
        let bytes = base64_to_bytes(base64, url_safe)
            .map_err(FromBase64Error::DecodeError)?;
        Self::from_raw_bytes(&bytes).map_err(FromBase64Error::ConvertError)
    }
    /// Exports this public key to a base64 string. This is a base64 encoding of the raw public key
    /// bytes, and will not be readable by most other programs (consider [`Self::to_pem`] instead).
    #[cfg(feature = "base64")]
    pub fn to_base64(&self, url_safe: bool) -> String {
        let bytes = self.to_raw_bytes();
        bytes_to_base64(bytes, url_safe)
    }
}

impl<C: SigningCryptosystem> PublicKey<C> {
    /// Verifies the given signature on the given message bytes, returning an error if the
    /// signature is invalid for any reason.
    pub fn verify_bytes(&self, signature: &Signature<C>, msg: &[u8]) -> Result<(), C::Error> {
        C::verify(signature.inner(), msg, &self.key)
    }
    /// Verifies the given signature on the given message, first serializing the message to bytes
    /// with [`bincode`]. If the signature was made with another program, or with a different
    /// serialization format, you should convert the message however the signer did and use
    /// [`Self::verify_bytes`] instead.
    #[cfg(feature = "serde")]
    pub fn verify<T: Serialize>(
        &self,
        signature: &Signature<C>,
        msg: T,
    ) -> Result<(), CryptoError<C::Error>> {
        let msg_bytes = bincode::serialize(&msg)
            .map_err(|source| CryptoError::SerializationFailed { source })?;
        C::verify(signature.inner(), &msg_bytes, &self.key)
            .map_err(|source| CryptoError::ImplementationError { source })
    }
}
