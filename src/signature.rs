#[cfg(feature = "base64")]
use crate::base64_utils::{base64_to_bytes, bytes_to_base64};
use crate::{
    cryptosystem::SigningCryptosystem,
    error::{FromBase64Error, FromHexError},
};

/// A signature on some message, produced by someone's secret key, and which can be verified by the
/// corresponding public key. This is a wrapper type over whatever the underlying
/// [`SigningCryptosystem`] considers a signature, providing convenience methods around importing
/// and exporting.
pub struct Signature<C: SigningCryptosystem> {
    signature: C::Signature,
}
impl<C: SigningCryptosystem> Signature<C> {
    /// Imports the given bytes as a signature.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, <C as SigningCryptosystem>::IoError> {
        C::import_signature(bytes).map(|signature| Self { signature })
    }
    /// Exports this signature to bytes.
    pub fn to_bytes(&self) -> &[u8] {
        C::export_signature(&self.signature)
    }

    /// Imports the given hex-encoded string as a signature.
    #[cfg(feature = "hex")]
    pub fn from_hex(hex: &str) -> Result<Self, FromHexError<<C as SigningCryptosystem>::IoError>> {
        let bytes = hex::decode(hex).map_err(FromHexError::DecodeError)?;
        Self::from_bytes(&bytes).map_err(FromHexError::ConvertError)
    }
    /// Exports this signature to a hex-encoded string.
    #[cfg(feature = "hex")]
    pub fn to_hex(&self) -> String {
        let bytes = self.to_bytes();
        hex::encode(bytes)
    }

    /// Imports the given base64-encoded string as a signature.
    #[cfg(feature = "base64")]
    pub fn from_base64(
        base64: &str,
        url_safe: bool,
    ) -> Result<Self, FromBase64Error<<C as SigningCryptosystem>::IoError>> {
        let bytes = base64_to_bytes(base64, url_safe)
            .map_err(FromBase64Error::DecodeError)?;
        Self::from_bytes(&bytes).map_err(FromBase64Error::ConvertError)
    }
    /// Exports this signature to a base64-encoded string.
    #[cfg(feature = "base64")]
    pub fn to_base64(&self, url_safe: bool) -> String {
        let bytes = self.to_bytes();
        bytes_to_base64(bytes, url_safe)
    }

    /// Gets the inner cryptosystem's signature.
    pub(crate) fn inner(&self) -> &C::Signature {
        &self.signature
    }
}
