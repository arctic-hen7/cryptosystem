use crate::crypto_io::{CryptoDerExport, CryptoDerImport, CryptoExport, CryptoImport};
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
#[derive(Clone)]
pub struct PublicKey<C: PublicKeyCryptosystem> {
    pub(crate) key: C::PublicKey,
}

impl<C: PublicKeyCryptosystem> CryptoImport for PublicKey<C> {
    type Error = C::IoError;

    fn from_bytes(bytes: &[u8]) -> Result<Self, Self::Error> {
        C::import_public_key_raw(bytes).map(|key| Self { key })
    }
}
impl<C: PublicKeyCryptosystem> CryptoExport for PublicKey<C> {
    fn to_bytes(&self) -> &[u8] {
        C::export_public_key_raw(&self.key)
    }
}
#[cfg(feature = "der")]
impl<C: PublicKeyCryptosystem> CryptoDerImport for PublicKey<C> {
    fn from_der(der: &[u8]) -> Result<Self, C::IoError> {
        C::import_public_key_der(der).map(|key| Self { key })
    }
    #[cfg(feature = "pem")]
    fn pem_header() -> &'static str {
        "PUBLIC KEY"
    }
}
#[cfg(feature = "der")]
impl<C: PublicKeyCryptosystem> CryptoDerExport for PublicKey<C> {
    type Error = C::IoError;

    fn to_der(&self) -> Result<Vec<u8>, C::IoError> {
        C::export_public_key_der(&self.key)
    }
    #[cfg(feature = "pem")]
    fn pem_header() -> &'static str {
        "PUBLIC KEY"
    }
}

impl<C: SigningCryptosystem> PublicKey<C> {
    /// Verifies the given signature on the given message bytes, returning an error if the
    /// signature is invalid for any reason.
    pub fn verify_bytes(&self, signature: &Signature<C>, msg: &[u8]) -> Result<(), C::Error> {
        C::verify(&signature.signature, msg, &self.key)
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
        C::verify(&signature.signature, &msg_bytes, &self.key)
            .map_err(|source| CryptoError::ImplementationError { source })
    }
}
