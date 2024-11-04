use crate::crypto_io::{CryptoDerIo, CryptoIo};
use crate::cryptosystem::KeyExchangeCryptosystem;
use crate::CryptoError;
use crate::{
    cryptosystem::{PublicKeyCryptosystem, SigningCryptosystem},
    PublicKey,
};
#[cfg(feature = "serde")]
use serde::Serialize;

/// A secret key, which should be kept secret by some party to either decrypt messages encrypted by
/// others for them with their public key, or to create signatures on messages that will be
/// verifiable by others with their public key. The capabilities of this key depend on whether the
/// type parameter `C` implements [`crate::SigningCryptosystem`],
/// [`crate::AsymmetricCryptosystem`], [`crate::KeyExchangeCryptosystem`], or some combination of
/// the three.
#[derive(Clone)]
pub struct SecretKey<C: PublicKeyCryptosystem> {
    key: C::SecretKey,
}
impl<C: PublicKeyCryptosystem> CryptoIo for SecretKey<C> {
    type Error = C::IoError;

    fn from_bytes(bytes: &[u8]) -> Result<Self, Self::Error> {
        C::import_secret_key_raw(bytes).map(|key| Self { key })
    }
    fn to_bytes(&self) -> &[u8] {
        C::export_secret_key_raw(&self.key)
    }
}
#[cfg(feature = "der")]
impl<C: PublicKeyCryptosystem> CryptoDerIo for SecretKey<C> {
    fn from_der(der: &[u8]) -> Result<Self, Self::Error> {
        C::import_secret_key_der(der).map(|key| Self { key })
    }
    fn to_der(&self) -> Result<Vec<u8>, Self::Error> {
        C::export_secret_key_der(&self.key)
    }
    #[cfg(feature = "pem")]
    fn pem_header() -> &'static str {
        "PRIVATE KEY"
    }
}

impl<C: PublicKeyCryptosystem> SecretKey<C> {
    /// Generates a new asymmetric keypair of a public key and secret key.
    pub fn generate_keypair() -> (PublicKey<C>, Self) {
        let (pubkey, key) = C::generate_keypair();
        (PublicKey { key: pubkey }, Self { key })
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
