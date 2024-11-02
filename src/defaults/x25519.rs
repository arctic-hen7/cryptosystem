use crate::{key_exchange_cryptosystem_tests, KeyExchangeCryptosystem, PublicKeyCryptosystem};
use rand::rngs::OsRng;
use thiserror::Error;
use x25519_dalek::{PublicKey, SharedSecret, StaticSecret};

/// A cryptosystem for key exchange using X25519.
///
/// Note: elliptic curve cryptography doesn't use direct asymmetric encryption like RSA, and
/// instead you should use this cryptosystem to derive a shared secret, and then you can use that
/// as a symmetric key.
pub struct X25519Cryptosystem;
impl PublicKeyCryptosystem for X25519Cryptosystem {
    type PublicKey = PublicKey;
    type SecretKey = StaticSecret;
    type IoError = X25519IoError;

    fn generate_keypair() -> (Self::PublicKey, Self::SecretKey) {
        let secret_key = StaticSecret::random_from_rng(&mut OsRng);
        let public_key = PublicKey::from(&secret_key);

        (public_key, secret_key)
    }

    fn export_public_key_raw(key: &Self::PublicKey) -> &[u8] {
        key.as_bytes()
    }
    fn import_public_key_raw(key: &[u8]) -> Result<Self::PublicKey, Self::IoError> {
        let mut buf = [0u8; 32];
        if key.len() != buf.len() {
            // We can borrow this error type, it's opaque anyway and byte length issues are
            // documented as a possible error source
            return Err(X25519IoError::InvalidKeyLen(key.len()));
        }
        buf.copy_from_slice(key);

        Ok(PublicKey::from(buf))
    }

    #[cfg(feature = "der")]
    fn export_public_key_der(_key: &Self::PublicKey) -> Result<Vec<u8>, Self::IoError> {
        todo!("der support not yet implemented for x25519")
    }
    #[cfg(feature = "der")]
    fn import_public_key_der(_key: &[u8]) -> Result<Self::PublicKey, Self::IoError> {
        todo!("der support not yet implemented for x25519")
    }

    // NOTE: Exporting secret keys is not recommended, as using ephemeral keys for key exchange is
    // *much* more secure.

    fn export_secret_key_raw(key: &Self::SecretKey) -> &[u8] {
        key.as_bytes()
    }
    fn import_secret_key_raw(key: &[u8]) -> Result<Self::SecretKey, Self::IoError> {
        let mut buf = [0u8; 32];
        if key.len() != buf.len() {
            // We can borrow this error type, it's opaque anyway and byte length issues are
            // documented as a possible error source
            return Err(X25519IoError::InvalidKeyLen(key.len()));
        }
        buf.copy_from_slice(key);

        Ok(StaticSecret::from(buf))
    }

    #[cfg(feature = "der")]
    fn export_secret_key_der(_key: &Self::SecretKey) -> Result<Vec<u8>, Self::IoError> {
        todo!("der support not yet implemented for x25519")
    }
    #[cfg(feature = "der")]
    fn import_secret_key_der(_key: &[u8]) -> Result<Self::SecretKey, Self::IoError> {
        todo!("der support not yet implemented for x25519")
    }
}
impl KeyExchangeCryptosystem for X25519Cryptosystem {
    type SharedSecret = SharedSecret;
    type Error = std::convert::Infallible;

    fn generate_shared_secret(
        secret_key: &Self::SecretKey,
        public_key: &Self::PublicKey,
    ) -> Result<Self::SharedSecret, Self::Error> {
        Ok(secret_key.diffie_hellman(public_key))
    }

    fn export_shared_secret(shared_secret: &Self::SharedSecret) -> &[u8] {
        shared_secret.as_bytes()
    }
}

/// Errors that can occur when importing X25519 keys.
#[derive(Error, Debug)]
pub enum X25519IoError {
    #[error("invalid key length: {0}")]
    InvalidKeyLen(usize),
}

key_exchange_cryptosystem_tests!(super::X25519Cryptosystem);
