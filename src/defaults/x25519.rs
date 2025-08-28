use crate::{
    key_encapsulation_cryptosystem_tests, KeyEncapsulationCryptosystem, PublicKeyCryptosystem,
};
use rand::rngs::OsRng;
use std::borrow::Cow;
use thiserror::Error;
use x25519_dalek::{PublicKey, StaticSecret};

/// A cryptosystem for key exchange using X25519.
///
/// Note: elliptic curve cryptography doesn't use direct asymmetric encryption like RSA, and
/// instead you should use this cryptosystem to derive a shared secret, and then you can use that
/// as a symmetric key.
#[derive(Clone, Copy, Debug)]
pub struct X25519Cryptosystem;
impl PublicKeyCryptosystem for X25519Cryptosystem {
    type PublicKey = PublicKey;
    type PublicKeyBytes = [u8; 32];
    type SecretKey = StaticSecret;
    type SecretKeyBytes = [u8; 32];
    type IoError = InvalidKeyLen;

    fn generate_keypair() -> (Self::PublicKey, Self::SecretKey) {
        let secret_key = StaticSecret::random_from_rng(OsRng);
        let public_key = PublicKey::from(&secret_key);

        (public_key, secret_key)
    }

    fn export_public_key_raw(key: &Self::PublicKey) -> Cow<'_, Self::PublicKeyBytes> {
        Cow::Borrowed(key.as_bytes())
    }
    fn import_public_key_raw(key: &Self::PublicKeyBytes) -> Result<Self::PublicKey, Self::IoError> {
        Ok(PublicKey::from(*key))
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

    fn export_secret_key_raw(key: &Self::SecretKey) -> Cow<'_, Self::SecretKeyBytes> {
        Cow::Borrowed(key.as_bytes())
    }
    fn import_secret_key_raw(key: &Self::SecretKeyBytes) -> Result<Self::SecretKey, Self::IoError> {
        Ok(StaticSecret::from(*key))
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
impl KeyEncapsulationCryptosystem for X25519Cryptosystem {
    // Need to use the raw bytes so we get cloning
    type SharedSecret = [u8; 32];
    type SharedSecretBytes = Self::SharedSecret;
    type Encapsulation = [u8; 32];
    type EncapsulationBytes = Self::Encapsulation;
    type Error = std::convert::Infallible;
    type IoError = InvalidEncapsulationLen;

    // Encapsulate by creating an ephemeral keypair and sending the public key
    fn encapsulate(
        public_key: &Self::PublicKey,
    ) -> Result<(Self::Encapsulation, Self::SharedSecret), Self::Error> {
        let ephemeral_secret_key = StaticSecret::random_from_rng(OsRng);
        let ephemeral_public_key = PublicKey::from(&ephemeral_secret_key);

        let shared_secret = ephemeral_secret_key.diffie_hellman(public_key).to_bytes();
        let encapsulation = ephemeral_public_key.as_bytes().to_owned();
        Ok((encapsulation, shared_secret))
    }

    // Then decapsulate with regular Diffie-Hellman
    fn decapsulate(
        encapsulation: &Self::Encapsulation,
        secret_key: &Self::SecretKey,
    ) -> Result<Self::SharedSecret, Self::Error> {
        // Any 32-byte slice is a valid public key: the encapsulation guarantees the length, so
        // this is safe
        let ephemeral_public_key = PublicKey::from(*encapsulation);
        Ok(secret_key.diffie_hellman(&ephemeral_public_key).to_bytes())
    }

    // Same as importing a public key (because we are)
    fn import_encapsulation(
        encapsulation: &Self::EncapsulationBytes,
    ) -> Result<Self::Encapsulation, <Self as KeyEncapsulationCryptosystem>::IoError> {
        Ok(encapsulation.to_owned())
    }

    fn export_encapsulation(
        encapsulation: &Self::Encapsulation,
    ) -> Cow<'_, Self::EncapsulationBytes> {
        Cow::Borrowed(encapsulation)
    }

    fn export_shared_secret(
        shared_secret: &Self::SharedSecret,
    ) -> Cow<'_, Self::SharedSecretBytes> {
        Cow::Borrowed(shared_secret)
    }
}

/// An invalid X25519 key length error.
#[derive(Error, Debug)]
#[error("invalid key length: {0}")]
pub struct InvalidKeyLen(pub usize);

/// An invalid X25519 encapsulation length error.
#[derive(Error, Debug)]
#[error("invalid encapsulation length: {0}")]
pub struct InvalidEncapsulationLen(pub usize);

key_encapsulation_cryptosystem_tests!(super::X25519Cryptosystem);
