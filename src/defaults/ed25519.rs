use crate::{
    cryptosystem::{PublicKeyCryptosystem, SigningCryptosystem},
    signing_cryptosystem_tests,
};
use ed25519_dalek::{Signature, SignatureError, Signer, SigningKey, Verifier, VerifyingKey};
use rand::{TryCryptoRng, TryRngCore};
use std::borrow::Cow;
use thiserror::Error;

/// A cryptosystem using Ed25519 for signing and verification.
#[derive(Clone, Copy, Debug)]
pub struct Ed25519Cryptosystem;
impl PublicKeyCryptosystem for Ed25519Cryptosystem {
    type PublicKey = VerifyingKey;
    type PublicKeyBytes = [u8; 32];
    type SecretKey = SigningKey;
    type SecretKeyBytes = [u8; 32];
    type IoError = Ed25519IoError;

    fn generate_keypair_from_rng<R: TryRngCore + TryCryptoRng>(
        rng: &mut R,
    ) -> Result<(Self::PublicKey, Self::SecretKey), R::Error> {
        // Downstream crate uses an old version of `rand`, so we generate the secret manually,
        // hwich is helpfully infallible
        let mut key_bytes = [0u8; 32];
        rng.try_fill_bytes(&mut key_bytes)?;
        let signing_key = SigningKey::from_bytes(&key_bytes);
        let verifying_key = signing_key.verifying_key();

        Ok((verifying_key, signing_key))
    }

    fn export_public_key_raw(key: &Self::PublicKey) -> Cow<'_, Self::PublicKeyBytes> {
        Cow::Borrowed(key.as_bytes())
    }
    fn import_public_key_raw(key: &Self::PublicKeyBytes) -> Result<Self::PublicKey, Self::IoError> {
        Ok(VerifyingKey::from_bytes(key)?)
    }

    #[cfg(feature = "der")]
    fn export_public_key_der(key: &Self::PublicKey) -> Result<Vec<u8>, Self::IoError> {
        use ed25519_dalek::pkcs8::EncodePublicKey;

        let document = key.to_public_key_der()?;
        Ok(document.to_vec())
    }
    #[cfg(feature = "der")]
    fn import_public_key_der(key: &[u8]) -> Result<Self::PublicKey, Self::IoError> {
        use ed25519_dalek::pkcs8::DecodePublicKey;

        Ok(VerifyingKey::from_public_key_der(key)?)
    }

    fn export_secret_key_raw(key: &Self::SecretKey) -> Cow<'_, Self::SecretKeyBytes> {
        Cow::Borrowed(key.as_bytes())
    }
    fn import_secret_key_raw(key: &Self::SecretKeyBytes) -> Result<Self::SecretKey, Self::IoError> {
        // Infallible
        Ok(SigningKey::from_bytes(&key))
    }

    #[cfg(feature = "der")]
    fn export_secret_key_der(key: &Self::SecretKey) -> Result<Vec<u8>, Self::IoError> {
        use ed25519_dalek::pkcs8::EncodePrivateKey;

        let document = key.to_pkcs8_der().unwrap();
        Ok(document.to_bytes().to_vec())
    }
    #[cfg(feature = "der")]
    fn import_secret_key_der(key: &[u8]) -> Result<Self::SecretKey, Self::IoError> {
        use ed25519_dalek::pkcs8::DecodePrivateKey;

        Ok(SigningKey::from_pkcs8_der(key)?)
    }
}
impl SigningCryptosystem for Ed25519Cryptosystem {
    // All byte sequences are valid signatures, and we need this to avooid lifetime issues with how
    // `ed25519_dalek` stores signature bytes internally.
    type Signature = [u8; 64];
    type SignatureBytes = Self::Signature;
    type Error = SignatureError;
    type IoError = InvalidSignatureLen;

    fn sign(msg: &[u8], key: &Self::SecretKey) -> Result<Self::Signature, Self::Error> {
        let signature = key.sign(msg);
        Ok(signature.to_bytes())
    }
    fn verify(
        signature: &Self::Signature,
        msg: &[u8],
        key: &Self::PublicKey,
    ) -> Result<(), Self::Error> {
        // Helpfully infallible!
        let signature = Signature::from_bytes(signature);
        // TODO: Should we be using `verify_strict` here? Malleability issues...
        key.verify(msg, &signature)
    }
    fn export_signature(signature: &Self::Signature) -> Cow<'_, Self::SignatureBytes> {
        Cow::Borrowed(signature)
    }
    fn import_signature(
        signature: &Self::SignatureBytes,
    ) -> Result<Self::Signature, <Self as SigningCryptosystem>::IoError> {
        Ok(signature.to_owned())
    }
}

#[derive(Error, Debug)]
pub enum Ed25519IoError {
    #[error("expected ed25519 key to be 32 bytes, but found {0}")]
    InvalidKeyLen(usize),
    #[error("failed to import key")]
    ImportFailed {
        #[from]
        source: SignatureError,
    },
    #[error("failed to import public key from der")]
    DerDecodePublicFailed {
        #[from]
        source: ed25519_dalek::pkcs8::spki::Error,
    },
    #[error("failed to import private key from der")]
    DerDecodePrivateFailed {
        #[from]
        source: ed25519_dalek::pkcs8::Error,
    },
}

#[derive(Error, Debug)]
#[error("expected signature to be 64 bytes, but found {0}")]
pub struct InvalidSignatureLen(usize);

signing_cryptosystem_tests!(super::Ed25519Cryptosystem);
