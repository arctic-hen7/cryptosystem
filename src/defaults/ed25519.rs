use crate::{
    cryptosystem::{PublicKeyCryptosystem, SigningCryptosystem},
    signing_cryptosystem_tests,
};
use ed25519_dalek::{Signature, SignatureError, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use thiserror::Error;

/// A cryptosystem using Ed25519 for signing and verification.
pub struct Ed25519Cryptosystem;
impl PublicKeyCryptosystem for Ed25519Cryptosystem {
    type PublicKey = VerifyingKey;
    type SecretKey = SigningKey;
    type IoError = Ed25519IoError;

    fn generate_keypair() -> (Self::PublicKey, Self::SecretKey) {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();

        (verifying_key, signing_key)
    }

    fn export_public_key_raw(key: &Self::PublicKey) -> &[u8] {
        key.as_bytes()
    }
    fn import_public_key_raw(key: &[u8]) -> Result<Self::PublicKey, Self::IoError> {
        let mut buf = [0u8; 32];
        if key.len() != buf.len() {
            // We can borrow this error type, it's opaque anyway and byte length issues are
            // documented as a possible error source
            return Err(Ed25519IoError::InvalidKeyLen(key.len()));
        }
        buf.copy_from_slice(key);
        Ok(VerifyingKey::from_bytes(&buf)?)
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

    fn export_secret_key_raw(key: &Self::SecretKey) -> &[u8] {
        key.as_bytes()
    }
    fn import_secret_key_raw(key: &[u8]) -> Result<Self::SecretKey, Self::IoError> {
        let mut buf = [0u8; 32];
        if key.len() != buf.len() {
            // We can borrow this error type, it's opaque anyway and byte length issues are
            // documented as a possible error source
            return Err(Ed25519IoError::InvalidKeyLen(key.len()));
        }
        buf.copy_from_slice(key);
        // Infallible
        Ok(SigningKey::from_bytes(&buf))
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
    fn export_signature(signature: &Self::Signature) -> &[u8] {
        signature.as_ref()
    }
    fn import_signature(
        signature: &[u8],
    ) -> Result<Self::Signature, <Self as SigningCryptosystem>::IoError> {
        // Any 64 bytes are a valid signature, so we just need to make sure we have 64 bytes
        let mut buf = [0u8; 64];
        if signature.len() != buf.len() {
            return Err(InvalidSignatureLen(signature.len()));
        }
        buf.copy_from_slice(signature);

        Ok(buf)
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
