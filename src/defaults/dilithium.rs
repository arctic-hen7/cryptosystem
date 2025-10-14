use crate::{
    cryptosystem::{PublicKeyCryptosystem, SigningCryptosystem},
    signing_cryptosystem_tests,
};
use ml_dsa::{
    signature::{Signer, Verifier},
    KeyGen, MlDsa65, Signature, SigningKey, VerifyingKey,
};
use pkcs8::{DecodePublicKey, EncodePublicKey};
use rand::{rngs::OsRng, RngCore};
use std::borrow::Cow;
use thiserror::Error;

const PUBLIC_KEY_LEN: usize = 1952;
const SIGNATURE_LEN: usize = 3309;

/// A cryptosystem using CRYSTALS-Dilithium for signing and verification. By standards, this uses
/// ML-DSA 65, which provides an intermediate "level 3" security.
#[derive(Clone, Copy, Debug)]
pub struct DilithiumCryptosystem;
impl PublicKeyCryptosystem for DilithiumCryptosystem {
    type PublicKey = VerifyingKey<MlDsa65>;
    type PublicKeyBytes = [u8; PUBLIC_KEY_LEN];
    // We store both the *seed* of the secret key and the actual signing key for memory efficiency,
    // but we export the key as the seed (also needed for DER export)
    type SecretKey = ([u8; 32], SigningKey<MlDsa65>);
    type SecretKeyBytes = [u8; 32];
    type IoError = DilithiumIoError;

    fn generate_keypair() -> (Self::PublicKey, Self::SecretKey) {
        // This generation is the same as `MlDsa65::key_gen()` does internally, but we get to
        // extract the seed so we can use it ourselves
        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);
        // This is deterministic
        let keypair = MlDsa65::key_gen_internal(&seed.into());

        (
            keypair.verifying_key().clone(),
            (seed, keypair.signing_key().clone()),
        )
    }

    fn export_public_key_raw(key: &Self::PublicKey) -> Cow<'_, Self::PublicKeyBytes> {
        Cow::Owned(key.encode().into())
    }
    fn import_public_key_raw(key: &Self::PublicKeyBytes) -> Result<Self::PublicKey, Self::IoError> {
        // Infallible
        Ok(VerifyingKey::decode(key.into()))
    }

    #[cfg(feature = "der")]
    fn export_public_key_der(key: &Self::PublicKey) -> Result<Vec<u8>, Self::IoError> {
        let document = key.to_public_key_der()?;
        Ok(document.to_vec())
    }
    #[cfg(feature = "der")]
    fn import_public_key_der(key: &[u8]) -> Result<Self::PublicKey, Self::IoError> {
        Ok(VerifyingKey::from_public_key_der(key)?)
    }

    fn export_secret_key_raw(key: &Self::SecretKey) -> Cow<'_, Self::SecretKeyBytes> {
        Cow::Borrowed(&key.0)
    }
    fn import_secret_key_raw(
        seed: &Self::SecretKeyBytes,
    ) -> Result<Self::SecretKey, Self::IoError> {
        // Re-derive the full keypair from the seed (deterministic)
        let keypair = MlDsa65::key_gen_internal(seed.into());
        Ok((seed.clone(), keypair.signing_key().clone()))
    }

    #[cfg(feature = "der")]
    fn export_secret_key_der(key: &Self::SecretKey) -> Result<Vec<u8>, Self::IoError> {
        // This is copied from exactly how `KeyPair` is serialized to DER, using the seed as the
        // contents of the secret document
        use pkcs8::spki::AssociatedAlgorithmIdentifier;
        let pkcs8_key = pkcs8::PrivateKeyInfo::new(MlDsa65::ALGORITHM_IDENTIFIER, &key.0);
        let document = pkcs8::der::SecretDocument::encode_msg(&pkcs8_key).unwrap();

        Ok(document.to_bytes().to_vec())
    }
    #[cfg(feature = "der")]
    fn import_secret_key_der(key: &[u8]) -> Result<Self::SecretKey, Self::IoError> {
        use pkcs8::{spki::AssociatedAlgorithmIdentifier, PrivateKeyInfo};

        // This is copied from exactly how `KeyPair` is deserialized from DER, but we need to
        // extract the seed directly
        let private_key_info = PrivateKeyInfo::try_from(key)?;
        match private_key_info.algorithm {
            alg if alg == MlDsa65::ALGORITHM_IDENTIFIER => {}
            other => return Err(pkcs8::spki::Error::OidUnknown { oid: other.oid }.into()),
        }

        let seed: [u8; 32] = private_key_info
            .private_key
            .try_into()
            .map_err(|_| pkcs8::Error::KeyMalformed)?;
        // Re-derive the full keypair from the seed (deterministic)
        let keypair = MlDsa65::key_gen_internal(&seed.into());
        Ok((seed, keypair.signing_key().clone()))
    }
}
impl SigningCryptosystem for DilithiumCryptosystem {
    type Signature = Signature<MlDsa65>;
    type SignatureBytes = [u8; SIGNATURE_LEN];
    type Error = ml_dsa::Error;
    type IoError = InvalidSignature;

    fn sign(msg: &[u8], key: &Self::SecretKey) -> Result<Self::Signature, Self::Error> {
        let signature = key.1.sign(msg);
        Ok(signature)
    }
    fn verify(
        signature: &Self::Signature,
        msg: &[u8],
        key: &Self::PublicKey,
    ) -> Result<(), Self::Error> {
        key.verify(msg, &signature)
    }
    fn export_signature(signature: &Self::Signature) -> Cow<'_, Self::SignatureBytes> {
        Cow::Owned(signature.encode().into())
    }
    fn import_signature(
        signature: &Self::SignatureBytes,
    ) -> Result<Self::Signature, <Self as SigningCryptosystem>::IoError> {
        let signature = Signature::decode(signature.into()).ok_or(InvalidSignature)?;
        Ok(signature)
    }
}

#[derive(Error, Debug)]
pub enum DilithiumIoError {
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

// TODO: More descriptive error message; this happens when `z.infinity_norm() >=
// P::GAMMA1_MINUS_BETA`...I have no clue what that means...
#[derive(Error, Debug)]
#[error("found invalid dilithium signature")]
pub struct InvalidSignature;

signing_cryptosystem_tests!(super::DilithiumCryptosystem);
