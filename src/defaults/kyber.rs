use std::borrow::Cow;

use super::{InvalidEncapsulationLen, InvalidKeyLen};
use crate::{
    key_encapsulation_cryptosystem_tests, KeyEncapsulationCryptosystem, PublicKeyCryptosystem,
};
use ml_kem::{
    kem::{Decapsulate, DecapsulationKey, Encapsulate, EncapsulationKey},
    EncodedSizeUser, KemCore, MlKem1024, MlKem1024Params,
};
use rand::rngs::OsRng;

// Yeah...
const PUBLIC_KEY_LEN: usize = 1568;
const SECRET_KEY_LEN: usize = 3168;
const ENCAPSULATION_LEN: usize = 1568;

/// A Kyber public key (you should work with these through [`crate::PublicKey`]).
#[derive(Clone)]
pub struct KyberPublicKey {
    pub(crate) inner: EncapsulationKey<MlKem1024Params>,
    pub(crate) bytes: [u8; PUBLIC_KEY_LEN],
}

/// A Kyber secret key (you should work with these through [`crate::SecretKey`]).
#[derive(Clone)]
pub struct KyberSecretKey {
    pub(crate) inner: DecapsulationKey<MlKem1024Params>,
    pub(crate) bytes: [u8; SECRET_KEY_LEN],
}

/// A cryptosystem for key exchange using CRYSTALS-Kyber (standardised as ML-KEM under FIPS 203).
/// Formally, this is not the original Kyber, but the modified and enhanced Kyber that was
/// standardised by NIST.
///
/// Note: lattice cryptography doesn't use direct asymmetric encryption like RSA, and
/// instead you should use this cryptosystem to derive a shared secret, and then you can use that
/// as a symmetric key.
#[derive(Clone, Copy, Debug)]
pub struct KyberCryptosystem;
impl PublicKeyCryptosystem for KyberCryptosystem {
    type PublicKey = KyberPublicKey;
    type SecretKey = KyberSecretKey;
    type IoError = InvalidKeyLen;

    fn generate_keypair() -> (Self::PublicKey, Self::SecretKey) {
        let (dk, ek) = MlKem1024::generate(&mut OsRng);
        // NOTE: Key lengths are implicitly type-checked here
        let ek_bytes = ek.as_bytes().into();
        let dk_bytes = dk.as_bytes().into();

        // Encapsulation is public, decapsulation is secret
        (
            KyberPublicKey {
                inner: ek,
                bytes: ek_bytes,
            },
            KyberSecretKey {
                inner: dk,
                bytes: dk_bytes,
            },
        )
    }

    fn export_public_key_raw(key: &Self::PublicKey) -> Cow<'_, [u8]> {
        Cow::Borrowed(&key.bytes)
    }
    fn import_public_key_raw(key: &[u8]) -> Result<Self::PublicKey, Self::IoError> {
        let mut buf = [0u8; PUBLIC_KEY_LEN];
        if key.len() != buf.len() {
            return Err(InvalidKeyLen(key.len()));
        }
        buf.copy_from_slice(key);

        Ok(KyberPublicKey {
            inner: EncapsulationKey::from_bytes((&buf).into()),
            bytes: buf,
        })
    }

    #[cfg(feature = "der")]
    fn export_public_key_der(_key: &Self::PublicKey) -> Result<Vec<u8>, Self::IoError> {
        todo!("der support not yet implemented for kyber")
    }
    #[cfg(feature = "der")]
    fn import_public_key_der(_key: &[u8]) -> Result<Self::PublicKey, Self::IoError> {
        todo!("der support not yet implemented for kyber")
    }

    fn export_secret_key_raw(key: &Self::SecretKey) -> Cow<'_, [u8]> {
        Cow::Borrowed(&key.bytes)
    }
    fn import_secret_key_raw(key: &[u8]) -> Result<Self::SecretKey, Self::IoError> {
        let mut buf = [0u8; SECRET_KEY_LEN];
        if key.len() != buf.len() {
            return Err(InvalidKeyLen(key.len()));
        }
        buf.copy_from_slice(key);

        Ok(KyberSecretKey {
            inner: DecapsulationKey::from_bytes((&buf).into()),
            bytes: buf,
        })
    }

    #[cfg(feature = "der")]
    fn export_secret_key_der(_key: &Self::SecretKey) -> Result<Vec<u8>, Self::IoError> {
        todo!("der support not yet implemented for kyber")
    }
    #[cfg(feature = "der")]
    fn import_secret_key_der(_key: &[u8]) -> Result<Self::SecretKey, Self::IoError> {
        todo!("der support not yet implemented for kyber")
    }
}
impl KeyEncapsulationCryptosystem for KyberCryptosystem {
    // Need to use the raw bytes so we get cloning
    type SharedSecret = [u8; 32];
    type Encapsulation = [u8; ENCAPSULATION_LEN];
    type Error = std::convert::Infallible;
    type IoError = InvalidEncapsulationLen;

    fn encapsulate(
        public_key: &Self::PublicKey,
    ) -> Result<(Self::Encapsulation, Self::SharedSecret), Self::Error> {
        // NOTE: This is infallible in the code, but they use `()` to denote this
        let (encapsulation, shared_secret) = public_key.inner.encapsulate(&mut OsRng).unwrap();

        Ok((encapsulation.into(), shared_secret.into()))
    }

    fn decapsulate(
        encapsulation: &Self::Encapsulation,
        secret_key: &Self::SecretKey,
    ) -> Result<Self::SharedSecret, Self::Error> {
        Ok(secret_key
            .inner
            .decapsulate(encapsulation.into())
            // This is infallible, but can lead to just plain invalid secrets if used improperly
            .map(|shared_secret| shared_secret.into())
            .unwrap())
    }

    // Same as importing a public key (because we are)
    fn import_encapsulation(
        encapsulation: &[u8],
    ) -> Result<Self::Encapsulation, <Self as KeyEncapsulationCryptosystem>::IoError> {
        let mut buf = [0u8; ENCAPSULATION_LEN];
        if encapsulation.len() != buf.len() {
            return Err(InvalidEncapsulationLen(encapsulation.len()));
        }
        buf.copy_from_slice(encapsulation);

        Ok(buf)
    }

    fn export_encapsulation(encapsulation: &Self::Encapsulation) -> Cow<'_, [u8]> {
        Cow::Borrowed(encapsulation)
    }

    fn export_shared_secret(shared_secret: &Self::SharedSecret) -> Cow<'_, [u8]> {
        Cow::Borrowed(shared_secret)
    }
}

key_encapsulation_cryptosystem_tests!(super::KyberCryptosystem);
