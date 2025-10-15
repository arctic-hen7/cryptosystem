use super::{InvalidEncapsulationLen, InvalidKeyLen};
use crate::{
    key_encapsulation_cryptosystem_tests, KeyEncapsulationCryptosystem, PublicKeyCryptosystem,
};
use ml_kem::{
    kem::{Decapsulate, DecapsulationKey, EncapsulationKey},
    EncapsulateDeterministic, EncodedSizeUser, KemCore, MlKem512, MlKem512Params,
};
use rand::{TryCryptoRng, TryRngCore};
use std::borrow::Cow;

// Yeah...
const PUBLIC_KEY_LEN: usize = 800;
const SECRET_KEY_LEN: usize = 1632;
const ENCAPSULATION_LEN: usize = 768;

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
    type PublicKey = EncapsulationKey<MlKem512Params>;
    type PublicKeyBytes = [u8; PUBLIC_KEY_LEN];
    type SecretKey = DecapsulationKey<MlKem512Params>;
    type SecretKeyBytes = [u8; SECRET_KEY_LEN];
    type IoError = InvalidKeyLen;

    fn generate_keypair_from_rng<R: rand::TryRngCore + rand::TryCryptoRng>(
        rng: &mut R,
    ) -> Result<(Self::PublicKey, Self::SecretKey), R::Error> {
        // We can generate the parameters manually with our version of `rand` and then pass them
        // in. This is the only thing we need `deterministic` on `ml_kem` for.
        let mut d = [0u8; 32];
        let mut z = [0u8; 32];
        rng.try_fill_bytes(&mut d)?;
        rng.try_fill_bytes(&mut z)?;

        // Yes, this cooked reference-then-convert is the best `hybrid_array` gives us ;)
        let (dk, ek) = MlKem512::generate_deterministic((&d).into(), (&z).into());

        // Encapsulation is public, decapsulation is secret
        Ok((ek, dk))
    }

    fn export_public_key_raw(key: &Self::PublicKey) -> Cow<'_, Self::PublicKeyBytes> {
        Cow::Owned(key.as_bytes().into())
    }
    fn import_public_key_raw(key: &Self::PublicKeyBytes) -> Result<Self::PublicKey, Self::IoError> {
        Ok(EncapsulationKey::from_bytes(key.into()))
    }

    #[cfg(feature = "der")]
    fn export_public_key_der(_key: &Self::PublicKey) -> Result<Vec<u8>, Self::IoError> {
        todo!("der support not yet implemented for kyber")
    }
    #[cfg(feature = "der")]
    fn import_public_key_der(_key: &[u8]) -> Result<Self::PublicKey, Self::IoError> {
        todo!("der support not yet implemented for kyber")
    }

    fn export_secret_key_raw(key: &Self::SecretKey) -> Cow<'_, Self::SecretKeyBytes> {
        Cow::Owned(key.as_bytes().into())
    }
    fn import_secret_key_raw(key: &Self::SecretKeyBytes) -> Result<Self::SecretKey, Self::IoError> {
        Ok(DecapsulationKey::from_bytes(key.into()))
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
    type SharedSecretBytes = Self::SharedSecret;
    type Encapsulation = [u8; ENCAPSULATION_LEN];
    type EncapsulationBytes = Self::Encapsulation;
    type Error = std::convert::Infallible;
    type IoError = InvalidEncapsulationLen;

    fn encapsulate_with_rng<R: TryRngCore + TryCryptoRng>(
        public_key: &Self::PublicKey,
        rng: &mut R,
    ) -> Result<Result<(Self::Encapsulation, Self::SharedSecret), Self::Error>, R::Error> {
        // NOTE: This is infallible in the code, but they use `()` to denote this
        let mut m = [0u8; 32];
        rng.try_fill_bytes(&mut m)?;
        let (encapsulation, shared_secret) =
            public_key.encapsulate_deterministic((&m).into()).unwrap();

        Ok(Ok((encapsulation.into(), shared_secret.into())))
    }

    fn decapsulate(
        encapsulation: &Self::Encapsulation,
        secret_key: &Self::SecretKey,
    ) -> Result<Self::SharedSecret, Self::Error> {
        Ok(secret_key
            .decapsulate(encapsulation.into())
            // This is infallible, but can lead to just plain invalid secrets if used improperly
            .map(|shared_secret| shared_secret.into())
            .unwrap())
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

key_encapsulation_cryptosystem_tests!(super::KyberCryptosystem);
