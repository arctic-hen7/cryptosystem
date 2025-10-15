use super::{export_combination, import_combination, CompositeCryptosystem, CompositeIoError};
use crate::{crypto_array::CryptoArraySum, PublicKeyCryptosystem};
use std::borrow::Cow;

impl<C1: PublicKeyCryptosystem, C2: PublicKeyCryptosystem> PublicKeyCryptosystem
    for CompositeCryptosystem<C1, C2>
{
    type PublicKey = (C1::PublicKey, C2::PublicKey);
    type PublicKeyBytes = CryptoArraySum<C1::PublicKeyBytes, C2::PublicKeyBytes>;
    type SecretKey = (C1::SecretKey, C2::SecretKey);
    type SecretKeyBytes = CryptoArraySum<C1::SecretKeyBytes, C2::SecretKeyBytes>;
    type IoError = CompositeIoError<
        <C1 as PublicKeyCryptosystem>::IoError,
        <C2 as PublicKeyCryptosystem>::IoError,
    >;

    fn generate_keypair_from_rng<R: rand::TryRngCore + rand::TryCryptoRng>(
        rng: &mut R,
    ) -> Result<(Self::PublicKey, Self::SecretKey), R::Error> {
        let (pk_1, sk_1) = C1::generate_keypair_from_rng(rng)?;
        let (pk_2, sk_2) = C2::generate_keypair_from_rng(rng)?;
        Ok(((pk_1, pk_2), (sk_1, sk_2)))
    }
    fn export_public_key_raw(key: &Self::PublicKey) -> Cow<'_, Self::PublicKeyBytes> {
        let key_1 = C1::export_public_key_raw(&key.0);
        let key_2 = C2::export_public_key_raw(&key.1);

        Cow::Owned(export_combination(key_1.as_ref(), key_2.as_ref()))
    }
    fn import_public_key_raw(buf: &Self::PublicKeyBytes) -> Result<Self::PublicKey, Self::IoError> {
        let (key_1_bytes, key_2_bytes) = import_combination(buf)?;

        let key_1 = C1::import_public_key_raw(&key_1_bytes).map_err(CompositeIoError::A)?;
        let key_2 = C2::import_public_key_raw(&key_2_bytes).map_err(CompositeIoError::B)?;

        Ok((key_1, key_2))
    }

    #[cfg(feature = "der")]
    fn export_public_key_der(_key: &Self::PublicKey) -> Result<Vec<u8>, Self::IoError> {
        todo!("der support not yet implemented for composites")
    }
    #[cfg(feature = "der")]
    fn import_public_key_der(_key: &[u8]) -> Result<Self::PublicKey, Self::IoError> {
        todo!("der support not yet implemented for composites")
    }

    fn export_secret_key_raw(key: &Self::SecretKey) -> Cow<'_, Self::SecretKeyBytes> {
        let key_1 = C1::export_secret_key_raw(&key.0);
        let key_2 = C2::export_secret_key_raw(&key.1);

        Cow::Owned(export_combination(key_1.as_ref(), key_2.as_ref()))
    }
    fn import_secret_key_raw(buf: &Self::SecretKeyBytes) -> Result<Self::SecretKey, Self::IoError> {
        let (key_1_bytes, key_2_bytes) = import_combination(buf)?;

        let key_1 = C1::import_secret_key_raw(&key_1_bytes).map_err(CompositeIoError::A)?;
        let key_2 = C2::import_secret_key_raw(&key_2_bytes).map_err(CompositeIoError::B)?;

        Ok((key_1, key_2))
    }

    #[cfg(feature = "der")]
    fn export_secret_key_der(_key: &Self::SecretKey) -> Result<Vec<u8>, Self::IoError> {
        todo!("der support not yet implemented for composites")
    }
    #[cfg(feature = "der")]
    fn import_secret_key_der(_key: &[u8]) -> Result<Self::SecretKey, Self::IoError> {
        todo!("der support not yet implemented for composites")
    }
}
