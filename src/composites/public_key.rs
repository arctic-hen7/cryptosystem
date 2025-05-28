use super::{CompositeCryptosystem, CompositeIoError};
use crate::PublicKeyCryptosystem;
use std::borrow::Cow;

impl<C1: PublicKeyCryptosystem, C2: PublicKeyCryptosystem> PublicKeyCryptosystem
    for CompositeCryptosystem<C1, C2>
{
    type PublicKey = (C1::PublicKey, C2::PublicKey);
    type SecretKey = (C1::SecretKey, C2::SecretKey);
    type IoError = CompositeIoError<
        <C1 as PublicKeyCryptosystem>::IoError,
        <C2 as PublicKeyCryptosystem>::IoError,
    >;

    fn generate_keypair() -> (Self::PublicKey, Self::SecretKey) {
        let (pk_1, sk_1) = C1::generate_keypair();
        let (pk_2, sk_2) = C2::generate_keypair();
        ((pk_1, pk_2), (sk_1, sk_2))
    }
    fn export_public_key_raw(key: &Self::PublicKey) -> Cow<'_, [u8]> {
        let key_1 = C1::export_public_key_raw(&key.0);
        let key_2 = C2::export_public_key_raw(&key.1);

        // Encode both into a buffer, declaring the first key's length
        let mut buf = Vec::with_capacity(4 + key_1.len() + key_2.len());
        buf.extend_from_slice(&(key_1.len() as u32).to_be_bytes());
        buf.extend_from_slice(&key_1);
        buf.extend_from_slice(&key_2);

        Cow::Owned(buf)
    }
    fn import_public_key_raw(key: &[u8]) -> Result<Self::PublicKey, Self::IoError> {
        if key.len() < 4 {
            return Err(CompositeIoError::TooShort);
        }

        let key_1_len = u32::from_be_bytes(key[0..4].try_into().unwrap()) as usize;
        if key.len() < 4 + key_1_len {
            return Err(CompositeIoError::TooShort);
        }

        let key_1 =
            C1::import_public_key_raw(&key[4..4 + key_1_len]).map_err(CompositeIoError::A)?;
        let key_2 =
            C2::import_public_key_raw(&key[4 + key_1_len..]).map_err(CompositeIoError::B)?;

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

    fn export_secret_key_raw(key: &Self::SecretKey) -> Cow<'_, [u8]> {
        let key_1 = C1::export_secret_key_raw(&key.0);
        let key_2 = C2::export_secret_key_raw(&key.1);

        // Encode both into a buffer, declaring the first key's length
        let mut buf = Vec::with_capacity(4 + key_1.len() + key_2.len());
        buf.extend_from_slice(&(key_1.len() as u32).to_be_bytes());
        buf.extend_from_slice(&key_1);
        buf.extend_from_slice(&key_2);

        Cow::Owned(buf)
    }
    fn import_secret_key_raw(key: &[u8]) -> Result<Self::SecretKey, Self::IoError> {
        if key.len() < 4 {
            return Err(CompositeIoError::TooShort);
        }

        let key_1_len = u32::from_be_bytes(key[0..4].try_into().unwrap()) as usize;
        if key.len() < 4 + key_1_len {
            return Err(CompositeIoError::TooShort);
        }

        let key_1 =
            C1::import_secret_key_raw(&key[4..4 + key_1_len]).map_err(CompositeIoError::A)?;
        let key_2 =
            C2::import_secret_key_raw(&key[4 + key_1_len..]).map_err(CompositeIoError::B)?;

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
