use super::{CompositeCryptosystem, CompositeError, CompositeIoError};
use crate::KeyEncapsulationCryptosystem;
use std::borrow::Cow;

const KDF_CONTEXT: &str = "cryptosystem::composites::key_encapsulation kdf";

impl<E1: KeyEncapsulationCryptosystem, E2: KeyEncapsulationCryptosystem>
    KeyEncapsulationCryptosystem for CompositeCryptosystem<E1, E2>
{
    type SharedSecret = [u8; 32];
    type Encapsulation = (E1::Encapsulation, E2::Encapsulation);
    type Error = CompositeError<
        <E1 as KeyEncapsulationCryptosystem>::Error,
        <E2 as KeyEncapsulationCryptosystem>::Error,
    >;
    type IoError = CompositeIoError<
        <E1 as KeyEncapsulationCryptosystem>::IoError,
        <E2 as KeyEncapsulationCryptosystem>::IoError,
    >;

    fn encapsulate(
        public_key: &Self::PublicKey,
    ) -> Result<(Self::Encapsulation, Self::SharedSecret), Self::Error> {
        let (encap_1, secret_1) = E1::encapsulate(&public_key.0).map_err(CompositeError::A)?;
        let (encap_2, secret_2) = E2::encapsulate(&public_key.1).map_err(CompositeError::B)?;

        let secret = blake3::derive_key(
            KDF_CONTEXT,
            &[
                &E1::export_shared_secret(&secret_1)[..],
                &E2::export_shared_secret(&secret_2)[..],
            ]
            .concat(),
        );

        Ok(((encap_1, encap_2), secret))
    }

    fn decapsulate(
        encapsulation: &Self::Encapsulation,
        secret_key: &Self::SecretKey,
    ) -> Result<Self::SharedSecret, Self::Error> {
        let secret1 =
            E1::decapsulate(&encapsulation.0, &secret_key.0).map_err(CompositeError::A)?;
        let secret2 =
            E2::decapsulate(&encapsulation.1, &secret_key.1).map_err(CompositeError::B)?;

        let secret = blake3::derive_key(
            KDF_CONTEXT,
            &[
                &E1::export_shared_secret(&secret1)[..],
                &E2::export_shared_secret(&secret2)[..],
            ]
            .concat(),
        );

        Ok(secret)
    }

    fn import_encapsulation(
        encapsulation: &[u8],
    ) -> Result<Self::Encapsulation, <Self as KeyEncapsulationCryptosystem>::IoError> {
        if encapsulation.len() < 4 {
            return Err(CompositeIoError::TooShort);
        }

        let key_1_len = u32::from_be_bytes(encapsulation[0..4].try_into().unwrap()) as usize;
        if encapsulation.len() < 4 + key_1_len {
            return Err(CompositeIoError::TooShort);
        }

        let key_1 = E1::import_encapsulation(&encapsulation[4..4 + key_1_len])
            .map_err(CompositeIoError::A)?;
        let key_2 = E2::import_encapsulation(&encapsulation[4 + key_1_len..])
            .map_err(CompositeIoError::B)?;

        Ok((key_1, key_2))
    }

    fn export_encapsulation(encapsulation: &Self::Encapsulation) -> Cow<'_, [u8]> {
        let encap_1 = E1::export_encapsulation(&encapsulation.0);
        let encap_2 = E2::export_encapsulation(&encapsulation.1);

        // Encode both into a buffer, declaring the first encap's length
        let mut buf = Vec::with_capacity(4 + encap_1.len() + encap_2.len());
        buf.extend_from_slice(&(encap_1.len() as u32).to_be_bytes());
        buf.extend_from_slice(&encap_1);
        buf.extend_from_slice(&encap_2);

        Cow::Owned(buf)
    }

    fn export_shared_secret(shared_secret: &Self::SharedSecret) -> Cow<'_, [u8]> {
        Cow::Borrowed(shared_secret)
    }
}
