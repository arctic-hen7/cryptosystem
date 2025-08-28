use super::{
    export_combination, import_combination, CompositeCryptosystem, CompositeError, CompositeIoError,
};
use crate::{crypto_array::CryptoArraySum, KeyEncapsulationCryptosystem};
use std::borrow::Cow;

const KDF_CONTEXT: &str = "cryptosystem::composites::key_encapsulation kdf";

impl<E1: KeyEncapsulationCryptosystem, E2: KeyEncapsulationCryptosystem>
    KeyEncapsulationCryptosystem for CompositeCryptosystem<E1, E2>
{
    // Shared secrets are KDFed into one 32-byte key
    type SharedSecret = [u8; 32];
    type SharedSecretBytes = Self::SharedSecret;
    // But encapsulations we need to combine
    type Encapsulation = (E1::Encapsulation, E2::Encapsulation);
    type EncapsulationBytes = CryptoArraySum<E1::EncapsulationBytes, E2::EncapsulationBytes>;
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
                E1::export_shared_secret(&secret_1).as_ref().as_ref(),
                E2::export_shared_secret(&secret_2).as_ref().as_ref(),
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
                E1::export_shared_secret(&secret1).as_ref().as_ref(),
                E2::export_shared_secret(&secret2).as_ref().as_ref(),
            ]
            .concat(),
        );

        Ok(secret)
    }

    fn import_encapsulation(
        buf: &Self::EncapsulationBytes,
    ) -> Result<Self::Encapsulation, <Self as KeyEncapsulationCryptosystem>::IoError> {
        let (encap_1_bytes, encap_2_bytes) = import_combination(buf)?;

        let encap_1 = E1::import_encapsulation(&encap_1_bytes).map_err(CompositeIoError::A)?;
        let encap_2 = E2::import_encapsulation(&encap_2_bytes).map_err(CompositeIoError::B)?;

        Ok((encap_1, encap_2))
    }

    fn export_encapsulation(
        encapsulation: &Self::Encapsulation,
    ) -> Cow<'_, Self::EncapsulationBytes> {
        let encap_1 = E1::export_encapsulation(&encapsulation.0);
        let encap_2 = E2::export_encapsulation(&encapsulation.1);

        Cow::Owned(export_combination(encap_1.as_ref(), encap_2.as_ref()))
    }

    fn export_shared_secret(
        shared_secret: &Self::SharedSecret,
    ) -> Cow<'_, Self::SharedSecretBytes> {
        Cow::Borrowed(shared_secret)
    }
}
