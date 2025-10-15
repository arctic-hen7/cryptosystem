use crate::crypto_io::{CryptoDerExport, CryptoDerImport, CryptoExport, CryptoImport};
use crate::shared_secret::Encapsulation;
use crate::{
    cryptosystem::{PublicKeyCryptosystem, SigningCryptosystem},
    signature::Signature,
};
use crate::{CryptoError, KeyEncapsulationCryptosystem, SharedSecret};
use rand::{TryCryptoRng, TryRngCore};
#[cfg(feature = "serde")]
use serde::Serialize;
use std::borrow::Cow;

/// A public key, which can be shared with the world to either encrypt messages to the holder of
/// the secret key, or to verify signatures which they have created. The capabilities of this key
/// depend on whether the type parameter `C` implements [`crate::SigningCryptosystem`],
/// [`crate::AsymmetricCryptosystem`], or both. (Public keys are essential for key exchange, but
/// have no operations performed on them beyond sending them to the other party, so implementing
/// [`KeyExchangeCryptosystem`] doesn't provide any additional capabilities for this type.)
#[derive(Clone)]
pub struct PublicKey<C: PublicKeyCryptosystem> {
    pub(crate) key: C::PublicKey,
}

impl<C: PublicKeyCryptosystem> CryptoImport for PublicKey<C> {
    type Bytes = C::PublicKeyBytes;
    type Error = C::IoError;

    fn from_bytes_exact(bytes: &Self::Bytes) -> Result<Self, Self::Error> {
        C::import_public_key_raw(bytes).map(|key| Self { key })
    }
}
impl<C: PublicKeyCryptosystem> CryptoExport for PublicKey<C> {
    type Output = C::PublicKeyBytes;

    fn to_bytes(&self) -> Cow<'_, Self::Output> {
        C::export_public_key_raw(&self.key)
    }
}
#[cfg(feature = "der")]
impl<C: PublicKeyCryptosystem> CryptoDerImport for PublicKey<C> {
    fn from_der(der: &[u8]) -> Result<Self, C::IoError> {
        C::import_public_key_der(der).map(|key| Self { key })
    }
    #[cfg(feature = "pem")]
    fn pem_header() -> &'static str {
        "PUBLIC KEY"
    }
}
#[cfg(feature = "der")]
impl<C: PublicKeyCryptosystem> CryptoDerExport for PublicKey<C> {
    type Error = C::IoError;

    fn to_der(&self) -> Result<Vec<u8>, C::IoError> {
        C::export_public_key_der(&self.key)
    }
    #[cfg(feature = "pem")]
    fn pem_header() -> &'static str {
        "PUBLIC KEY"
    }
}

impl<C: SigningCryptosystem> PublicKey<C> {
    /// Verifies the given signature on the given message bytes, returning an error if the
    /// signature is invalid for any reason.
    pub fn verify_bytes(&self, signature: &Signature<C>, msg: &[u8]) -> Result<(), C::Error> {
        C::verify(&signature.signature, msg, &self.key)
    }
    /// Verifies the given signature on the given message, first serializing the message to bytes
    /// with [`bincode`]. If the signature was made with another program, or with a different
    /// serialization format, you should convert the message however the signer did and use
    /// [`Self::verify_bytes`] instead.
    #[cfg(feature = "serde")]
    pub fn verify<T: Serialize>(
        &self,
        signature: &Signature<C>,
        msg: T,
    ) -> Result<(), CryptoError<C::Error>> {
        let msg_bytes = bincode::serialize(&msg)
            .map_err(|source| CryptoError::SerializationFailed { source })?;
        C::verify(&signature.signature, &msg_bytes, &self.key)
            .map_err(|source| CryptoError::ImplementationError { source })
    }
}

impl<C: KeyEncapsulationCryptosystem> PublicKey<C> {
    /// Encapsulates a random shared secret to this public key (such that the owner will be able to
    /// decapsulate it with their secret key). This is similar to encrypting a message to someone's
    /// public key, except the message is random (a shared secret), and is returned by this
    /// function. When the other party "decapsulates", they will get the same shared secret, which
    /// can be used as a symmetric key.
    ///
    /// This function takes a source of randomness, if you want to provide one. If you don't need
    /// to control the randomness (most use-cases), you should use [`Self::encapsulate`] instead.
    /// The outer error this function returns propagates any errors in getting randomness, and the
    /// inner one any errors in the actual encapsulation process.
    pub fn encapsulate_with_rng<R: TryRngCore + TryCryptoRng>(
        &self,
        rng: &mut R,
    ) -> Result<Result<(Encapsulation<C>, SharedSecret<C>), C::Error>, R::Error> {
        let (encapsulation, shared_secret) = match C::encapsulate_with_rng(&self.key, rng) {
            Ok(Ok(x)) => x,
            Ok(Err(err)) => return Ok(Err(err)),
            Err(rand_err) => return Err(rand_err),
        };

        Ok(Ok((
            Encapsulation {
                inner: encapsulation,
            },
            SharedSecret { shared_secret },
        )))
    }

    /// Encapsulates a random shared secret to this public key (such that the owner will be able to
    /// decapsulate it with their secret key). This is similar to encrypting a message to someone's
    /// public key, except the message is random (a shared secret), and is returned by this
    /// function. When the other party "decapsulates", they will get the same shared secret, which
    /// can be used as a symmetric key.
    ///
    /// # Panics
    ///
    /// This uses [`OsRng`] to generate randomness, and will panic if getting random values fails.
    pub fn encapsulate(&self) -> Result<(Encapsulation<C>, SharedSecret<C>), C::Error> {
        let (encapsulation, shared_secret) = C::encapsulate(&self.key)?;

        Ok((
            Encapsulation {
                inner: encapsulation,
            },
            SharedSecret { shared_secret },
        ))
    }
}
