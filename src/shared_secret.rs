use crate::crypto_io::CryptoExport;
use crate::cryptosystem::KeyEncapsulationCryptosystem;
use crate::CryptoImport;

/// A shared secret, produced by by encapsulating to the public key of a recipient (e.g. a server).
/// The sender immediately has the shared secret, and the recipient can decapsulate what was sent
/// to them with their secret key to derive the same thing.
///
/// This is a wrapper type over the underlying [`KeyEncapsulationCryptosystem`], providing
/// convenience methods for exporting. Note that shared secrets cannot be imported.
#[derive(Clone)]
pub struct SharedSecret<C: KeyEncapsulationCryptosystem> {
    pub(crate) shared_secret: C::SharedSecret,
}
impl<C: KeyEncapsulationCryptosystem> CryptoExport for SharedSecret<C> {
    fn to_bytes(&self) -> &[u8] {
        C::export_shared_secret(&self.shared_secret)
    }
}

/// An encapsulation of a shared secret. This is essentially the ciphertext of a message encrypted
/// to the public key of a party, such that they can decrypt it with their secret key, only the
/// message is random --- a shared secret.
///
/// An [`Encapsulation`] can be transformed into a [`SharedSecret`] with the recipient's secret
/// key.
#[derive(Clone)]
pub struct Encapsulation<C: KeyEncapsulationCryptosystem> {
    pub(crate) inner: C::Encapsulation,
}
impl<C: KeyEncapsulationCryptosystem> CryptoImport for Encapsulation<C> {
    type Error = <C as KeyEncapsulationCryptosystem>::IoError;

    fn from_bytes(bytes: &[u8]) -> Result<Self, Self::Error> {
        C::import_encapsulation(bytes).map(|inner| Self { inner })
    }
}
impl<C: KeyEncapsulationCryptosystem> CryptoExport for Encapsulation<C> {
    fn to_bytes(&self) -> &[u8] {
        C::export_encapsulation(&self.inner)
    }
}
