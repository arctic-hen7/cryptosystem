use crate::crypto_io::{CryptoExport, CryptoImport};
use crate::cryptosystem::SigningCryptosystem;

/// A signature on some message, produced by someone's secret key, and which can be verified by the
/// corresponding public key. This is a wrapper type over whatever the underlying
/// [`SigningCryptosystem`] considers a signature, providing convenience methods around importing
/// and exporting.
#[derive(Clone)]
pub struct Signature<C: SigningCryptosystem> {
    pub(crate) signature: C::Signature,
}
impl<C: SigningCryptosystem> CryptoImport for Signature<C> {
    type Error = <C as SigningCryptosystem>::IoError;

    fn from_bytes(bytes: &[u8]) -> Result<Self, Self::Error> {
        C::import_signature(bytes).map(|signature| Self { signature })
    }
}
impl<C: SigningCryptosystem> CryptoExport for Signature<C> {
    fn to_bytes(&self) -> &[u8] {
        C::export_signature(&self.signature)
    }
}
