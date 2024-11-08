use crate::crypto_io::CryptoExport;
use crate::cryptosystem::KeyExchangeCryptosystem;

/// A shared_secret on some message, produced by someone's secret key, and which can be verified by
/// the corresponding public key. This is a wrapper type over whatever the underlying
/// [`KeyExchangeCryptosystem`] considers a shared_secret, providing convenience methods around
/// exporting. Note that shared secrets cannot be imported.
#[derive(Clone)]
pub struct SharedSecret<C: KeyExchangeCryptosystem> {
    pub(crate) shared_secret: C::SharedSecret,
}
impl<C: KeyExchangeCryptosystem> CryptoExport for SharedSecret<C> {
    fn to_bytes(&self) -> &[u8] {
        C::export_shared_secret(&self.shared_secret)
    }
}
