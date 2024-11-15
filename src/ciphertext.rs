use crate::crypto_io::{CryptoExport, CryptoImport};

/// Ciphertext resulting from some kind of encryption. This is a wrapper over the raw bytes of the
/// ciphertext designed to facilitate easy conversion to other formats like hex and base64, as well
/// as serialization.
///
/// Note that [`Self::from_bytes`] will never fail.
#[derive(Clone)]
pub struct Ciphertext {
    pub(crate) inner: Vec<u8>,
}
impl CryptoImport for Ciphertext {
    type Error = std::convert::Infallible;

    fn from_bytes(bytes: &[u8]) -> Result<Self, Self::Error> {
        Ok(Self {
            inner: bytes.to_vec(),
        })
    }
}
impl CryptoExport for Ciphertext {
    fn to_bytes(&self) -> &[u8] {
        &self.inner
    }
}
impl From<Vec<u8>> for Ciphertext {
    fn from(value: Vec<u8>) -> Self {
        Self { inner: value }
    }
}
