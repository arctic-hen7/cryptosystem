#[cfg(feature = "serde")]
use crate::error::CryptoError;
use crate::{
    crypto_array::{
        CryptoArrayDiff, CryptoArrayDiffLen, CryptoArraySum, CryptoArraySumLen, CryptoBuffer,
        OwnedHasCryptoLen,
    },
    crypto_io::{CryptoExport, CryptoImport},
    SymmetricCryptosystem,
};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use std::borrow::Cow;

/// A symmetric key, which can be used to encrypt and decrypt messages.
#[derive(Clone)]
pub struct SymmetricKey<C: SymmetricCryptosystem> {
    key: C::Key,
}
impl<C: SymmetricCryptosystem> CryptoImport for SymmetricKey<C> {
    type Bytes = C::KeyBytes;
    type Error = C::IoError;

    fn from_bytes_exact(bytes: &Self::Bytes) -> Result<Self, Self::Error> {
        C::import_key(bytes).map(|key| Self { key })
    }
}
impl<C: SymmetricCryptosystem> CryptoExport for SymmetricKey<C> {
    type Output = C::KeyBytes;

    fn to_bytes(&self) -> Cow<'_, Self::Output> {
        C::export_key(&self.key)
    }
}
impl<C: SymmetricCryptosystem> SymmetricKey<C> {
    /// Generates a new symmetric key.
    pub fn generate() -> Self {
        Self {
            key: C::generate_key(),
        }
    }

    /// Encrypts the given bytes with this symmetric key, writing the result to the given buffer.
    ///
    /// This method is written somewhat oddly with [`CryptoArray`] to allow it to take both
    /// fixed-length and variable-length collections of bytes. If the symmetric system you're
    /// working with has a known fixed overhead length, providing `&[u8; N]` as your plaintext here
    /// will give you `&[u8; N + O]` as your ciphertext, where `O` is the overhead length.
    /// Alternately, providing `&Vec<u8>` or `&[u8]` will give you a `Vec<u8>` as the ciphertext.
    ///
    /// The buffer you provide for the ciphertext to be written to must be the correct fixed size
    /// if both the plaintext and overhead are fixed-length, or it can be a `Vec<u8>` otherwise.
    /// You can create the right kind of buffer in a type-agnostic way with `LengthSum<P::Owned,
    /// C::OverheadBytes>::zeroed()`.
    pub fn encrypt_to_buf<P: OwnedHasCryptoLen + ?Sized, B: OwnedHasCryptoLen + ?Sized>(
        &self,
        msg: &P,
        buf: &mut B, // buf: &mut CryptoArraySum<P::Owned, Self::OverheadBytes>,
    ) -> Result<(), C::Error>
    where
        <B as OwnedHasCryptoLen>::Owned:
            CryptoBuffer<CryptoArraySumLen<P::Owned, C::OverheadBytes>>,
    {
        // This method should set the size appropriately based on what it needs, if any component
        // is variable-length
        C::encrypt_to_buf(msg, &self.key, buf)
    }

    /// Decrypts the given ciphertext bytes with this symmetric key, writing the result to the
    /// given buffer.
    ///
    /// This method is written somewhat oddly with [`CryptoArray`] to allow it to take both
    /// fixed-length and variable-length collections of bytes. If the symmetric system you're
    /// working with has a known fixed overhead length, providing `&[u8; N]` as your ciphertext here
    /// will give you `&[u8; N - O]` as your ciphertext, where `O` is the overhead length.
    /// Alternately, providing `&Vec<u8>` or `&[u8]` will give you a `Vec<u8>` as the ciphertext.
    ///
    /// The buffer you provide for the ciphertext to be written to must be the correct fixed size
    /// if both the plaintext and overhead are fixed-length, or it can be a `Vec<u8>` otherwise.
    /// You can create the right kind of buffer in a type-agnostic way with `LengthSum<P::Owned,
    /// C::OverheadBytes>::zeroed()`.
    pub fn decrypt_to_buf<X: OwnedHasCryptoLen + ?Sized, B: OwnedHasCryptoLen + ?Sized>(
        &self,
        ciphertext: &X,
        buf: &mut B,
    ) -> Result<(), C::Error>
    where
        <B as OwnedHasCryptoLen>::Owned:
            CryptoBuffer<CryptoArrayDiffLen<X::Owned, C::OverheadBytes>>,
    {
        // This method should set the size appropriately based on what it needs, if any component
        // is variable-length
        C::decrypt_to_buf(ciphertext, &self.key, buf)
    }

    /// Encrypts the given bytes with this key, returning the ciphertext. Providing fixed-length
    /// plaintext to this method will give you a fixed-length output when you use a cryptosystem
    /// that has a fixed overhead length, and otherwise you'll get a `Vec<u8>`. See
    /// [`Self::encrypt_to_buf`] for details.
    ///
    /// If you'd rather get a `Vec<u8>` no matter what, you can call [`CryptoArray::into_vec`] on
    /// the output.
    pub fn encrypt_bytes<P: OwnedHasCryptoLen + ?Sized>(
        &self,
        plaintext: &P,
    ) -> Result<CryptoArraySum<P::Owned, C::OverheadBytes>, C::Error> {
        // Create the right kind of buffer (this will be fixed-length if it can be, otherwise
        // variable, if the latter then `encrypt_to_buf` should handle it)
        let mut buf = CryptoArraySum::<P::Owned, C::OverheadBytes>::new();
        C::encrypt_to_buf(plaintext, &self.key, &mut buf)?;
        Ok(buf)
    }

    /// Decrypts the given ciphertext bytes with this key, returning the plaintext bytes. Providing
    /// fixed-length ciphertext to this method will give you a fixed-length output when you use a
    /// cryptosystem that has a fixed overhead length, and otherwise you'll get a `Vec<u8>`.
    /// See [`Self::decrypt_to_buf`] for details.
    ///
    /// If you'd rather get a `Vec<u8>` no matter what, you can call [`CryptoArray::into_vec`] on
    /// the output.
    pub fn decrypt_bytes<X: OwnedHasCryptoLen + ?Sized>(
        &self,
        ciphertext: &X,
    ) -> Result<CryptoArrayDiff<X::Owned, C::OverheadBytes>, C::Error> {
        // Create the right kind of buffer (this will be fixed-length if it can be, otherwise
        // variable)
        let mut buf = CryptoArrayDiff::<X::Owned, C::OverheadBytes>::new();
        C::decrypt_to_buf(ciphertext, &self.key, &mut buf)?;
        Ok(buf)
    }

    /// Encrypts the given message, returning the bytes of the ciphertext, but first serializing
    /// the message to bytes with [`bincode`].
    ///
    /// Note that encryption done this way is intended for decryption by these same systems, as
    /// [`bincode`]'s serialization format is not standardised! If you want to decrypt messages on
    /// different systems, first serialize your message to bytes in some standardised way the other
    /// system can do too, and then use [`Self::encrypt_bytes`].
    #[cfg(feature = "serde")]
    pub fn encrypt<T: Serialize>(&self, msg: &T) -> Result<Vec<u8>, CryptoError<C::Error>> {
        let msg_bytes = bincode::serialize(msg)
            .map_err(|source| CryptoError::SerializationFailed { source })?;
        self.encrypt_bytes(&msg_bytes)
            .map(|a| a.into_vec())
            .map_err(|source| CryptoError::ImplementationError { source })
    }
    /// Decrypts the given ciphertext, deserializing the resulting plaintext bytes into the given
    /// type. This is intended for decrypting messages created with this same system, as
    /// [`bincode`]'s serialization format is not standardised!
    #[cfg(feature = "serde")]
    pub fn decrypt<T: for<'de> Deserialize<'de>>(
        &self,
        ciphertext: &[u8],
    ) -> Result<T, CryptoError<C::Error>> {
        let plaintext_bytes = self
            .decrypt_bytes(ciphertext)
            .map_err(|source| CryptoError::ImplementationError { source })?;
        bincode::deserialize(plaintext_bytes.as_ref())
            .map_err(|source| CryptoError::DeserializationFailed { source })
    }
}
