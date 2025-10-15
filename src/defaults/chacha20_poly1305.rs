use crate::{
    crypto_array::{CryptoArrayDiffLen, CryptoArraySumLen, CryptoBuffer, OwnedHasCryptoLen},
    cryptosystem::SymmetricCryptosystem,
    symmetric_cryptosystem_tests,
};
use chacha20poly1305::{
    aead::{AeadCore, AeadMutInPlace, KeyInit, OsRng},
    Key, XChaCha20Poly1305,
};
use std::{borrow::Cow, convert::Infallible};
use thiserror::Error;

pub type C7P7Cryptosystem = ChaCha20Poly1305Cryptosystem;

/// A cryptosystem using ChaCha20Poly1305 for symmetric encryption.
#[derive(Clone, Copy, Debug)]
pub struct ChaCha20Poly1305Cryptosystem;
impl SymmetricCryptosystem for ChaCha20Poly1305Cryptosystem {
    type Key = Key;
    type KeyBytes = [u8; 32];
    type OverheadBytes = [u8; 40]; // 24-byte nonce and 16-byte tag
    type Error = ChaCha20Poly1305Error;
    type IoError = Infallible;

    fn generate_key_from_rng<R: rand::TryRngCore + rand::TryCryptoRng>(
        rng: &mut R,
    ) -> Result<Self::Key, R::Error> {
        // A key is literally a 32-byte array, we get around different `rand` versions by
        // generating the key bytes manually
        let mut key_bytes = [0u8; 32];
        rng.try_fill_bytes(&mut key_bytes)?;
        Ok(key_bytes.into())
    }

    fn encrypt_to_buf<P: OwnedHasCryptoLen + ?Sized, B: OwnedHasCryptoLen + ?Sized>(
        plaintext: &P,
        key: &Self::Key,
        buf: &mut B, // buf: &mut CryptoArraySum<P::Owned, Self::OverheadBytes>,
    ) -> Result<(), Self::Error>
    where
        <B as OwnedHasCryptoLen>::Owned:
            CryptoBuffer<CryptoArraySumLen<P::Owned, Self::OverheadBytes>>,
    {
        buf.set_size(plaintext.len() + 40);

        let mut cipher = XChaCha20Poly1305::new(key);
        let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
        // We use the detached method because it accepts a `&mut [u8]`, rather than `Buffer`
        buf.as_mut()[..plaintext.len()].copy_from_slice(plaintext.as_ref());
        let tag = cipher
            .encrypt_in_place_detached(&nonce, &[], &mut buf.as_mut()[..plaintext.len()])
            .map_err(|_| ChaCha20Poly1305Error::EncryptionFailed)?;
        // Now write the tag on the end of the buffer (we use the runtime length because we'll
        // strip the constant-size data off in decryption, and this can be left as is)
        buf.as_mut()[plaintext.len()..(plaintext.len() + 16)].copy_from_slice(&tag);
        // And finally write the nonce (this will panic if the lengths are wrong, but we know
        // they're correct in this implementation because we have a fixed overhead length)
        buf.as_mut()[(plaintext.len() + 16)..].copy_from_slice(&nonce);

        Ok(())
    }

    fn decrypt_to_buf<C: OwnedHasCryptoLen + ?Sized, B: OwnedHasCryptoLen + ?Sized>(
        ciphertext: &C,
        key: &Self::Key,
        buf: &mut B, // buf: &mut CryptoArrayDiff<P::Owned, Self::OverheadBytes>,
    ) -> Result<(), Self::Error>
    where
        <B as OwnedHasCryptoLen>::Owned:
            CryptoBuffer<CryptoArrayDiffLen<C::Owned, Self::OverheadBytes>>,
    {
        if ciphertext.len() < 40 {
            return Err(ChaCha20Poly1305Error::DecryptionFailed);
        }
        buf.set_size(ciphertext.len() - 40);

        let raw_ciphertext = &ciphertext.as_ref()[..(ciphertext.len() - 40)];
        let tag = &ciphertext.as_ref()[(ciphertext.len() - 40)..(ciphertext.len() - 24)];
        let nonce = &ciphertext.as_ref()[(ciphertext.len() - 24)..];

        let mut cipher = XChaCha20Poly1305::new(key);
        buf.as_mut().copy_from_slice(raw_ciphertext);
        cipher
            // The nonce and tag are guaranteed by the above indexing to be the right length
            .decrypt_in_place_detached(nonce.into(), &[], buf.as_mut(), tag.into())
            .map_err(|_| ChaCha20Poly1305Error::DecryptionFailed)?;

        Ok(())
    }

    // fn encrypt(msg: &[u8], key: &Self::Key) -> Result<Vec<u8>, Self::Error> {
    //     let cipher = XChaCha20Poly1305::new(key);
    //     let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
    //     let ciphertext = cipher
    //         .encrypt(&nonce, msg)
    //         .map_err(|_| ChaCha20Poly1305Error::EncryptionFailed)?;
    //
    //     let mut ciphertext_with_nonce = Vec::with_capacity(nonce.len() + ciphertext.len());
    //     ciphertext_with_nonce.extend_from_slice(&nonce);
    //     ciphertext_with_nonce.extend_from_slice(&ciphertext);
    //     Ok(ciphertext_with_nonce)
    // }
    // fn decrypt(ciphertext: &[u8], key: &Self::Key) -> Result<Vec<u8>, Self::Error> {
    //     // Nonce is the first 24 bytes
    //     let extracted_nonce = &ciphertext[..24];
    //     let cipher = XChaCha20Poly1305::new(key);
    //     let plaintext_bytes = cipher
    //         .decrypt(extracted_nonce.into(), &ciphertext[24..])
    //         .map_err(|_| ChaCha20Poly1305Error::DecryptionFailed)?;
    //     Ok(plaintext_bytes)
    // }

    fn export_key(key: &Self::Key) -> Cow<'_, Self::KeyBytes> {
        Cow::Borrowed(key.as_ref())
    }
    fn import_key(key: &Self::KeyBytes) -> Result<Self::Key, Self::IoError> {
        // Infallible, symmetric keys for ChaCha are just raw bytes with no particular structure
        Ok(*Key::from_slice(key))
    }
}

#[derive(Error, Debug)]
pub enum ChaCha20Poly1305Error {
    #[error("failed to encrypt given message")]
    EncryptionFailed,
    #[error("failed to decrypt given message with given key")]
    DecryptionFailed,
}

symmetric_cryptosystem_tests!(super::ChaCha20Poly1305Cryptosystem);
