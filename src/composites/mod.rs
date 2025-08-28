use crate::crypto_array::{BadSize, CryptoArraySum, HasCryptoLen};
use std::marker::PhantomData;
use thiserror::Error;
use typebits::Bitstring;

mod key_encapsulation;
mod public_key;
mod signing;

/// Either of the two given error types. This is used for composite cryptosystem errors.
#[derive(Error, Debug)]
pub enum CompositeError<A, B> {
    #[error(transparent)]
    A(A),
    #[error(transparent)]
    B(B),
}

/// Either of the two given error types, plus the possibility of not having enough length overall.
/// This is used for composite cryptosystem I/O errors.
#[derive(Error, Debug)]
pub enum CompositeIoError<A, B> {
    #[error(transparent)]
    A(A),
    #[error(transparent)]
    B(B),
    #[error(transparent)]
    ImportError(#[from] CompositeImportError),
}

#[derive(Error, Debug)]
pub enum CompositeImportError {
    #[error("composite bytes are too short")]
    TooShort,
    // This will happen if the size tag is just plain wrong
    #[error("composte bytes size was incorrect")]
    BadSize(#[from] BadSize),
}

/// A composite cryptosystem, which literally combines two different cryptographic
/// schemes into one. This should generally be used sparingly, when one system isn't fully trusted,
/// and the other is likely to make up for its shortcomings. For instance, this is a common pattern
/// in transitioning to quantum-safe cryptography.
#[derive(Clone, Copy, Debug)]
pub struct CompositeCryptosystem<C1, C2>(PhantomData<(C1, C2)>);

/// Exports the two given `HasCryptoLen`s as a single `HasCryptoLen` appropriately.
fn export_combination<B1: HasCryptoLen, B2: HasCryptoLen>(
    bytes_1: &B1,
    bytes_2: &B2,
) -> CryptoArraySum<B1, B2> {
    let mut buf = CryptoArraySum::<B1, B2>::new();
    buf.set_size(bytes_1.len() + bytes_2.len());

    // If both component keys are fixed-length, we can just write them one after the other
    if B1::is_fixed_length() && B2::is_fixed_length() {
        buf.as_mut()[0..bytes_1.len()].copy_from_slice(bytes_1.as_ref());
        buf.as_mut()[bytes_1.len()..].copy_from_slice(bytes_2.as_ref());
    } else {
        // If one is variable-length, then our `buf` is guaranteed to be a vector (so this
        // won't fail on a debug assertion)
        buf.set_size(4 + bytes_1.len() + bytes_2.len());
        let size_tag = (bytes_1.len() as u32).to_le_bytes();

        buf.as_mut()[0..4].copy_from_slice(&size_tag);
        buf.as_mut()[4..4 + bytes_1.len()].copy_from_slice(bytes_1.as_ref());
        buf.as_mut()[4 + bytes_1.len()..].copy_from_slice(bytes_2.as_ref());
    }

    buf
}

/// Imports the given `HasCryptoLen` as a combination of two `HasCryptoLen`s appropriately.
fn import_combination<B1: HasCryptoLen, B2: HasCryptoLen>(
    buf: &CryptoArraySum<B1, B2>,
) -> Result<(B1, B2), CompositeImportError> {
    // If both component keys are fixed-length, we can just read them one after the other
    if B1::is_fixed_length() && B2::is_fixed_length() {
        let key_1_len = B1::Length::UNSIGNED;

        // This is guaranteed to work for both because our buffer is the right length
        // (type-assured), and so will these be
        let key_1_bytes = B1::from_slice(&buf.as_ref()[0..key_1_len]).unwrap();
        let key_2_bytes = B2::from_slice(&buf.as_ref()[key_1_len..]).unwrap();

        Ok((key_1_bytes, key_2_bytes))
    } else {
        // If one is variable-length, then our `buf` is guaranteed to be a vector, and assuming
        // we exported correctly, there'll be a size tag at the front
        if buf.len() < 4 {
            return Err(CompositeImportError::TooShort);
        }

        // Read the size tag and make sure we have enough bytes after it
        let key_1_len = u32::from_le_bytes(buf.as_ref()[0..4].try_into().unwrap()) as usize;
        if buf.len() < 4 + key_1_len {
            return Err(CompositeImportError::TooShort);
        }

        // We know this slice is the correct length, assuming our length prefix was right (but
        // that could be corrupt!)
        let key_1_bytes = B1::from_slice(&buf.as_ref()[4..4 + key_1_len])?;
        // This one is anyone's guess
        let key_2_bytes = B2::from_slice(&buf.as_ref()[4 + key_1_len..])?;

        Ok((key_1_bytes, key_2_bytes))
    }
}
