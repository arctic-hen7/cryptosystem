use std::marker::PhantomData;
use thiserror::Error;

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
    #[error("composite bytes are too short")]
    TooShort,
}

/// A composite cryptosystem, which literally combines two different cryptographic
/// schemes into one. This should generally be used sparingly, when one system isn't fully trusted,
/// and the other is likely to make up for its shortcomings. For instance, this is a common pattern
/// in transitioning to quantum-safe cryptography.
#[derive(Clone, Copy, Debug)]
pub struct CompositeCryptosystem<C1, C2>(PhantomData<(C1, C2)>);
