// #![cfg_attr(not(feature = "std"), no_std)]
#![warn(
    clippy::std_instead_of_core,
    clippy::std_instead_of_alloc,
    clippy::alloc_instead_of_core
)]

mod auto_tests;
#[cfg(feature = "base64")]
mod base64_utils;
mod composites;
mod crypto_array;
mod crypto_io;
mod cryptosystem;
mod defaults;
mod error;
mod public_key;
mod secret_key;
/// Custom implementations of serialization and deserialization for different encodings of
/// cryptographic values. This also provides default implementations for standard base64.
#[cfg(feature = "serde")]
pub mod serde;
mod shared_secret;
mod signature;
mod sizes;
mod symmetric_key;

pub use crate::crypto_io::*;
pub use crate::cryptosystem::{
    KeyEncapsulationCryptosystem, PublicKeyCryptosystem, SigningCryptosystem, SymmetricCryptosystem,
};
pub use crate::error::*;
pub use crate::public_key::PublicKey;
pub use crate::secret_key::SecretKey;
pub use crate::shared_secret::{Encapsulation, SharedSecret};
pub use crate::signature::Signature;
pub use crate::symmetric_key::SymmetricKey;

pub use crate::composites::*;
pub use crate::defaults::*;
