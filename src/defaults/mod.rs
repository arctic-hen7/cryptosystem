#[cfg(feature = "default-chacha20poly1305")]
mod chacha20_poly1305;
#[cfg(feature = "default-ed25519")]
mod ed25519;
#[cfg(feature = "default-kyber")]
mod kyber;
#[cfg(feature = "default-x25519")]
mod x25519;

#[cfg(feature = "default-chacha20poly1305")]
pub use chacha20_poly1305::*;
#[cfg(feature = "default-ed25519")]
pub use ed25519::*;
#[cfg(feature = "default-kyber")]
pub use kyber::*;
#[cfg(feature = "default-x25519")]
pub use x25519::*;

#[cfg(all(feature = "default-x25519", feature = "default-kyber"))]
crate::key_encapsulation_cryptosystem_tests!(crate::CompositeCryptosystem<crate::X25519Cryptosystem, crate::KyberCryptosystem>);
