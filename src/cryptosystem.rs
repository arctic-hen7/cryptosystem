use crate::crypto_array::{
    CryptoArrayDiffLen, CryptoArraySumLen, CryptoBuffer, HasCryptoLen, OwnedHasCryptoLen,
};
use std::borrow::Cow;

/// A trait for a collection of cryptographic primitives for symmetric encryption (i.e. encrypting
/// and decrypting with the same key, which is shared between parties).
pub trait SymmetricCryptosystem: Clone + Copy + Send + Sync {
    /// The type of the symmetric key used by this cryptosystem.
    type Key: Clone + Send + Sync;
    /// The type of the symmetric key, when represented as bytes. See [`CryptoArray`] for details.
    type KeyBytes: HasCryptoLen;
    /// The type of the overhead bytes produced when encrypting. Many symmetric cryptosystems have
    /// known overhead lengths (i.e. the ciphertext will be the length of the plaintext, plus some
    /// number of overhead bytes), though this will often vary between implementations. If this is
    /// known, it can be used to optimise encryption and decryption with stack-allocation.
    type OverheadBytes: HasCryptoLen;
    /// The type of errors that can occur during encryption and decryption.
    type Error: std::error::Error;
    /// The type of errors that can occur when importing a key from bytes.
    type IoError: std::error::Error;

    /// Generates a new key. This should use a cryptographically-secure random number generator,
    /// and should panic if random bytes cannot be generated.
    fn generate_key() -> Self::Key;

    /// Encrypts the given plaintext with the given key, writing the bytes of the ciphertext to the
    /// given buffer.
    ///
    /// Implementors should *always* include an assertion that the given buffer is the right size!
    /// You can use [`CryptoArrayRef::len`] to get the size of the plaintext, which will be correct
    /// at runtime regardless of whether the user provides a fixed or variable-length array.
    ///
    /// Callers can work out how long of a buffer to pass to this function by using
    ///
    /// If both the plaintext and overhead are fixed-length, then the provided buffer is guaranteed
    /// by the type machinery to be the right length. If either is variable-length, however, the
    /// buffer will be a vector, which may of the wrong size. As such, implementors should be
    /// careful to call `buf.set_size()` to ensure the buffer is the right size before writing into
    /// it.
    fn encrypt_to_buf<P: OwnedHasCryptoLen + ?Sized, B: OwnedHasCryptoLen + ?Sized>(
        plaintext: &P,
        key: &Self::Key,
        buf: &mut B, // buf: &mut CryptoArraySum<P::Owned, Self::OverheadBytes>,
    ) -> Result<(), Self::Error>
    where
        <B as OwnedHasCryptoLen>::Owned:
            CryptoBuffer<CryptoArraySumLen<P::Owned, Self::OverheadBytes>>;

    /// Decrypts the given ciphertext with the given key, writing the bytes of the plaintext to the
    /// given buffer.
    ///
    /// If both the ciphertext and overhead are fixed-length, then the provided buffer is guaranteed
    /// by the type machinery to be the right length. If either is variable-length, however, the
    /// buffer will be a vector, which may of the wrong size. As such, implementors should be
    /// careful to call `buf.set_size()` to ensure the buffer is the right size before writing into
    /// it. In many cases, a check to make sure the ciphertext is a minimum length will also be
    /// required (though if fixed-length, type machinery will handle this).
    fn decrypt_to_buf<C: OwnedHasCryptoLen + ?Sized, B: OwnedHasCryptoLen + ?Sized>(
        ciphertext: &C,
        key: &Self::Key,
        buf: &mut B, // buf: &mut CryptoArrayDiff<P::Owned, Self::OverheadBytes>,
    ) -> Result<(), Self::Error>
    where
        <B as OwnedHasCryptoLen>::Owned:
            CryptoBuffer<CryptoArrayDiffLen<C::Owned, Self::OverheadBytes>>;

    /// Exports the given symmetric key to raw bytes, without any special formatting.
    fn export_key(key: &Self::Key) -> Cow<'_, Self::KeyBytes>;
    /// Imports a key from its byte representation.
    fn import_key(key: &Self::KeyBytes) -> Result<Self::Key, Self::IoError>;
}

/// A trait for a collection of cryptographic primitives for signing and verification (i.e. where
/// the signer holds a secret key, and signatures created by them can be verified by other parties
/// using their public key).
pub trait SigningCryptosystem: PublicKeyCryptosystem + Clone + Copy {
    /// The type of signatures produced by this cryptosystem.
    type Signature: Clone + Send + Sync;
    /// The type of signatures, when represented as bytes. See [`CryptoArray`] for details.
    type SignatureBytes: HasCryptoLen;
    /// Errors that can occur when signing or verifying messages.
    type Error: std::error::Error;
    /// Errors that can occur when importing or exporting signatures.
    type IoError: std::error::Error;

    /// Signs the given bytes with the given key, returning the signature.
    fn sign(msg: &[u8], key: &Self::SecretKey) -> Result<Self::Signature, Self::Error>;
    /// Verifies the given signature on the given message, using the given public key. If
    /// verification fails, for any reason, this should return an error.
    fn verify(
        signature: &Self::Signature,
        msg: &[u8],
        key: &Self::PublicKey,
    ) -> Result<(), Self::Error>;

    /// Exports the given signature to raw bytes, without any special formatting.
    fn export_signature(signature: &Self::Signature) -> Cow<'_, Self::SignatureBytes>;
    /// Imports a signature from its byte representation.
    fn import_signature(
        signature: &Self::SignatureBytes,
    ) -> Result<Self::Signature, <Self as SigningCryptosystem>::IoError>;
}

// /// A trait for a collection of key exchange primitives that allow, from a public and secret key,
// /// the derivation of a shared secret, which can be used for communication. This is used in this
// /// library instead of a trait for direct asymmetric encryption, as key exchange, followed by
// /// symmetric encryption, tends to be more flexible and more secure (especially when used with
// /// ephemeral keys).
// pub trait KeyExchangeCryptosystem: PublicKeyCryptosystem + Clone + Copy {
//     /// The type of shared secrets produced by this cryptosystem.
//     type SharedSecret: Clone + Send + Sync;
//     /// The type of errors that can occur when generating shared secrets.
//     type Error: std::error::Error;
//
//     /// Generates a shared secret for communication with some other party, given their public key
//     /// and our secret key.
//     fn generate_shared_secret(
//         secret_key: &Self::SecretKey,
//         public_key: &Self::PublicKey,
//     ) -> Result<Self::SharedSecret, Self::Error>;
//
//     /// Exports the given shared secret to raw bytes, without any additional formatting. It is
//     /// assumed that this will never need to be imported again.
//     fn export_shared_secret(shared_secret: &Self::SharedSecret) -> Cow<'_, [u8]>;
// }

/// A trait for a collection of key encapsulation primitives that allow a public key to be used to
/// send a random shared secret to its owner, who can decrypt it with their secret key. This is
/// similar to key exchange, though only *one* party contributes the shared secret here, as opposed
/// to both. Crucially, encapsulating a random key from Alice to Bob is *not* the same as
/// encapsulating a key from Bob to Alice, even if the randomness were engineered to be identical
/// (insecure), hence the difference with multi-party key exchange.
///
/// Key encapsulation is more common among post-quantum primitives, and can always be built from
/// key exchange, while the reverse is not true. Hence, we have chosen to implement key
/// encapsulation as the core primitive of this library, rather than key exchange.
pub trait KeyEncapsulationCryptosystem: PublicKeyCryptosystem + Clone + Copy {
    /// The type of shared secrets produced by this cryptosystem.
    type SharedSecret: Clone + Send + Sync;
    /// The type of shared secrets, when represented as bytes. See [`CryptoArray`] for details.
    type SharedSecretBytes: HasCryptoLen;
    /// The type of encapsulations produced by this cryptosystem, which are sent from one party to
    /// the other to facilitate shared secret derivation.
    type Encapsulation: Clone + Send + Sync;
    /// The type of encapsulations, when represented as bytes. See [`CryptoArray`] for details.
    type EncapsulationBytes: HasCryptoLen;
    /// The type of errors that can occur when generating shared secrets.
    type Error: std::error::Error;
    /// The type of errors that can occur when importing encapsulations.
    type IoError: std::error::Error;

    /// Encapsulates a random shared secret to the given public (encapsulation) key. The result is
    /// first the encapsulation, which should be sent to the other party, and the shared secret,
    /// which will be the same as what they "decapsulate".
    fn encapsulate(
        public_key: &Self::PublicKey,
    ) -> Result<(Self::Encapsulation, Self::SharedSecret), Self::Error>;

    /// Decapsulates the given encapsulation with the given secret key. The encapsulation provided
    /// must have been encapsulated to the corresponding public key, or this will fail.
    fn decapsulate(
        encapsulation: &Self::Encapsulation,
        secret_key: &Self::SecretKey,
    ) -> Result<Self::SharedSecret, Self::Error>;

    /// Exports the given encapsulation to raw bytes, without any additional formatting.
    fn export_encapsulation(
        encapsulation: &Self::Encapsulation,
    ) -> Cow<'_, Self::EncapsulationBytes>;
    /// Imports an encapsulation from its byte representation.
    fn import_encapsulation(
        encapsulation: &Self::EncapsulationBytes,
    ) -> Result<Self::Encapsulation, <Self as KeyEncapsulationCryptosystem>::IoError>;

    /// Exports the given shared secret to raw bytes, without any additional formatting. It is
    /// assumed that this will never need to be imported again.
    fn export_shared_secret(shared_secret: &Self::SharedSecret)
        -> Cow<'_, Self::SharedSecretBytes>;
}

/// A trait for a collection of asymmetric cryptographic primitives. This trait by itself does not
/// provide any useful things for these primitives to do, it only looks at the public and secret
/// keys involved, providing the capacity to generate, import, and export them.
pub trait PublicKeyCryptosystem: Clone + Copy {
    /// The type of public keys in this cryptosystem.
    type PublicKey: Clone + Send + Sync;
    /// The type of public keys, when represented as bytes. See [`CryptoArray`] for details.
    type PublicKeyBytes: HasCryptoLen;
    /// The type of secret keys in this cryptosystem.
    type SecretKey: Clone + Send + Sync;
    /// The type of secret keys, when represented as bytes. See [`CryptoArray`] for details.
    type SecretKeyBytes: HasCryptoLen;
    /// The type of errors that can occur when importing or exporting keys.
    type IoError: std::error::Error;

    /// Generates a new keypair. This should use a cryptographically-secure random number
    /// generator, and should panic if random bytes cannot be generated.
    fn generate_keypair() -> (Self::PublicKey, Self::SecretKey);

    /// Exports the given public key to *raw* bytes, without any additional formatting.
    fn export_public_key_raw(key: &Self::PublicKey) -> Cow<'_, Self::PublicKeyBytes>;
    /// Imports a public key from its byte representation.
    fn import_public_key_raw(key: &Self::PublicKeyBytes) -> Result<Self::PublicKey, Self::IoError>;

    /// Exports the given public key to DER-encoded bytes.
    #[cfg(feature = "der")]
    fn export_public_key_der(key: &Self::PublicKey) -> Result<Vec<u8>, Self::IoError>;
    /// Imports a public key from the given DER-encoded bytes.
    #[cfg(feature = "der")]
    fn import_public_key_der(key: &[u8]) -> Result<Self::PublicKey, Self::IoError>;

    /// Exports the given secret key to *raw* bytes, without any additional formatting.
    fn export_secret_key_raw(key: &Self::SecretKey) -> Cow<'_, Self::SecretKeyBytes>;
    /// Imports a secret key from its byte representation.
    fn import_secret_key_raw(key: &Self::SecretKeyBytes) -> Result<Self::SecretKey, Self::IoError>;

    /// Exports the given secret key to DER-encoded bytes.
    #[cfg(feature = "der")]
    fn export_secret_key_der(key: &Self::SecretKey) -> Result<Vec<u8>, Self::IoError>;
    /// Imports a secret key from the given DER-encoded bytes.
    #[cfg(feature = "der")]
    fn import_secret_key_der(key: &[u8]) -> Result<Self::SecretKey, Self::IoError>;
}
