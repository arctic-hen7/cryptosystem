/// A trait for a collection of cryptographic primitives for symmetric encryption (i.e. encrypting
/// and decrypting with the same key, which is shared between parties).
pub trait SymmetricCryptosystem {
    /// The type of the symmetric key used by this cryptosystem.
    type Key;
    /// The type of errors that can occur during encryption and decryption.
    type Error: std::error::Error;
    /// The type of errors that can occur when importing a key from bytes.
    type IoError: std::error::Error;

    /// Generates a new key. This should use a cryptographically-secure random number generator,
    /// and should panic if random bytes cannot be generated.
    fn generate_key() -> Self::Key;

    /// Encrypts the given bytes with the given key, returning the bytes of the ciphertext.
    fn encrypt(msg: &[u8], key: &Self::Key) -> Result<Vec<u8>, Self::Error>;
    /// Decrypts the given ciphertext with the given key, returning the raw bytes of the plaintext.
    fn decrypt(ciphertext: &[u8], key: &Self::Key) -> Result<Vec<u8>, Self::Error>;

    /// Exports the given symmetric key to raw bytes, without any special formatting.
    fn export_key(key: &Self::Key) -> &[u8];
    /// Imports a key from the given raw byte slice.
    fn import_key(key: &[u8]) -> Result<Self::Key, Self::IoError>;
}

/// A trait for a collection of cryptographic primitives for signing and verification (i.e. where
/// the signer holds a secret key, and signatures created by them can be verified by other parties
/// using their public key).
pub trait SigningCryptosystem: PublicKeyCryptosystem {
    /// The type of signatures produced by this cryptosystem.
    type Signature;
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
    fn export_signature(signature: &Self::Signature) -> &[u8];
    /// Imports a signature from the given raw byte slice.
    fn import_signature(
        signature: &[u8],
    ) -> Result<Self::Signature, <Self as SigningCryptosystem>::IoError>;
}

/// A trait for a collection of key exchange primitives that allow, from a public and secret key,
/// the derivation of a shared secret, which can be used for communication. This is used in this
/// library instead of a trait for direct asymmetric encryption, as key exchange, followed by
/// symmetric encryption, tends to be more flexible and more secure (especially when used with
/// ephemeral keys).
pub trait KeyExchangeCryptosystem: PublicKeyCryptosystem {
    /// The type of shared secrets produced by this cryptosystem.
    type SharedSecret;
    /// The type of errors that can occur when generating shared secrets.
    type Error: std::error::Error;

    /// Generates a shared secret for communication with some other party, given their public key
    /// and our secret key.
    fn generate_shared_secret(
        secret_key: &Self::SecretKey,
        public_key: &Self::PublicKey,
    ) -> Result<Self::SharedSecret, Self::Error>;

    /// Exports the given shared secret to raw bytes, without any additional formatting. It is
    /// assumed that this will never need to be imported again.
    fn export_shared_secret(shared_secret: &Self::SharedSecret) -> &[u8];
}

/// A trait for a collection of asymmetric cryptographic primitives. This trait by itself does not
/// provide any useful things for these primitives to do, it only looks at the public and secret
/// keys involved, providing the capacity to generate, import, and export them.
pub trait PublicKeyCryptosystem {
    /// The type of public keys in this cryptosystem.
    type PublicKey;
    /// The type of secret keys in this cryptosystem.
    type SecretKey;
    /// The type of errors that can occur when importing or exporting keys.
    type IoError: std::error::Error;

    /// Generates a new keypair. This should use a cryptographically-secure random number
    /// generator, and should panic if random bytes cannot be generated.
    fn generate_keypair() -> (Self::PublicKey, Self::SecretKey);

    /// Exports the given public key to *raw* bytes, without any additional formatting.
    fn export_public_key_raw(key: &Self::PublicKey) -> &[u8];
    /// Imports a public key from the given *raw* byte slice.
    fn import_public_key_raw(key: &[u8]) -> Result<Self::PublicKey, Self::IoError>;

    /// Exports the given public key to DER-encoded bytes.
    #[cfg(feature = "der")]
    fn export_public_key_der(key: &Self::PublicKey) -> Result<Vec<u8>, Self::IoError>;
    /// Imports a public key from the given DER-encoded bytes.
    #[cfg(feature = "der")]
    fn import_public_key_der(key: &[u8]) -> Result<Self::PublicKey, Self::IoError>;

    /// Exports the given secret key to *raw* bytes, without any additional formatting.
    fn export_secret_key_raw(key: &Self::SecretKey) -> &[u8];
    /// Imports a secret key from the given *raw* byte slice.
    fn import_secret_key_raw(key: &[u8]) -> Result<Self::SecretKey, Self::IoError>;

    /// Exports the given secret key to DER-encoded bytes.
    #[cfg(feature = "der")]
    fn export_secret_key_der(key: &Self::SecretKey) -> Result<Vec<u8>, Self::IoError>;
    /// Imports a secret key from the given DER-encoded bytes.
    #[cfg(feature = "der")]
    fn import_secret_key_der(key: &[u8]) -> Result<Self::SecretKey, Self::IoError>;
}
