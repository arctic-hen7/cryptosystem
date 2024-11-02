use thiserror::Error;

/// A cryptography error, which is generic over a cryptosystem's own unique error type.
#[derive(Error, Debug)]
pub enum CryptoError<E: std::error::Error> {
    #[error("failed to serialize plaintext to binary for encryption")]
    SerializationFailed {
        #[source]
        source: bincode::Error,
    },
    #[error("failed to deserialize plaintext to type after successful decryption (was the incorrect type specified?)")]
    DeserializationFailed {
        #[source]
        source: bincode::Error,
    },
    // This error type is provided by the cryptosystem implementation
    #[error("underlying cryptography error occurred")]
    ImplementationError {
        #[source]
        #[from]
        source: E,
    },
}

/// Errors that can occur in converting base64 strings to types.
#[cfg(feature = "base64")]
#[derive(Error, Debug)]
pub enum FromBase64Error<E: std::error::Error> {
    #[error("failed to convert base64 into bytes")]
    DecodeError(#[source] base64::DecodeError),
    #[error("failed to convert bytes into type")]
    ConvertError(#[from] E),
}

/// Errors that can occur in converting hex strings to types.
#[cfg(feature = "hex")]
#[derive(Error, Debug)]
pub enum FromHexError<E: std::error::Error> {
    #[error("failed to convert hex into bytes")]
    DecodeError(#[source] hex::FromHexError),
    #[error("failed to convert bytes into type")]
    ConvertError(#[from] E),
}

/// Errors that can occur in converting PEM strings into keys.
#[cfg(feature = "pem")]
#[derive(Error, Debug)]
pub enum FromPemError<E: std::error::Error> {
    #[error("invalid pem format")]
    InvalidFormat,
    #[error("failed to convert pem into bytes")]
    DecodeError(#[source] base64::DecodeError),
    #[error("failed to convert bytes into type")]
    ConvertError(#[from] E),
}
