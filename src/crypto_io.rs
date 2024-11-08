#[cfg(feature = "base64")]
use crate::error::FromBase64Error;
#[cfg(feature = "hex")]
use crate::error::FromHexError;
#[cfg(feature = "pem")]
use crate::error::FromPemError;

/// A trait for cryptographic values that can be imported from a variety of formats, based on their
/// raw byte encodings. The formats available depend on the feature flags (currently `hex` and
/// `base64`).
pub trait CryptoImport {
    type Error: std::error::Error;

    /// Imports this cryptographic value from the given bytes.
    ///
    /// For types that also implement [`CryptoDerIo`], this expects the *raw* bytes, not the
    /// DER-encoded bytes!
    fn from_bytes(bytes: &[u8]) -> Result<Self, Self::Error>
    where
        Self: Sized;

    /// Imports this cryptographic value from the given hex-encoded string.
    ///
    /// For types that also implement [`CryptoDerIo`], this expects a hex encoding of the *raw*
    /// bytes, *not* the DER-encoded bytes!
    #[cfg(feature = "hex")]
    fn from_hex(hex: &str) -> Result<Self, FromHexError<Self::Error>>
    where
        Self: Sized,
    {
        let bytes = hex::decode(hex).map_err(FromHexError::DecodeError)?;
        Self::from_bytes(&bytes).map_err(FromHexError::ConvertError)
    }

    /// Imports this cryptographic value from the given base64-encoded string.
    ///
    /// For types that also implement [`CryptoDerIo`], this expects a base64 encoding of the *raw*
    /// bytes, *not* the DER-encoded bytes!
    #[cfg(feature = "base64")]
    fn from_base64(base64: &str, url_safe: bool) -> Result<Self, FromBase64Error<Self::Error>>
    where
        Self: Sized,
    {
        use crate::base64_utils::base64_to_bytes;

        let bytes = base64_to_bytes(base64, url_safe).map_err(FromBase64Error::DecodeError)?;
        Self::from_bytes(&bytes).map_err(FromBase64Error::ConvertError)
    }
}

/// A trait for cryptographic values that can be exported to a variety of formats, based on their
/// raw byte encodings. The formats available depend on the feature flags (currently `hex` and
/// `base64`).
pub trait CryptoExport {
    /// Exports this cryptographic value to bytes.
    ///
    /// For types that also implement [`CryptoDerIo`], this will be the *raw* bytes, not the
    /// DER-encoded bytes!
    fn to_bytes(&self) -> &[u8];

    /// Exports this cryptographic value to a hex-encoded string.
    ///
    /// For types that also implement [`CryptoDerIo`], this will be a hex encoding of the *raw*
    /// bytes, *not* the DER-encoded bytes!
    #[cfg(feature = "hex")]
    fn to_hex(&self) -> String {
        let bytes = self.to_bytes();
        hex::encode(bytes)
    }

    /// Exports this cryptographic value to a base64-encoded string.
    ///
    /// For types that also implement [`CryptoDerIo`], this will be a base64 encoding of the *raw*
    /// bytes, *not* the DER-encoded bytes!
    #[cfg(feature = "base64")]
    fn to_base64(&self, url_safe: bool) -> String {
        use crate::base64_utils::bytes_to_base64;

        let bytes = self.to_bytes();
        bytes_to_base64(bytes, url_safe)
    }
}

/// A trait for cryptographic values that can be imported from DER (and PEM, if `pem` is enabled).
#[cfg(feature = "der")]
pub trait CryptoDerImport: CryptoImport {
    /// Imports this cryptographic value from the given DER-encoded bytes.
    fn from_der(der: &[u8]) -> Result<Self, Self::Error>
    where
        Self: Sized;

    /// Gets the text that will appear in the header and footer of a PEM encoding of this value.
    /// For example, if this returns `PUBLIC KEY`, the PEM string will start with `-----BEGIN
    /// PUBLIC KEY-----` and end with `-----END PUBLIC KEY-----`.
    #[cfg(feature = "pem")]
    fn pem_header() -> &'static str;

    /// Imports this cryptographic value from the given PEM-encoded string.
    #[cfg(feature = "pem")]
    fn from_pem(pem: &str) -> Result<Self, FromPemError<Self::Error>>
    where
        Self: Sized,
    {
        use crate::base64_utils::base64_to_bytes;

        let header = format!("-----BEGIN {}-----", Self::pem_header());
        let footer = format!("-----END {}-----", Self::pem_header());

        let pem = pem.trim();
        if !pem.starts_with(&header) || !pem.ends_with(&footer) {
            return Err(FromPemError::InvalidFormat);
        }

        let pem = pem.strip_prefix(&header).unwrap();
        let pem = pem.strip_suffix(&footer).unwrap();
        let base64 = pem.trim();

        let bytes = base64_to_bytes(base64, false).map_err(FromPemError::DecodeError)?;
        Self::from_bytes(&bytes).map_err(FromPemError::ConvertError)
    }
}

/// A trait for cryptographic values that can be exported to DER (and PEM, if `pem` is enabled).
#[cfg(feature = "der")]
pub trait CryptoDerExport: CryptoExport {
    /// Errors that can occur while exporting to DER.
    type Error: std::error::Error;

    /// Exports this cryptographic value to DER-encoded bytes.
    fn to_der(&self) -> Result<Vec<u8>, Self::Error>;

    /// Gets the text that will appear in the header and footer of a PEM encoding of this value.
    /// For example, if this returns `PUBLIC KEY`, the PEM string will start with `-----BEGIN
    /// PUBLIC KEY-----` and end with `-----END PUBLIC KEY-----`.
    #[cfg(feature = "pem")]
    fn pem_header() -> &'static str;

    /// Exports this cryptographic value to a PEM-encoded string, whose header aand footer will be
    /// based on the [`Self::pem_header`] method.
    #[cfg(feature = "pem")]
    fn to_pem(&self) -> Result<String, Self::Error> {
        use crate::base64_utils::bytes_to_base64;

        let der_bytes = self.to_der();
        let base64 = bytes_to_base64(&der_bytes?, false);
        Ok(format!(
            "-----BEGIN {header}-----\n{contents}\n-----END {header}-----",
            header = Self::pem_header(),
            contents = base64
        ))
    }
}
