use crate::{
    CryptoIo, PublicKey, PublicKeyCryptosystem, SecretKey, Signature, SigningCryptosystem,
    SymmetricCryptosystem, SymmetricKey,
};
use serde::{Deserialize, Serialize};

// NOTE: We provide a bunch of ways to serialize and deserialize cryptographic values, based around
// raw and DER bytes, using the [`CryptoIo`] and [`CryptoDerIo`] traits. But the *default* way of
// serializing is with standard base64 on the raw bytes, as this works well for most users, and can
// be easily changed.

macro_rules! impl_serde_str_mod {
    ($mod_name:ident, $ser:expr, $deser:expr, $doc:literal) => {
        #[doc = $doc]
        pub mod $mod_name {
            use serde::{Deserialize, Deserializer, Serializer};
            use $crate::CryptoIo;

            pub fn serialize<T: CryptoIo, S: Serializer>(
                val: &T,
                serializer: S,
            ) -> Result<S::Ok, S::Error> {
                let val_str = $ser(val);
                serializer.serialize_str(&format!("{}", val_str))
            }
            pub fn deserialize<'de, T: CryptoIo, D: Deserializer<'de>>(
                deserializer: D,
            ) -> Result<T, D::Error> {
                let val_str = String::deserialize(deserializer)?;
                let val = $deser(val_str).map_err(serde::de::Error::custom)?;

                Ok(val)
            }
        }
    };
}

impl_serde_str_mod!(
    base64_standard,
    |val: &T| { val.to_base64(false) },
    |val_str: String| { T::from_base64(&val_str, false) },
    "A module for use with `#[serde(with = \"..\")]` for serializing and deserializing
    cryptographic values (e.g. keys, signatures) to and from base64 strings (which will *not* be
    URL-safe)."
);
impl_serde_str_mod!(
    base64_url_safe,
    |val: &T| { val.to_base64(true) },
    |val_str: String| { T::from_base64(&val_str, true) },
    "A module for use with `#[serde(with = \"..\")]` for serializing and deserializing
    cryptographic values (e.g. keys, signatures) to and from base64 strings (which *will* be
    URL-safe)."
);
impl_serde_str_mod!(
    hex,
    |val: &T| { val.to_hex() },
    |val_str: String| { T::from_hex(&val_str) },
    "A module for use with `#[serde(with = \"..\")]` for serializing and deserializing
    cryptographic values (e.g. keys, signatures) to and from hex strings."
);

/// A module for use with `#[serde(with = "..")]` for serializing and deserializing cryptographic
/// values (e.g. keys) to and from PEM strings. This only works for values that implement
/// [`crate::CryptoDerIo`].
#[cfg(feature = "pem")]
pub mod pem {
    use crate::CryptoDerIo;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<T: CryptoDerIo, S: Serializer>(
        val: &T,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        let val_str = val.to_pem().map_err(serde::ser::Error::custom)?;
        serializer.serialize_str(&val_str)
    }
    pub fn deserialize<'de, T: CryptoDerIo, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<T, D::Error> {
        let val_str = String::deserialize(deserializer)?;
        let val = T::from_pem(&val_str).map_err(serde::de::Error::custom)?;

        Ok(val)
    }
}

/// A module for use with `#[serde(with = "..")]` for serializing and deserializing cryptographic
/// values (e.g. keys) to and from DER-encoded bytes. This only works for values that implement
/// [`crate::CryptoDerIo`].
#[cfg(feature = "der")]
pub mod der_bytes {
    use crate::CryptoDerIo;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<T: CryptoDerIo, S: Serializer>(
        val: &T,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        let der_bytes = val.to_der().map_err(serde::ser::Error::custom)?;
        serializer.serialize_bytes(&der_bytes)
    }
    pub fn deserialize<'de, T: CryptoDerIo, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<T, D::Error> {
        let val_bytes = Vec::<u8>::deserialize(deserializer)?;
        let val = T::from_der(&val_bytes).map_err(serde::de::Error::custom)?;

        Ok(val)
    }
}

/// A module for use with `#[serde(with = "..")]` for serializing and deserializing cryptographic
/// values (e.g. keys) to and from raw bytes.
pub mod bytes {
    use crate::CryptoIo;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<T: CryptoIo, S: Serializer>(
        val: &T,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        let bytes = val.to_bytes();
        serializer.serialize_bytes(bytes)
    }
    pub fn deserialize<'de, T: CryptoIo, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<T, D::Error> {
        let bytes = Vec::<u8>::deserialize(deserializer)?;
        let val = T::from_bytes(&bytes).map_err(serde::de::Error::custom)?;

        Ok(val)
    }
}

// NOTE: Unfortunately, we can't implement for anything that implements [`CryptoIo`] due to foreign
// trait restrictions. This works fine though.

impl<C: PublicKeyCryptosystem> Serialize for PublicKey<C> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.to_base64(false).serialize(serializer)
    }
}
impl<'de, C: PublicKeyCryptosystem> Deserialize<'de> for PublicKey<C> {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let base64 = String::deserialize(deserializer)?;
        PublicKey::from_base64(&base64, false).map_err(serde::de::Error::custom)
    }
}

impl<C: PublicKeyCryptosystem> Serialize for SecretKey<C> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.to_base64(false).serialize(serializer)
    }
}
impl<'de, C: PublicKeyCryptosystem> Deserialize<'de> for SecretKey<C> {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let base64 = String::deserialize(deserializer)?;
        SecretKey::from_base64(&base64, false).map_err(serde::de::Error::custom)
    }
}

impl<C: SymmetricCryptosystem> Serialize for SymmetricKey<C> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.to_base64(false).serialize(serializer)
    }
}
impl<'de, C: SymmetricCryptosystem> Deserialize<'de> for SymmetricKey<C> {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let base64 = String::deserialize(deserializer)?;
        SymmetricKey::from_base64(&base64, false).map_err(serde::de::Error::custom)
    }
}

impl<C: SigningCryptosystem> Serialize for Signature<C> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.to_base64(false).serialize(serializer)
    }
}
impl<'de, C: SigningCryptosystem> Deserialize<'de> for Signature<C> {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let base64 = String::deserialize(deserializer)?;
        Signature::from_base64(&base64, false).map_err(serde::de::Error::custom)
    }
}
