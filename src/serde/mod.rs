use crate::{
    shared_secret::Encapsulation, KeyEncapsulationCryptosystem, PublicKey, PublicKeyCryptosystem,
    SecretKey, SharedSecret, Signature, SigningCryptosystem, SymmetricCryptosystem, SymmetricKey,
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
            use $crate::{CryptoExport, CryptoImport};

            pub fn serialize<T: CryptoExport, S: Serializer>(
                val: &T,
                serializer: S,
            ) -> Result<S::Ok, S::Error> {
                let val_str = $ser(val);
                serializer.serialize_str(&format!("{}", val_str))
            }
            pub fn deserialize<'de, T: CryptoImport, D: Deserializer<'de>>(
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
    use crate::{CryptoDerExport, CryptoDerImport};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<T: CryptoDerExport, S: Serializer>(
        val: &T,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        let val_str = val.to_pem().map_err(serde::ser::Error::custom)?;
        serializer.serialize_str(&val_str)
    }
    pub fn deserialize<'de, T: CryptoDerImport, D: Deserializer<'de>>(
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
    use crate::{CryptoDerExport, CryptoDerImport};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<T: CryptoDerExport, S: Serializer>(
        val: &T,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        let der_bytes = val.to_der().map_err(serde::ser::Error::custom)?;
        serializer.serialize_bytes(&der_bytes)
    }
    pub fn deserialize<'de, T: CryptoDerImport, D: Deserializer<'de>>(
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
    use std::marker::PhantomData;

    use crate::{CryptoExport, CryptoImport, HasCryptoLen};
    use serde::{
        de::{SeqAccess, Visitor},
        ser::SerializeTuple,
        Deserialize, Deserializer, Serializer,
    };
    use typebits::Bitstring;

    pub fn serialize<T: CryptoExport, S: Serializer>(
        val: &T,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        let bytes = val.to_bytes();
        if <T::Output as HasCryptoLen>::is_fixed_length() {
            // We're fixed-length, serialize *without* a length prefix (as a tuple of bytes)
            let mut tup = serializer
                .serialize_tuple(<<T::Output as HasCryptoLen>::Length as Bitstring>::UNSIGNED)?;
            for byte in bytes.as_ref().as_ref() {
                tup.serialize_element(byte)?;
            }
            tup.end()
        } else {
            // We're variable-length, this will get a `&[u8]` and add a length prefix
            serializer.serialize_bytes(bytes.as_ref().as_ref())
        }
    }
    pub fn deserialize<'de, T: CryptoImport, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<T, D::Error> {
        let val = if <T::Bytes as HasCryptoLen>::is_fixed_length() {
            // We're fixed-size, we need a full-on visitor because serde is annoying
            struct BytesVisitor<T: CryptoImport>(PhantomData<T>);
            impl<'de, T: CryptoImport> Visitor<'de> for BytesVisitor<T> {
                type Value = T;

                fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                    let len = <<T::Bytes as HasCryptoLen>::Length as Bitstring>::UNSIGNED;
                    write!(formatter, "a byte array of length {}", len)
                }

                fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
                where
                    A: SeqAccess<'de>,
                {
                    let len = <<T::Bytes as HasCryptoLen>::Length as Bitstring>::UNSIGNED;
                    // Create a zeroed container of the right length, which we can then put into
                    // the `T` itself (this is the bytes input, which most of the time is the same
                    // thing)
                    let mut bytes = <T::Bytes as HasCryptoLen>::zeroed();

                    for i in 0..len {
                        let byte: u8 = seq
                            .next_element()?
                            // If the sequence ended early, we have a corruption relative to the
                            // length we were expecting
                            .ok_or_else(|| serde::de::Error::invalid_length(i, &self))?;
                        bytes.as_mut()[i] = byte;
                    }

                    // NOTE: For our implementation of `CryptoImport` for anything that implements
                    // `HasCryptoLen`, this will be cloning our bytes into the exact same thing,
                    // which *should* get optimised away...
                    T::from_bytes_exact(&bytes).map_err(serde::de::Error::custom)
                }
            }

            let len = <<T::Bytes as HasCryptoLen>::Length as Bitstring>::UNSIGNED;
            deserializer.deserialize_tuple(len, BytesVisitor(PhantomData))?
        } else {
            // We're variable-length, this will get a `&[u8]` and add a length prefix
            let bytes = Vec::<u8>::deserialize(deserializer)?;
            // This can't fail, we have variable-length bytes, but the underlying conversion from
            // the correct size *might* fail
            T::from_bytes(&bytes).map_err(serde::de::Error::custom)?
        };

        Ok(val)
    }
}

// NOTE: Unfortunately, we can't implement for anything that implements [`CryptoIo`] due to foreign
// trait restrictions. This works fine though.

impl<C: PublicKeyCryptosystem> Serialize for PublicKey<C> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        base64_standard::serialize(self, serializer)
    }
}
impl<'de, C: PublicKeyCryptosystem> Deserialize<'de> for PublicKey<C> {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        base64_standard::deserialize(deserializer)
    }
}

impl<C: PublicKeyCryptosystem> Serialize for SecretKey<C> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        base64_standard::serialize(self, serializer)
    }
}
impl<'de, C: PublicKeyCryptosystem> Deserialize<'de> for SecretKey<C> {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        base64_standard::deserialize(deserializer)
    }
}

impl<C: SymmetricCryptosystem> Serialize for SymmetricKey<C> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        base64_standard::serialize(self, serializer)
    }
}
impl<'de, C: SymmetricCryptosystem> Deserialize<'de> for SymmetricKey<C> {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        base64_standard::deserialize(deserializer)
    }
}

impl<C: SigningCryptosystem> Serialize for Signature<C> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        base64_standard::serialize(self, serializer)
    }
}
impl<'de, C: SigningCryptosystem> Deserialize<'de> for Signature<C> {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        base64_standard::deserialize(deserializer)
    }
}

impl<C: KeyEncapsulationCryptosystem> Serialize for Encapsulation<C> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        base64_standard::serialize(self, serializer)
    }
}
impl<'de, C: KeyEncapsulationCryptosystem> Deserialize<'de> for Encapsulation<C> {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        base64_standard::deserialize(deserializer)
    }
}

impl<C: KeyEncapsulationCryptosystem> Serialize for SharedSecret<C> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        base64_standard::serialize(self, serializer)
    }
}
// NOTE: Shared secrets can't be imported, so no deserializing impl

#[cfg(test)]
mod tests {
    use crate::{Const, CryptoArray};
    use serde::{Deserialize, Serialize};

    #[test]
    fn fixed_array_should_have_no_overhead() {
        #[derive(Serialize, Deserialize)]
        struct Test {
            #[serde(with = "crate::serde::bytes")]
            field: CryptoArray<Const<10>>,
        }

        let fixed_array = CryptoArray::<Const<10>>::from_slice(&[2u8; 10]).unwrap();
        let test = Test { field: fixed_array };
        let serialized = bincode::serialize(&test).unwrap();
        assert_eq!(serialized, [2u8; 10]);
        let deserialized: Test = bincode::deserialize(&serialized).unwrap();
        assert_eq!(deserialized.field.as_ref(), &[2u8; 10]);
    }

    #[test]
    fn variable_array_should_have_overhead() {
        #[derive(Serialize, Deserialize)]
        struct Test {
            #[serde(with = "crate::serde::bytes")]
            field: CryptoArray<Const<0>>,
        }

        let fixed_array = CryptoArray::<Const<0>>::from_slice(&[2u8; 10]).unwrap();
        let test = Test { field: fixed_array };
        let serialized = bincode::serialize(&test).unwrap();
        assert!(serialized.len() > 10);
        let deserialized: Test = bincode::deserialize(&serialized).unwrap();
        assert_eq!(deserialized.field.as_ref(), &[2u8; 10]);
    }
}
