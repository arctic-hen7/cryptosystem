/// Auto-generates tests for the provided symmetric cryptosystem, which should be specified by its
/// import path as if it were being used in a submodule (typically `super::CryptosystemName`).
/// These tests cover basic things like signing and verification, and do **not** test security
/// properties! They represent an absolute minimum to test that the given cryptosystem is actually
/// usable, and should be extended by the implementor.
#[macro_export]
macro_rules! symmetric_cryptosystem_tests {
    ($cs:ty) => {
        #[cfg(test)]
        mod __symmetric_cryptosystem_tests {
            use crate::cryptosystem::SymmetricCryptosystem;

            #[test]
            fn generate_symmetric_key_succeeds() {
                let key = <$cs>::generate_key();
                // Make sure it works by encrypting something
                <$cs>::encrypt(b"Hello, world!", &key).unwrap();
            }
            #[test]
            fn encrypt_and_decrypt_symmetric_succeeds() {
                let key = <$cs>::generate_key();
                let plaintext = b"Hello, world!";
                let ciphertext = <$cs>::encrypt(plaintext, &key).unwrap();
                let decrypted = <$cs>::decrypt(&ciphertext, &key).unwrap();
                assert_eq!(plaintext, decrypted.as_slice());
            }
            #[test]
            fn encrypt_and_decrypt_symmetric_fails_with_modified_ciphertext() {
                let key = <$cs>::generate_key();
                let plaintext = b"Hello, world!";
                let mut ciphertext = <$cs>::encrypt(plaintext, &key).unwrap();
                ciphertext[32] ^= 1;
                let decrypted = <$cs>::decrypt(&ciphertext, &key);
                assert!(decrypted.is_err());
            }
            #[test]
            fn encrypt_and_decrypt_symmetric_fails_with_bad_key() {
                let key = <$cs>::generate_key();
                let bad_key = <$cs>::generate_key();

                let plaintext = b"Hello, world!";
                let ciphertext = <$cs>::encrypt(plaintext, &key).unwrap();
                let decrypted = <$cs>::decrypt(&ciphertext, &bad_key);
                assert!(decrypted.is_err());
            }
        }
    };
}

/// Auto-generates tests for the provided signing cryptosystem, which should be specified by its
/// import path as if it were being used in a submodule (typically `super::CryptosystemName`).
/// These tests cover basic things like signing and verification, and do **not** test security
/// properties! They represent an absolute minimum to test that the given cryptosystem is actually
/// usable, and should be extended by the implementor.
#[macro_export]
macro_rules! signing_cryptosystem_tests {
    ($cs:ty) => {
        #[cfg(test)]
        mod __signing_cryptosystem_tests {
            use crate::cryptosystem::{PublicKeyCryptosystem, SigningCryptosystem};

            #[test]
            fn generate_signing_keypair_succeeds() {
                let (_pub_key, sec_key) = <$cs>::generate_keypair();
                // Make sure it works by signing something
                <$cs>::sign(b"Hello, world!", &sec_key).unwrap();
            }
            #[test]
            fn sign_and_verify_succeeds() {
                let (pub_key, sec_key) = <$cs>::generate_keypair();

                let plaintext = b"Hello, world!";
                let signature = <$cs>::sign(plaintext, &sec_key).unwrap();
                let result = <$cs>::verify(&signature, plaintext, &pub_key);
                assert!(result.is_ok());
            }
            #[test]
            fn sign_and_verify_fails_with_bad_key() {
                let (pub_key, _) = <$cs>::generate_keypair();
                let (_, bad_sec_key) = <$cs>::generate_keypair();

                let plaintext = b"Hello, world!";
                let signature = <$cs>::sign(plaintext, &bad_sec_key).unwrap();
                let result = <$cs>::verify(&signature, plaintext, &pub_key);
                assert!(result.is_err());
            }
            #[test]
            fn sign_and_verify_fails_with_bad_signature() {
                let (pub_key, sec_key) = <$cs>::generate_keypair();

                let plaintext = b"Hello, world!";
                let mut signature = <$cs>::sign(plaintext, &sec_key).unwrap();
                signature[0] ^= 1;
                let result = <$cs>::verify(&signature, plaintext, &pub_key);
                assert!(result.is_err());
            }
        }
    };
}

/// Automatically writes tests for cryptosystems based on a default set of parameters. These cover
/// very broad things like random byte alterations within keys, and general interface properties,
/// so individual implementations should add additional tests if they have further edge cases.
macro_rules! cryptosys_tests {
    ($cs:ty) => {
        #[cfg(test)]
        mod __cryptosys_tests {
            use super::*;
            use crate::Cryptosystem;

            struct Test {
                foo: String,
            }
            // TODO Bytes impls

            #[test]
            fn generate_asymmetric_keypair_succeeds(
            ) -> Result<(), CryptoError<<$cs as Cryptosystem>::Error>> {
                let (pub_key, _sec_key) = <$cs>::generate_asymmetric_keypair()?;
                // Make sure it works by encrypting something
                <$cs>::a_encrypt(&"Hello, world!".to_string(), &pub_key)?;

                Ok(())
            }

            #[cfg(feature = "master-key")]
            #[test]
            fn encrypt_and_decrypt_asymmetric_succeeds(
            ) -> Result<(), CryptoError<<$cs as Cryptosystem>::Error>> {
                let (pub_key, sec_key) = <$cs>::generate_asymmetric_keypair()?;

                let plaintext = "Hello, world!".to_string();
                let ciphertext = <$cs>::a_encrypt(&plaintext, &pub_key)?;
                let decrypted = <$cs>::a_decrypt(&ciphertext, &sec_key)?;
                assert_eq!(plaintext, decrypted);

                Ok(())
            }
            #[cfg(feature = "master-key")]
            #[test]
            fn encrypt_and_decrypt_asymmetric_succeeds_for_object(
            ) -> Result<(), CryptoError<<$cs as Cryptosystem>::Error>> {
                #[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
                struct Test {
                    foo: String,
                }

                let obj = Test {
                    foo: "Bar!".to_string(),
                };
                let (pub_key, sec_key) = <$cs>::generate_asymmetric_keypair()?;

                let ciphertext = <$cs>::a_encrypt(&obj, &pub_key)?;
                let decrypted = <$cs>::a_decrypt(&ciphertext, &sec_key)?;
                assert_eq!(obj, decrypted);

                Ok(())
            }
            #[cfg(feature = "master-key")]
            #[test]
            fn encrypt_and_decrypt_asymmetric_fails_with_modified_ciphertext(
            ) -> Result<(), CryptoError<<$cs as Cryptosystem>::Error>> {
                let (pub_key, sec_key) = <$cs>::generate_asymmetric_keypair()?;

                let plaintext = "Hello, world!".to_string();
                let mut ciphertext = <$cs>::a_encrypt(&plaintext, &pub_key)?;
                ciphertext.data[32] ^= 1;
                let decrypted = <$cs>::a_decrypt(&ciphertext, &sec_key);
                assert!(decrypted.is_err());

                Ok(())
            }
            #[cfg(feature = "master-key")]
            #[test]
            fn encrypt_and_decrypt_asymmetric_fails_with_bad_key(
            ) -> Result<(), CryptoError<<$cs as Cryptosystem>::Error>> {
                let (pub_key, _) = <$cs>::generate_asymmetric_keypair()?;
                let (_, bad_sec_key) = <$cs>::generate_asymmetric_keypair()?;

                let plaintext = "Hello, world!".to_string();
                let ciphertext = <$cs>::a_encrypt(&plaintext, &pub_key)?;
                let decrypted = <$cs>::a_decrypt(&ciphertext, &bad_sec_key);
                assert!(decrypted.is_err());

                Ok(())
            }

            #[test]
            fn hash_succeeds() -> Result<(), CryptoError<<$cs as Cryptosystem>::Error>> {
                let plaintext = "Hello, world!".to_string();
                let hash = <$cs>::hash(&plaintext);
                assert!(hash.is_ok());

                Ok(())
            }
            #[test]
            fn hash_succeeds_for_object() -> Result<(), CryptoError<<$cs as Cryptosystem>::Error>> {
                #[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
                struct Test {
                    foo: String,
                }

                let obj = Test {
                    foo: "Bar!".to_string(),
                };
                let hash = <$cs>::hash(&obj);
                assert!(hash.is_ok());

                Ok(())
            }
        }
    };
}