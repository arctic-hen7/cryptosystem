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
            use $crate::crypto_array::CryptoArraySum;
            use $crate::cryptosystem::SymmetricCryptosystem;

            #[test]
            fn generate_symmetric_key_succeeds() {
                let key = <$cs>::generate_key();
                // A vector will always work as a buffer
                let mut buf = Vec::new();
                // Make sure it works by encrypting something
                <$cs>::encrypt_to_buf(b"Hello, world!", &key, &mut buf).unwrap();
            }
            #[test]
            fn encrypt_and_decrypt_symmetric_succeeds() {
                let key = <$cs>::generate_key();
                let plaintext = b"Hello, world!"; // 13 bytes
                let mut ciphertext_buf =
                    CryptoArraySum::<[u8; 13], <$cs as SymmetricCryptosystem>::OverheadBytes>::new(
                    );
                <$cs>::encrypt_to_buf(plaintext, &key, &mut ciphertext_buf).unwrap();
                let mut plaintext_buf = [0u8; 13];
                <$cs>::decrypt_to_buf(&ciphertext_buf, &key, &mut plaintext_buf).unwrap();
                assert_eq!(plaintext, plaintext_buf.as_slice());
            }
            #[test]
            fn encrypt_and_decrypt_symmetric_fails_with_modified_ciphertext() {
                let key = <$cs>::generate_key();
                let plaintext = b"Hello, world!"; // 13 bytes
                let mut ciphertext_buf =
                    CryptoArraySum::<[u8; 13], <$cs as SymmetricCryptosystem>::OverheadBytes>::new(
                    );
                <$cs>::encrypt_to_buf(plaintext, &key, &mut ciphertext_buf).unwrap();
                ciphertext_buf[32] ^= 1;
                let mut plaintext_buf = [0u8; 13];
                assert!(<$cs>::decrypt_to_buf(&ciphertext_buf, &key, &mut plaintext_buf).is_err());
            }
            #[test]
            fn encrypt_and_decrypt_symmetric_fails_with_bad_key() {
                let key = <$cs>::generate_key();
                let bad_key = <$cs>::generate_key();

                let plaintext = b"Hello, world!"; // 13 bytes
                let mut ciphertext_buf =
                    CryptoArraySum::<[u8; 13], <$cs as SymmetricCryptosystem>::OverheadBytes>::new(
                    );
                <$cs>::encrypt_to_buf(plaintext, &key, &mut ciphertext_buf).unwrap();
                let mut plaintext_buf = [0u8; 13];
                assert!(
                    <$cs>::decrypt_to_buf(&ciphertext_buf, &bad_key, &mut plaintext_buf).is_err()
                );
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
            use $crate::cryptosystem::{PublicKeyCryptosystem, SigningCryptosystem};

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

/// Auto-generates tests for the provided key exchange cryptosystem, which should be specified by
/// its import path as if it were being used in a submodule (typically `super::CryptosystemName`).
/// These tests cover basic things actual exchange, and do **not** test security properties! They
/// represent an absolute minimum to test that the given cryptosystem is actually usable, and
/// should be extended by the implementor.
#[macro_export]
macro_rules! key_encapsulation_cryptosystem_tests {
    ($cs:ty) => {
        #[cfg(test)]
        mod __key_exchange_cryptosystem_tests {
            use $crate::cryptosystem::{KeyEncapsulationCryptosystem, PublicKeyCryptosystem};

            #[test]
            fn generate_keypair_succeeds() {
                let (_pub_key, _sec_key) = <$cs>::generate_keypair();
            }
            #[test]
            fn derive_shared_secret_succeeds() {
                let (bob_pub_key, bob_sec_key) = <$cs>::generate_keypair();

                let (encapsulation, alice_shared) = <$cs>::encapsulate(&bob_pub_key).unwrap();
                let bob_shared = <$cs>::decapsulate(&encapsulation, &bob_sec_key).unwrap();

                assert_eq!(
                    <$cs>::export_shared_secret(&alice_shared),
                    <$cs>::export_shared_secret(&bob_shared)
                );
            }
        }
    };
}
