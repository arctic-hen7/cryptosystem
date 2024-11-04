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
            use $crate::cryptosystem::SymmetricCryptosystem;

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
macro_rules! key_exchange_cryptosystem_tests {
    ($cs:ty) => {
        #[cfg(test)]
        mod __key_exchange_cryptosystem_tests {
            use $crate::cryptosystem::{KeyExchangeCryptosystem, PublicKeyCryptosystem};

            #[test]
            fn generate_keypair_succeeds() {
                let (_pub_key, _sec_key) = <$cs>::generate_keypair();
            }
            #[test]
            fn derive_shared_secret_succeeds() {
                let (alice_pub_key, alice_sec_key) = <$cs>::generate_keypair();
                let (bob_pub_key, bob_sec_key) = <$cs>::generate_keypair();

                let alice_shared =
                    <$cs>::generate_shared_secret(&bob_sec_key, &alice_pub_key).unwrap();
                let bob_shared =
                    <$cs>::generate_shared_secret(&alice_sec_key, &bob_pub_key).unwrap();

                assert_eq!(
                    <$cs>::export_shared_secret(&alice_shared),
                    <$cs>::export_shared_secret(&bob_shared)
                );
            }
        }
    };
}
