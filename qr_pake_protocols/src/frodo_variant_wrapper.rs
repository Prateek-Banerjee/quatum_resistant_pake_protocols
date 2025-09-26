use super::protocol_variants::AvailableVariants::{self, *};
use frodo_kem_rs::Algorithm::{FrodoKem1344Shake, FrodoKem640Shake, FrodoKem976Shake};
use rand_core::OsRng;

/// Struct that dispatches Frodo-KEM operations based on the selected variant.
///
/// # Fields:
/// - `variant`: `AvailableVariants` - The chosen Frodo-KEM variant for dispatching.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FrodoKemDispatcher {
    variant: AvailableVariants,
}

impl FrodoKemDispatcher {
    /// Creates a new instance of the `FrodoKemDispatcher` initialized with the given variant.
    ///
    /// # Parameters:
    /// - `variant`: `AvailableVariants` - The variant to associate with the new instance.
    ///
    /// # Returns:
    /// A new `FrodoKemDispatcher` instance of the specified `variant`.
    pub fn new(variant: AvailableVariants) -> Self {
        Self { variant }
    }

    /// Generates a public/private KEM key pair.
    ///
    /// # Returns:
    /// A tuple containing:
    /// - `(Vec<u8>)` – The public key bytes.
    /// - `(Vec<u8>)` – The secret key bytes.
    pub fn keygen(&self) -> (Vec<u8>, Vec<u8>) {
        match self.variant {
            LightWeight => {
                let (pk, sk) = FrodoKem640Shake.try_generate_keypair(OsRng).unwrap();
                let pk_as_vec = pk.as_ref().to_vec();
                let sk_as_vec = sk.as_ref().to_vec();
                (pk_as_vec, sk_as_vec)
            }
            Recommended => {
                let (pk, sk) = FrodoKem976Shake.try_generate_keypair(OsRng).unwrap();
                let pk_as_vec = pk.as_ref().to_vec();
                let sk_as_vec = sk.as_ref().to_vec();
                (pk_as_vec, sk_as_vec)
            }
            Paranoid => {
                let (pk, sk) = FrodoKem1344Shake.try_generate_keypair(OsRng).unwrap();
                let pk_as_vec = pk.as_ref().to_vec();
                let sk_as_vec = sk.as_ref().to_vec();
                (pk_as_vec, sk_as_vec)
            }
        }
    }

    /// Encapsulates the provided KEM public key.
    ///
    /// # Parameters:
    /// - `pk_as_slice`: `&[u8]` - The KEM public key bytes.
    ///
    /// # Returns:
    /// A tuple containing:
    /// - `Vec<u8>` – The KEM ciphertext.
    /// - `Vec<u8>` – The shared secret key derived from the encapsulation.
    pub fn encapsulate(&self, pk_as_slice: &[u8]) -> (Vec<u8>, Vec<u8>) {
        match self.variant {
            LightWeight => {
                let pk_converted = FrodoKem640Shake
                    .encryption_key_from_bytes(pk_as_slice)
                    .unwrap();
                let (kem_ciphertext, shared_secret_key) = FrodoKem640Shake
                    .try_encapsulate_with_rng(&pk_converted, OsRng)
                    .unwrap();
                let kem_ciphertext_as_vec: Vec<u8> = kem_ciphertext.as_ref().to_vec();
                let shared_secret_key_as_vec: Vec<u8> = shared_secret_key.as_ref().to_vec();
                (kem_ciphertext_as_vec, shared_secret_key_as_vec)
            }
            Recommended => {
                let pk_converted = FrodoKem976Shake
                    .encryption_key_from_bytes(pk_as_slice)
                    .unwrap();
                let (kem_ciphertext, shared_secret_key) = FrodoKem976Shake
                    .try_encapsulate_with_rng(&pk_converted, OsRng)
                    .unwrap();
                let kem_ciphertext_as_vec: Vec<u8> = kem_ciphertext.as_ref().to_vec();
                let shared_secret_key_as_vec: Vec<u8> = shared_secret_key.as_ref().to_vec();
                (kem_ciphertext_as_vec, shared_secret_key_as_vec)
            }
            Paranoid => {
                let pk_converted = FrodoKem1344Shake
                    .encryption_key_from_bytes(pk_as_slice)
                    .unwrap();
                let (kem_ciphertext, shared_secret_key) = FrodoKem1344Shake
                    .try_encapsulate_with_rng(&pk_converted, OsRng)
                    .unwrap();
                let kem_ciphertext_as_vec: Vec<u8> = kem_ciphertext.as_ref().to_vec();
                let shared_secret_key_as_vec: Vec<u8> = shared_secret_key.as_ref().to_vec();
                (kem_ciphertext_as_vec, shared_secret_key_as_vec)
            }
        }
    }

    /// Decapsulates the given KEM ciphertext using the KEM secret key.
    ///
    /// # Parameters:
    /// - `kem_ciphertext`: `&[u8]` – The KEM ciphertext.
    /// - `sk_as_slice`: `&[u8]` – The KEM secret key.
    ///
    /// # Returns:
    /// `Vec<u8>` – The shared secret key derived from the decapsulation.
    pub fn decapsulate(&self, kem_ciphertext: &[u8], sk_as_slice: &[u8]) -> Vec<u8> {
        match self.variant {
            LightWeight => {
                let sk_converted = FrodoKem640Shake
                    .decryption_key_from_bytes(sk_as_slice)
                    .unwrap();
                let kem_ciphertext_converted = FrodoKem640Shake
                    .ciphertext_from_bytes(kem_ciphertext)
                    .unwrap();
                let (shared_secret_key, _) = FrodoKem640Shake
                    .decapsulate(&sk_converted, &kem_ciphertext_converted)
                    .unwrap();
                let shared_secret_key_as_vec = shared_secret_key.as_ref().to_vec();
                shared_secret_key_as_vec
            }
            Recommended => {
                let sk_converted = FrodoKem976Shake
                    .decryption_key_from_bytes(sk_as_slice)
                    .unwrap();
                let kem_ciphertext_converted = FrodoKem976Shake
                    .ciphertext_from_bytes(kem_ciphertext)
                    .unwrap();
                let (shared_secret_key, _) = FrodoKem976Shake
                    .decapsulate(&sk_converted, &kem_ciphertext_converted)
                    .unwrap();
                let shared_secret_key_as_vec = shared_secret_key.as_ref().to_vec();
                shared_secret_key_as_vec
            }
            Paranoid => {
                let sk_converted = FrodoKem1344Shake
                    .decryption_key_from_bytes(sk_as_slice)
                    .unwrap();
                let kem_ciphertext_converted = FrodoKem1344Shake
                    .ciphertext_from_bytes(kem_ciphertext)
                    .unwrap();
                let (shared_secret_key, _) = FrodoKem1344Shake
                    .decapsulate(&sk_converted, &kem_ciphertext_converted)
                    .unwrap();
                let shared_secret_key_as_vec = shared_secret_key.as_ref().to_vec();
                shared_secret_key_as_vec
            }
        }
    }
}
