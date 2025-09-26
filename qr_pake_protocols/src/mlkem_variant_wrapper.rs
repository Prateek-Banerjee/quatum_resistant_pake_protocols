use super::protocol_variants::AvailableVariants::{self, *};
use ml_kem::{
    kem::{Decapsulate, Encapsulate, Kem},
    EncodedSizeUser, KemCore, MlKem1024, MlKem1024Params, MlKem512, MlKem512Params, MlKem768,
    MlKem768Params, B32,
};
use rand::rngs::OsRng;

/// Struct that dispatches ML-KEM operations based on the selected variant.
///
/// # Fields:
/// - `variant`: `AvailableVariants` - The chosen Kyber variant for dispatching.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MlKemDispatcher {
    variant: AvailableVariants,
}

impl MlKemDispatcher {
    /// Creates a new instance of the `MlKemDispatcher` initialized with the given variant.
    ///
    /// # Parameters:
    /// - `variant`: `AvailableVariants` - The variant to associate with the new instance.
    ///
    /// # Returns:
    /// A new `MlKemDispatcher` instance of the specified `variant`.
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
                let (sk, pk) = MlKem512::generate(&mut OsRng);
                (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
            }
            Recommended => {
                let (sk, pk) = MlKem768::generate(&mut OsRng);
                (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
            }
            Paranoid => {
                let (sk, pk) = MlKem1024::generate(&mut OsRng);
                (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
            }
        }
    }

    /// Generates a public/private KEM key pair from a 64-byte seed.
    ///
    /// # Parameters:
    /// - `seed`: `&[u8]` - A 64-byte seed used for deterministic key generation.
    ///
    /// # Panics
    /// This method will panic if:
    /// - `seed.len() != 64` – The seed must be exactly 64 bytes in length.
    ///
    /// # Returns:
    /// A tuple containing:
    /// - `Vec<u8>` – The public key bytes.
    /// - `Vec<u8>` – The secret key bytes.
    pub fn keygen_seeded(&self, seed: &[u8]) -> (Vec<u8>, Vec<u8>) {
        // The seed length must be 64 bytes
        if seed.len() != 64 {
            panic!(
                "The seed length must be 64 bytes whereas it is {}",
                seed.len()
            );
        }

        // Split the given seed into two 32 byte seeds
        let (sd_1_as_slice, sd_2_as_slice) = seed.split_at(32);

        // Convert them into B32 type
        let sd_1 = self.convert_to_b32(sd_1_as_slice);
        let sd_2 = self.convert_to_b32(sd_2_as_slice);

        match self.variant {
            LightWeight => {
                let (sk, pk) = MlKem512::generate_deterministic(&sd_1, &sd_2);
                (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
            }
            Recommended => {
                let (sk, pk) = MlKem768::generate_deterministic(&sd_1, &sd_2);
                (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
            }
            Paranoid => {
                let (sk, pk) = MlKem1024::generate_deterministic(&sd_1, &sd_2);
                (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
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
                let pk_converted = self.convert_pk_slice(pk_as_slice);
                let pk_as_key = AnyEncapKey::as_any(&*pk_converted)
                    .downcast_ref::<<Kem<MlKem512Params> as KemCore>::EncapsulationKey>()
                    .unwrap();
                let (kem_ciphertext, shared_secret_key) =
                    pk_as_key.encapsulate(&mut OsRng).unwrap();
                (kem_ciphertext.to_vec(), shared_secret_key.to_vec())
            }
            Recommended => {
                let pk_converted = self.convert_pk_slice(pk_as_slice);
                let pk_as_key = AnyEncapKey::as_any(&*pk_converted)
                    .downcast_ref::<<Kem<MlKem768Params> as KemCore>::EncapsulationKey>()
                    .unwrap();
                let (kem_ciphertext, shared_secret_key) =
                    pk_as_key.encapsulate(&mut OsRng).unwrap();
                (kem_ciphertext.to_vec(), shared_secret_key.to_vec())
            }
            Paranoid => {
                let pk_converted = self.convert_pk_slice(pk_as_slice);
                let pk_as_key = AnyEncapKey::as_any(&*pk_converted)
                    .downcast_ref::<<Kem<MlKem1024Params> as KemCore>::EncapsulationKey>()
                    .unwrap();
                let (kem_ciphertext, shared_secret_key) =
                    pk_as_key.encapsulate(&mut OsRng).unwrap();
                (kem_ciphertext.to_vec(), shared_secret_key.to_vec())
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
                let sk_converted = self.convert_sk_slice(sk_as_slice);
                let sk_as_key = AnyDecapKey::as_any(&*sk_converted).downcast_ref::<<Kem<ml_kem::MlKem512Params> as ml_kem::KemCore>::DecapsulationKey>().unwrap();
                let kem_ciphertext_as_array =
                    ml_kem::Ciphertext::<MlKem512>::try_from(kem_ciphertext).unwrap();
                sk_as_key
                    .decapsulate(&kem_ciphertext_as_array)
                    .unwrap()
                    .to_vec()
            }
            Recommended => {
                let sk_converted = self.convert_sk_slice(sk_as_slice);
                let sk_as_key = AnyDecapKey::as_any(&*sk_converted).downcast_ref::<<Kem<ml_kem::MlKem768Params> as ml_kem::KemCore>::DecapsulationKey>().unwrap();
                let kem_ciphertext_as_array =
                    ml_kem::Ciphertext::<MlKem768>::try_from(kem_ciphertext).unwrap();
                sk_as_key
                    .decapsulate(&kem_ciphertext_as_array)
                    .unwrap()
                    .to_vec()
            }
            Paranoid => {
                let sk_converted = self.convert_sk_slice(sk_as_slice);
                let sk_as_key = AnyDecapKey::as_any(&*sk_converted).downcast_ref::<<Kem<ml_kem::MlKem1024Params> as ml_kem::KemCore>::DecapsulationKey>().unwrap();
                let kem_ciphertext_as_array =
                    ml_kem::Ciphertext::<MlKem1024>::try_from(kem_ciphertext).unwrap();
                sk_as_key
                    .decapsulate(&kem_ciphertext_as_array)
                    .unwrap()
                    .to_vec()
            }
        }
    }

    /// Converts a raw KEM public key byte slice into a boxed encapsulation key object.
    ///
    /// # Parameters:
    /// - `pk_as_slice`: `&[u8]` - The KEM public key bytes to convert.
    ///
    /// # Panics
    /// This method will panic if:
    /// - `pk_as_slice` cannot be converted into the expected key length.
    ///
    /// # Returns:
    /// `Box<dyn AnyEncapKey>` – A boxed dynamic encapsulation key ready for use in KEM operations.
    fn convert_pk_slice(&self, pk_as_slice: &[u8]) -> Box<dyn AnyEncapKey> {
        match self.variant {
            LightWeight => {
                let key = <MlKem512 as KemCore>::EncapsulationKey::from_bytes(
                    pk_as_slice.try_into().expect("Invalid key length"),
                );
                Box::new(key)
            }
            Recommended => {
                let key = <MlKem768 as KemCore>::EncapsulationKey::from_bytes(
                    pk_as_slice.try_into().expect("Invalid key length"),
                );
                Box::new(key)
            }
            Paranoid => {
                let key = <MlKem1024 as KemCore>::EncapsulationKey::from_bytes(
                    pk_as_slice.try_into().expect("Invalid key length"),
                );
                Box::new(key)
            }
        }
    }

    /// Converts a raw KEM secret key byte slice into a boxed decapsulation key object.
    ///
    /// # Parameters:
    /// - `sk_as_slice`: `&[u8]` - The KEM secret key bytes to convert.
    ///
    /// # Panics
    /// This method will panic if:
    /// - `sk_as_slice` cannot be converted into the expected key length.
    ///
    /// # Returns:
    /// `Box<dyn AnyDecapKey>` – A boxed dynamic decapsulation key ready for use in KEM operations.
    fn convert_sk_slice(&self, sk_as_slice: &[u8]) -> Box<dyn AnyDecapKey> {
        match self.variant {
            LightWeight => {
                let key = <MlKem512 as KemCore>::DecapsulationKey::from_bytes(
                    sk_as_slice.try_into().expect("Invalid key length"),
                );
                Box::new(key)
            }
            Recommended => {
                let key = <MlKem768 as KemCore>::DecapsulationKey::from_bytes(
                    sk_as_slice.try_into().expect("Invalid key length"),
                );
                Box::new(key)
            }
            Paranoid => {
                let key = <MlKem1024 as KemCore>::DecapsulationKey::from_bytes(
                    sk_as_slice.try_into().expect("Invalid key length"),
                );
                Box::new(key)
            }
        }
    }

    /// Converts a 32-byte slice into a `B32` type.
    ///
    /// # Parameters:
    /// - `slice`: `&[u8]` – A byte slice expected to be exactly 32 bytes long.
    ///
    /// # Returns:
    /// `B32` – The converted 32-byte value wrapped in the `B32` type.
    fn convert_to_b32(&self, slice: &[u8]) -> B32 {
        B32::try_from(slice).expect("Slice must be 32 bytes")
    }
}

pub trait AnyEncapKey: Send + Sync {
    fn as_any(&self) -> &dyn core::any::Any;
}
impl<T: 'static + Send + Sync> AnyEncapKey for T {
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }
}
pub trait AnyDecapKey: Send + Sync {
    fn as_any(&self) -> &dyn core::any::Any;
}
impl<T: 'static + Send + Sync> AnyDecapKey for T {
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }
}
