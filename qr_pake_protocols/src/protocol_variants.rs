use super::{frodo_variant_wrapper::FrodoKemDispatcher, mlkem_variant_wrapper::MlKemDispatcher};
use serde::{Deserialize, Serialize};
use serde_json::to_vec;
use strum_macros::EnumIter;

/// Enum representing the available variants depending on the choice of KEM.
///
/// # Fields:
/// - `LightWeight`: Corresponds to Kyber-512 / Frodo640Shake.
/// - `Recommended`: Corresponds to Kyber-768 / Frodo976Shake.
/// - `Paranoid`: Corresponds to Kyber-1024 / Frodo1344Shake.
#[derive(Clone, Copy, Debug, EnumIter, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub enum AvailableVariants {
    LightWeight,
    Recommended,
    Paranoid,
}

impl AvailableVariants {
    /// Returns an ML-KEM dispatcher/Kyber instance based on the protocol variant.
    ///
    /// # Returns:
    /// - `MlKemDispatcher`: An instance of `MlKemDispatcher` corresponding to the current protocol variant.
    pub fn kyber_instance(self) -> MlKemDispatcher {
        match self {
            Self::LightWeight => MlKemDispatcher::new(Self::LightWeight),
            Self::Recommended => MlKemDispatcher::new(Self::Recommended),
            Self::Paranoid => MlKemDispatcher::new(Self::Paranoid),
        }
    }

    /// Returns a Frodo-KEM dispatcher instance based on the protocol variant.
    ///
    /// # Returns:
    /// - `FrodoKemDispatcher`: An instance of `FrodoKemDispatcher` corresponding to the current protocol variant.    
    pub fn frodo_instance(self) -> FrodoKemDispatcher {
        match self {
            Self::LightWeight => FrodoKemDispatcher::new(Self::LightWeight),
            Self::Recommended => FrodoKemDispatcher::new(Self::Recommended),
            Self::Paranoid => FrodoKemDispatcher::new(Self::Paranoid),
        }
    }

    /// Returns the Variant name as a `Vec<u8>`
    pub fn to_bytes(&self) -> Vec<u8> {
        to_vec(self).expect("Failed to serialize the variant")
    }
}

/// Enum representing the available choice of KEMs.
///
/// # Fields:
/// - `Kyber`
/// - `Frodo`
#[derive(Clone, Copy, Debug, EnumIter, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub enum KemChoice {
    Kyber,
    Frodo,
}

impl KemChoice {
    /// Returns the KEM name as a `Vec<u8>`
    pub fn to_bytes(&self) -> Vec<u8> {
        to_vec(self).expect("Failed to serialize the KEM choice")
    }
}
