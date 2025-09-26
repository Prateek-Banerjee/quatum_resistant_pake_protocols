/*
[1] Towards post-quantum secure PAKE-A tight security proof for OCAKE in the BPR model
https://eprint.iacr.org/2023/1368.pdf
*/

use super::{common_details::*, server::SERVER_ID};
use crate::{
    frodo_variant_wrapper::FrodoKemDispatcher,
    mlkem_variant_wrapper::MlKemDispatcher,
    overall_common_functionalities::{encrypt_data, get_base_encoded_pk, get_kyber_instance},
    protocol_variants::{
        AvailableVariants,
        KemChoice::{self, *},
    },
};
use zeroize::Zeroize;

/// Represents an OCAKE client with an ID, password, and protocol variant.
///
/// # Fields:
/// - `client_id`: `Vec<u8>` - The client's unique identifier.
/// - `client_password`: `Vec<u8>` - The client's password.
/// - `protocol_variant`: `AvailableVariants` - The protocol variant used by the client.
/// - `kem_choice`: `Option<KemChoice>` - Optional choice of KEM used by the client.
/// - `kyber_instance`: `Option<MlKemDispatcher>` - Optional dispatcher for instance of ML-KEM.
/// - `frodo_instance`: `Option<FrodoKemDispatcher>` - Optional dispatcher for instance of Frodo-KEM when `frodo` feature is used.
/// - `pk`: `Option<Vec<u8>>` - Optional KEM public key.
/// - `sk`: `Option<Vec<u8>>` - Optional KEM secret key.
/// - `c`: `Option<Vec<u8>>` - Optional ciphertext.
#[derive(Clone)]
pub struct OcakeClient {
    client_id: Vec<u8>,
    client_password: Vec<u8>,
    protocol_variant: AvailableVariants,
    kem_choice: Option<KemChoice>,
    kyber_instance: Option<MlKemDispatcher>,
    frodo_instance: Option<FrodoKemDispatcher>,
    pk: Option<Vec<u8>>,
    sk: Option<Vec<u8>>,
    c: Option<Vec<u8>>,
}

impl Default for OcakeClient {
    fn default() -> Self {
        OcakeClient {
            client_id: b"The OCAKE PAKE client ID".to_vec(),
            client_password: b"This is the password for client.".to_vec(),
            protocol_variant: AvailableVariants::Recommended,
            kem_choice: Some(Kyber),
            kyber_instance: None,
            frodo_instance: None,
            pk: None,
            sk: None,
            c: None,
        }
    }
}

impl OcakeClient {
    /// Creates a new `OcakeClient` with the specified ID, password, chosen protocol variant and KEM.
    ///
    /// # Parameters:
    /// - `client_id`: `Vec<u8>` - The client's unique identifier.
    /// - `client_password`: `Vec<u8>` - The client's password.
    /// - `protocol_variant`: `AvailableVariants` - The chosen protocol variant.
    /// - `kem_choice`: `KemChoice` - The chosen KEM.
    ///
    /// # Returns:
    /// A new instance of `OcakeClient`.
    pub fn new(
        client_id: Vec<u8>,
        client_password: Vec<u8>,
        protocol_variant: AvailableVariants,
        kem_choice: KemChoice,
    ) -> Self {
        OcakeClient {
            client_id: client_id,
            client_password: client_password,
            protocol_variant: protocol_variant,
            kem_choice: Some(kem_choice),
            kyber_instance: None,
            frodo_instance: None,
            pk: None,
            sk: None,
            c: None,
        }
    }

    /// Performs the `ClientInit` step of `Modified OCAKE-PAKE`
    ///
    /// # Returns:
    /// - (`Vec<u8>`, `Vec<u8>`): A tuple comprising the ciphertext `c` and its accompanying `nonce_c`.
    /// and its accompanying `nonce_c`.
    pub fn client_init(&mut self) -> (Vec<u8>, Vec<u8>) {
        // Generate password digest
        let pwd: Vec<u8> = generate_password_digest(&self.client_password);

        match self.kem_choice.unwrap() {
            Kyber => {
                // Get the kyber instance
                let kyber_instance: MlKemDispatcher = get_kyber_instance(self.protocol_variant);

                // Generating the key pair for encapsulation and decapsulation
                let (pk, sk) = kyber_instance.keygen();

                // Perform Base Encoding of pk
                let pk_base_encoded: Vec<u8> = get_base_encoded_pk(self.protocol_variant, &pk);

                // Encrypt the KEM public key
                let (c, nonce_c) = encrypt_data(&pwd, &pk_base_encoded);

                // Store the following values for future use
                self.kyber_instance = Some(kyber_instance);
                self.pk = Some(pk);
                self.sk = Some(sk);
                self.c = Some(c.clone());

                // Return the ciphertext and nonce
                return (c, nonce_c);
            }
            Frodo => {
                // Get the Frodo instance
                let frodo_instance: FrodoKemDispatcher = get_frodo_instance(self.protocol_variant);

                // Generating the key pair for encapsulation and decapsulation
                let (pk, sk) = frodo_instance.keygen();

                // Encrypt the KEM public key
                let (c, nonce_c) = encrypt_data(&pwd, &pk);

                // Store the following values for future use
                self.frodo_instance = Some(frodo_instance);
                self.pk = Some(pk);
                self.sk = Some(sk);
                self.c = Some(c.clone());

                // Return the ciphertext and nonce
                return (c, nonce_c);
            }
        }
    }

    /// Performs the `ClientFinish` step of `Modified OCAKE-PAKE`
    ///
    /// # Parameters:
    /// - `c_k`: `&[u8]` - The KEM ciphertext.
    /// - `tau_one`: `&[u8]` - The authentication tag from server.
    ///
    /// # Returns:
    /// - `([u8; 32], [u8; 32])`: A tuple containing the generated second authentication tag and and client's session key `sk_c`.
    pub fn client_finish(
        &mut self,
        c_k: &[u8],
        tau_one: &[u8],
    ) -> Result<([u8; 32], [u8; 32]), String> {
        match self.kem_choice.unwrap() {
            Kyber => {
                // Retrieve the shared secret by decapsulating
                let k_k: Vec<u8> = self
                    .kyber_instance
                    .unwrap()
                    .decapsulate(&c_k, &self.sk.clone().unwrap());

                // Compute tag 2
                let tau_two: [u8; 32] = generate_tag(
                    &self.client_password,
                    &self.c.clone().unwrap(),
                    &self.pk.clone().unwrap(),
                    c_k,
                    &k_k,
                    &self.client_id,
                );

                // Check whether the session key generation is possible or not
                let is_possible: bool = is_shared_session_key_derivation_possible(
                    &self.client_password,
                    &self.c.clone().unwrap(),
                    &self.pk.clone().unwrap(),
                    c_k,
                    &k_k,
                    &SERVER_ID,
                    tau_one,
                );

                if !is_possible {
                    return Err("ERROR: Server's explicit authentication check failed".to_string());
                }

                let sk_c: [u8; 32] = generate_session_key(tau_one, &k_k);

                // Return tag 2 and the generated session key
                Ok((tau_two, sk_c))
            }
            Frodo => {
                // Retrieve the shared secret by decapsulating
                let k_k: Vec<u8> = self
                    .frodo_instance
                    .unwrap()
                    .decapsulate(&c_k, &self.sk.clone().unwrap());

                // Compute tag 2
                let tau_two: [u8; 32] = generate_tag(
                    &self.client_password,
                    &self.c.clone().unwrap(),
                    &self.pk.clone().unwrap(),
                    c_k,
                    &k_k,
                    &self.client_id,
                );

                // Check whether the session key generation is possible or not
                let is_possible: bool = is_shared_session_key_derivation_possible(
                    &self.client_password,
                    &self.c.clone().unwrap(),
                    &self.pk.clone().unwrap(),
                    c_k,
                    &k_k,
                    &SERVER_ID,
                    tau_one,
                );

                if !is_possible {
                    return Err("ERROR: Server's explicit authentication check failed".to_string());
                }

                let sk_c: [u8; 32] = generate_session_key(tau_one, &k_k);

                // Return tag 2 and the generated session key
                Ok((tau_two, sk_c))
            }
        }
    }

    /// Returns the client ID of type `Vec<u8>`
    pub fn client_id(&self) -> Vec<u8> {
        self.client_id.clone()
    }

    /// Returns the client password of type `Vec<u8>`
    pub fn client_password(&self) -> Vec<u8> {
        self.client_password.clone()
    }

    /// Returns the protocol_variant of type `AvailableVariants`
    pub fn protocol_variant(&self) -> AvailableVariants {
        self.protocol_variant
    }

    /// Returns the protocol_variant of type `KemChoice`
    pub fn kem_choice(&self) -> KemChoice {
        self.kem_choice.unwrap()
    }
}

impl Drop for OcakeClient {
    fn drop(&mut self) {
        self.client_password.zeroize();
        if let Some(ref mut sk) = self.sk {
            sk.zeroize();
        }
    }
}
