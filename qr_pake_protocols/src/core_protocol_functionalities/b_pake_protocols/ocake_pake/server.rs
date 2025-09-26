/*
[1] Towards post-quantum secure PAKE-A tight security proof for OCAKE in the BPR model
https://eprint.iacr.org/2023/1368.pdf
*/

use super::common_details::*;
use crate::{
    frodo_variant_wrapper::FrodoKemDispatcher,
    mlkem_variant_wrapper::MlKemDispatcher,
    overall_common_functionalities::{decrypt_data, get_base_decoded_pk, get_kyber_instance},
    protocol_variants::{
        AvailableVariants,
        KemChoice::{self, *},
    },
};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

pub const SERVER_ID: [u8; 32] = *b"This is an OCAKE PAKE Server ID.";

/// Represents an OCAKE server with a specified protocol variant.
///
/// # Fields:
/// - `protocol_variant`: `AvailableVariants` - The chosen protocol variant.
/// - `kem_choice`: `Option<KemChoice>` - Optional choice of the KEM.
/// - `client_id`: `Option<Vec<u8>>` - Optional client’s identifier.
/// - `client_password`: `Option<Vec<u8>>` - Optional client’s password.
/// - `pk`: `Option<Vec<u8>>` - Optional KEM public key.
/// - `c_k`: `Option<Vec<u8>>` - Optional KEM ciphertext.
/// - `k_k`: `Option<Vec<u8>>` - Optional KEM shared secret key.
/// - `c`: `Option<Vec<u8>>` - Optional ciphertext.
/// * `tau_one`: `Option<[u8; 32]>` - Optional authentication tag.
#[derive(Clone, Serialize, Deserialize)]
pub struct OcakeServer {
    protocol_variant: AvailableVariants,
    kem_choice: Option<KemChoice>,
    client_id: Option<Vec<u8>>,
    client_password: Option<Vec<u8>>,
    pk: Option<Vec<u8>>,
    c_k: Option<Vec<u8>>,
    k_k: Option<Vec<u8>>,
    c: Option<Vec<u8>>,
    tau_one: Option<[u8; 32]>,
}

impl Default for OcakeServer {
    fn default() -> Self {
        OcakeServer {
            protocol_variant: AvailableVariants::Recommended,
            kem_choice: None,
            client_id: None,
            client_password: None,
            pk: None,
            c_k: None,
            k_k: None,
            c: None,
            tau_one: None,
        }
    }
}

impl OcakeServer {
    /// Creates a new `OcakeServer` with the specified protocol variant.
    ///
    /// # Parameters:
    /// - `protocol_variant`: `AvailableVariants` - The protocol variant to initialize the server with.
    ///
    /// # Returns:
    /// A new instance of `OcakeServer`.
    pub fn new(protocol_variant: AvailableVariants) -> Self {
        OcakeServer {
            protocol_variant: protocol_variant,
            kem_choice: None,
            client_id: None,
            client_password: None,
            pk: None,
            c_k: None,
            k_k: None,
            c: None,
            tau_one: None,
        }
    }

    /// Registers a new client by storing the provided client ID, password and the chosen KEM for future use.
    ///
    /// # Parameters
    /// - `client_id`: A byte vector (`Vec<u8>`) representing the client's unique identifier.
    /// - `client_password`: A byte vector (`Vec<u8>`) representing the client's password.
    /// - `kem_choice`: The KEM chosen by the client.
    pub fn accept_registration(
        &mut self,
        client_id: Vec<u8>,
        client_password: Vec<u8>,
        kem_choice: KemChoice,
    ) {
        // Store the client details for future use
        self.client_id = Some(client_id);
        self.client_password = Some(client_password);
        self.kem_choice = Some(kem_choice);
    }

    /// Performs the `ServerResp` step of `Modified OCAKE-PAKE`
    ///
    /// # Parameters:
    /// - `c`: `&[u8]` - The ciphertext from client.
    /// - `nonce_c`: `&[u8]` - The nonce with ciphertext `c`.
    ///
    /// # Returns:
    /// - `(Vec<u8>, [u8; 32])`: A tuple containing the KEM ciphertext and the first authentication tag.
    pub fn server_resp(&mut self, c: &[u8], nonce_c: &[u8]) -> (Vec<u8>, [u8; 32]) {
        match self.kem_choice.unwrap() {
            Kyber => {
                // Get the kyber instance
                let kyber_instance: MlKemDispatcher = get_kyber_instance(self.protocol_variant);

                // Generate password digest
                let pwd: Vec<u8> = generate_password_digest(&self.client_password.clone().unwrap());

                // Decrypt the received ciphertext
                let pk_base_encoded: Vec<u8> = decrypt_data(&pwd, c, nonce_c);

                // Perform the Base Decoding of pk
                let pk: Vec<u8> = get_base_decoded_pk(self.protocol_variant, &pk_base_encoded);

                // Performing the encapsulation
                let (c_k, k_k) = kyber_instance.encapsulate(&pk);

                // Compute tag 1
                let tau_one: [u8; 32] = generate_tag(
                    &self.client_password.clone().unwrap(),
                    c,
                    &pk,
                    &c_k,
                    &k_k,
                    &SERVER_ID,
                );

                // Store the following values for future use
                self.pk = Some(pk);
                self.c_k = Some(c_k.clone());
                self.k_k = Some(k_k);
                self.c = Some(c.to_vec());
                self.tau_one = Some(tau_one);

                // Return the kem_ciphertext and tag 1
                return (c_k, tau_one);
            }
            Frodo => {
                // Get the Frodo instance
                let frodo_instance: FrodoKemDispatcher = get_frodo_instance(self.protocol_variant);

                // Generate password digest
                let pwd: Vec<u8> = generate_password_digest(&self.client_password.clone().unwrap());

                // Decrypt the received ciphertext
                let pk: Vec<u8> = decrypt_data(&pwd, c, nonce_c);

                // Performing the encapsulation
                let (c_k, k_k) = frodo_instance.encapsulate(&pk);

                // Compute tag 1
                let tau_one: [u8; 32] = generate_tag(
                    &self.client_password.clone().unwrap(),
                    c,
                    &pk,
                    &c_k,
                    &k_k,
                    &SERVER_ID,
                );

                // Store the following values for future use
                self.pk = Some(pk);
                self.c_k = Some(c_k.clone());
                self.k_k = Some(k_k);
                self.c = Some(c.to_vec());
                self.tau_one = Some(tau_one);

                // Return the kem_ciphertext and tag 1
                return (c_k, tau_one);
            }
        }
    }

    /// Performs the `ServerFinish` step of `Modified OCAKE-PAKE`
    ///
    /// # Parameters:
    /// - `tau_two`: `&[u8]` - The authentication tag from the client.
    ///
    /// # Returns:
    /// - `Result<[u8; 32], String>`: If successful, then returns the generated session key.
    pub fn server_finish(&mut self, tau_two: &[u8]) -> Result<[u8; 32], String> {
        // Check whether the session key generation is possible or not
        let is_possible: bool = is_shared_session_key_derivation_possible(
            &self.client_password.clone().unwrap(),
            &self.c.clone().unwrap(),
            &self.pk.clone().unwrap(),
            &self.c_k.clone().unwrap(),
            &self.k_k.clone().unwrap(),
            &self.client_id.clone().unwrap(),
            tau_two,
        );

        if !is_possible {
            return Err("ERROR: Client's explicit authentication check failed".to_string());
        }

        let sk_s: [u8; 32] =
            generate_session_key(&self.tau_one.unwrap(), &self.k_k.clone().unwrap());

        // Return the session key
        Ok(sk_s)
    }

    /// Returns the stored client password of type `Vec<u8>`
    pub fn get_stored_client_password(&self) -> Vec<u8> {
        self.client_password.clone().unwrap()
    }
}

impl Drop for OcakeServer {
    fn drop(&mut self) {
        if let Some(ref mut client_password) = self.client_password {
            client_password.zeroize();
        }
        if let Some(ref mut k_k) = self.k_k {
            k_k.zeroize();
        }
    }
}
