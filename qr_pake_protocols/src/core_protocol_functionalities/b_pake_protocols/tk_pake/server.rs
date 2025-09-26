/*
[1] A Generic Construction of Tightly Secure Password-based Authenticated Key Exchange
https://eprint.iacr.org/2023/1334
*/

use super::common_details::generate_session_key;
use crate::{
    mlkem_variant_wrapper::MlKemDispatcher,
    overall_common_functionalities::{
        decrypt_data, encrypt_data, get_base_decoded_pk, get_base_encoded_kem_ciphertext,
        get_kyber_instance,
    },
    protocol_variants::AvailableVariants,
};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

pub const SERVER_ID: &[u8; 32] = b"This is a tight kyberpake server";

/// Represents a server with a specified protocol variant.
///
/// # Fields:
/// - `protocol_variant`: `AvailableVariants` - The chosen protocol variant.
/// - `client_id`: `Option<Vec<u8>>` - Optional client’s identifier.
/// - `client_password`: `Option<Vec<u8>>` - Optional client’s password.
#[derive(Clone, Serialize, Deserialize)]
pub struct TkServer {
    protocol_variant: AvailableVariants,
    client_id: Option<Vec<u8>>,
    client_password: Option<Vec<u8>>,
}

impl Default for TkServer {
    fn default() -> Self {
        TkServer {
            protocol_variant: AvailableVariants::Recommended,
            client_id: None,
            client_password: None,
        }
    }
}

impl TkServer {
    /// Creates a new `TkServer` with the given protocol variant.
    ///
    /// # Parameters:
    /// - `protocol_variant`: `AvailableVariants` - The protocol variant to initialize the server with.
    ///
    /// # Returns:
    /// A new instance of `TkServer`.
    pub fn new(protocol_variant: AvailableVariants) -> Self {
        TkServer {
            protocol_variant: protocol_variant,
            client_id: None,
            client_password: None,
        }
    }

    /// Registers the client by storing its ID and password for future use.
    ///
    /// # Parameters
    /// - `client_id`: A byte vector (`Vec<u8>`) representing the client's unique identifier.
    /// - `client_password`: A byte vector (`Vec<u8>`) representing the client's password.
    pub fn accept_registration(&mut self, client_id: Vec<u8>, client_password: Vec<u8>) {
        // Store the client details for future use
        self.client_id = Some(client_id);
        self.client_password = Some(client_password);
    }

    /// Performs the `ServerResp` step of `TK-PAKE`
    ///
    /// # Parameters:
    /// - `c_1`: `Vec<u8>` - The ciphertext from client.
    /// - `nonce_c_1`: `&[u8]` - The nonce with ciphertext `c_1`.
    ///
    /// # Returns:
    /// - `(Vec<u8>, Vec<u8>, [u8; 32])`: A tuple containing the ciphertext `c_2`, its accompanying `nonce_c_2`, and the derived session key.
    pub fn server_resp(self, c_1: &[u8], nonce_c_1: &[u8]) -> (Vec<u8>, Vec<u8>, [u8; 32]) {
        // Get the kyber instance
        let kyber_instance: MlKemDispatcher = get_kyber_instance(self.protocol_variant);

        // Decrypt the received ciphertext
        let pk_base_encoded: Vec<u8> =
            decrypt_data(&self.client_password.clone().unwrap(), c_1, nonce_c_1);

        // Perform the Base Decoding of pk
        let pk: Vec<u8> = get_base_decoded_pk(self.protocol_variant, &pk_base_encoded);

        // Performing the encapsulation to generate the encapsulated output
        let (c_k, k_k) = kyber_instance.encapsulate(&pk);

        // Perform base encoding of c_k
        let c_k_base_encoded: Vec<u8> =
            get_base_encoded_kem_ciphertext(self.protocol_variant, &c_k);

        // Encrypt the KEM ciphertext
        let (c_2, nonce_c_2) =
            encrypt_data(&self.client_password.clone().unwrap(), &c_k_base_encoded);

        let sk_s: [u8; 32] = generate_session_key(
            &self.client_id.clone().unwrap(),
            SERVER_ID,
            c_1,
            &c_2,
            &pk,
            &c_k,
            &k_k,
            &self.client_password.clone().unwrap(),
        );

        (c_2, nonce_c_2, sk_s)
    }

    /// Returns the stored client password of type `Vec<u8>`
    pub fn get_stored_client_password(&self) -> Vec<u8> {
        self.client_password.clone().unwrap()
    }
}

impl Drop for TkServer {
    fn drop(&mut self) {
        if let Some(ref mut client_password) = self.client_password {
            client_password.zeroize();
        }
    }
}
