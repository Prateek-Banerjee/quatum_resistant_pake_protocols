/*
[1] A Generic Construction of Tightly Secure Password-based Authenticated Key Exchange
https://eprint.iacr.org/2023/1334
*/

use super::{common_details::generate_session_key, server::SERVER_ID};
use crate::{
    mlkem_variant_wrapper::MlKemDispatcher,
    overall_common_functionalities::{
        decrypt_data, encrypt_data, get_base_decoded_kem_ciphertext, get_base_encoded_pk,
        get_kyber_instance,
    },
    protocol_variants::AvailableVariants,
};
use zeroize::Zeroize;

/// Represents a client with credentials and selected protocol variant.
///
/// # Fields:
/// - `client_id`: `Vec<u8>` — The unique identifier for the client.
/// - `client_password`: `Vec<u8>` — The password associated with the client.
/// - `protocol_variant`: `AvailableVariants` — The chosen protocol variant.
/// - `kyber_instance`: `Option<MlKemDispatcher>` - Optional dispatcher for instance of ML-KEM.
/// - `pk`: `Option<Vec<u8>>` - Optional KEM public key.
/// - `sk`: `Option<Vec<u8>>` - Optional KEM secret key.
/// * `c_1`: `Option<Vec<u8>>` - Optional first ciphertext.
#[derive(Clone)]
pub struct TkClient {
    client_id: Vec<u8>,
    client_password: Vec<u8>,
    protocol_variant: AvailableVariants,
    kyber_instance: Option<MlKemDispatcher>,
    pk: Option<Vec<u8>>,
    sk: Option<Vec<u8>>,
    c_1: Option<Vec<u8>>,
}

impl Default for TkClient {
    fn default() -> Self {
        TkClient {
            client_id: b"The TK PAKE client ID".to_vec(),
            client_password: b"This is client password.".to_vec(),
            protocol_variant: AvailableVariants::Recommended,
            kyber_instance: None,
            pk: None,
            sk: None,
            c_1: None,
        }
    }
}

impl TkClient {
    /// Creates a new `TkClient` instance with the given credentials and protocol variant.
    ///
    /// # Parameters
    /// - `client_id`: `Vec<u8>` – The unique identifier for the client.
    /// - `client_password`: `Vec<u8>` – The client's password used for AES encryption.
    /// - `protocol_variant`: `AvailableVariants` – The protocol variant to be used.
    ///
    /// # Returns
    /// A new instance of `TkClient`.
    ///
    /// # Panics
    /// The client instantiation panics if the length of the client password is netiher of the following: 16, 24 or 32 bytes.
    pub fn new(
        client_id: Vec<u8>,
        client_password: Vec<u8>,
        protocol_variant: AvailableVariants,
    ) -> Self {
        if ![16, 24, 32].contains(&client_password.len()) {
            panic!("Unacceptable Password Length. The password is of {} bytes, which is not within the acceptable key sizes of 16, 24 or 32 bytes for AES.", &client_password.len());
        }

        TkClient {
            client_id: client_id,
            client_password: client_password,
            protocol_variant: protocol_variant,
            kyber_instance: None,
            pk: None,
            sk: None,
            c_1: None,
        }
    }

    /// Performs the `ClientInit` step of `TK-PAKE`
    ///
    /// # Returns:
    /// - (`Vec<u8>`, `Vec<u8>`): A tuple comprising the ciphertext `c_1` and its accompanying `nonce_c_1`.
    pub fn client_init(&mut self) -> (Vec<u8>, Vec<u8>) {
        // Get the kyber instance
        let kyber_instance: MlKemDispatcher = get_kyber_instance(self.protocol_variant);

        // Generating the key pair for encapsulation and decapsulation
        let (pk, sk) = kyber_instance.keygen();

        // Perform Base Encoding of pk
        let pk_base_encoded: Vec<u8> = get_base_encoded_pk(self.protocol_variant, &pk);

        // Encrypt the public key
        let (c_1, nonce_c_1) = encrypt_data(&self.client_password, &pk_base_encoded);

        // Store the client state for future use
        self.kyber_instance = Some(kyber_instance);
        self.pk = Some(pk);
        self.sk = Some(sk);
        self.c_1 = Some(c_1.clone());

        // Return the ciphertext and nonce
        (c_1, nonce_c_1)
    }

    /// Performs the `ClientTerInit` step of `TK-PAKE`
    ///
    /// # Parameters:
    /// - `c_2`: `Vec<u8>` - The ciphertext from server.
    /// - `nonce_c_2`: `&[u8]` - The nonce with ciphertext `c_2`.
    ///
    /// # Returns:
    /// - `[u8; 32]`: The generated session key.
    pub fn client_ter_init(&mut self, c_2: &[u8], nonce_c_2: &[u8]) -> [u8; 32] {
        // This is the KEM Ciphertext
        let c_k_base_encoded: Vec<u8> = decrypt_data(&self.client_password, c_2, nonce_c_2);

        // Perform the base decoding of c_k
        let c_k: Vec<u8> =
            get_base_decoded_kem_ciphertext(self.protocol_variant, &c_k_base_encoded);

        // Retrieve the shared secret by decapsulating
        // let decapsulated_output = decapsulate(&c_k, &sk);
        let k_k: Vec<u8> = self
            .kyber_instance
            .unwrap()
            .decapsulate(&c_k, &self.sk.clone().unwrap());

        let sk_c: [u8; 32] = generate_session_key(
            &self.client_id,
            SERVER_ID,
            &self.c_1.clone().unwrap(),
            c_2,
            &self.pk.clone().unwrap(),
            &c_k,
            &k_k,
            &self.client_password,
        );

        // Return the generated session key
        sk_c
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
}

impl Drop for TkClient {
    fn drop(&mut self) {
        self.client_password.zeroize();
        if let Some(ref mut sk) = self.sk {
            sk.zeroize();
        }
    }
}
