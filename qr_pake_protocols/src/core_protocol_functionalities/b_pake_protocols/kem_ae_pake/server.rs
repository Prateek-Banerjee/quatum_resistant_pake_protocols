/*
[1] Efficient Asymmetric PAKE Compiler from KEM and AE
https://eprint.iacr.org/2024/1400
*/

use super::common_details::*;
use crate::{
    mlkem_variant_wrapper::MlKemDispatcher,
    overall_common_functionalities::{
        decrypt_data, encrypt_data, get_base_decoded_pk, get_base_encoded_kem_ciphertext,
        get_kyber_instance,
    },
    protocol_variants::AvailableVariants,
};
use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm,
};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

pub const SERVER_ID: [u8; 32] = *b"This is the KEMAE PAKE Server ID";

/// Represents the server of the KEM-AE-PAKE protocol.
///
/// # Fields:
/// - `protocol_variant`: `AvailableVariants` - The selected variant.
/// - `rw`: `Option<Vec<u8>>` - Optional registration value used in the protocol.
/// - `client_id`: `Vec<u8>` - The client’s identifier.
/// - `pk_1`: `Option<Vec<u8>>` - Optional first KEM public key.
/// - `pk_2`: `Option<Vec<u8>>` - Optional second KEM public key.
/// - `c_1`: `Option<Vec<u8>>` - Optional first ciphertext.
/// - `c_2`: `Option<Vec<u8>>` - Optional second ciphertext.
/// - `psi`: `Option<Vec<u8>>` - Optional ciphertext from authenticated encryption.
/// - `tau`: `Option<[u8; 32]>` - Optional tag.
/// - `psi`: `Option<Vec<u8>>` - Optional first KEM shared secret key.
#[derive(Clone, Serialize, Deserialize)]
pub struct KemAeServer {
    protocol_variant: AvailableVariants,
    rw: Option<Vec<u8>>,
    client_id: Option<Vec<u8>>,
    pk_1: Option<Vec<u8>>,
    pk_2: Option<Vec<u8>>,
    c_1: Option<Vec<u8>>,
    c_2: Option<Vec<u8>>,
    psi: Option<Vec<u8>>,
    tau: Option<[u8; 32]>,
    k_k_1: Option<Vec<u8>>,
}

impl Default for KemAeServer {
    fn default() -> Self {
        KemAeServer {
            protocol_variant: AvailableVariants::Recommended,
            rw: None,
            client_id: None,
            pk_1: None,
            pk_2: None,
            c_1: None,
            c_2: None,
            psi: None,
            tau: None,
            k_k_1: None,
        }
    }
}

impl KemAeServer {
    /// Creates a new `KemAeServer` with the specified protocol variant.
    ///
    /// # Parameters:
    /// - `protocol_variant`: `AvailableVariants` - The protocol variant to initialize the server with.
    ///
    /// # Returns:
    /// A new instance of `KemAeServer`.
    pub fn new(protocol_variant: AvailableVariants) -> Self {
        KemAeServer {
            protocol_variant: protocol_variant,
            rw: None,
            client_id: None,
            pk_1: None,
            pk_2: None,
            c_1: None,
            c_2: None,
            psi: None,
            tau: None,
            k_k_1: None,
        }
    }

    /// Stores one-time client registration details including client's ID, hash digest (verifier), and KEM public key.
    ///
    /// # Parameters:
    /// - `client_id`: `Vec<u8>` - The client's identifier.
    /// - `rw`: `Vec<u8>` - The registration value to be used in the protocol.
    /// - `pk_1`: `Vec<u8>` - The client's fist KEM public key.
    pub fn accept_registration(&mut self, client_id: Vec<u8>, rw: Vec<u8>, pk_1: Vec<u8>) {
        // Store the client details for future use
        self.client_id = Some(client_id);
        self.rw = Some(rw);
        self.pk_1 = Some(pk_1);
    }

    /// Performs the `ServerResp` step of `KEM-AE-PAKE`
    ///
    /// # Parameters:
    /// - `c_1`: `Vec<u8>` - The ciphertext from client.
    /// - `nonce_c_1`: `&[u8]` - The nonce with ciphertext `c_1`.
    ///
    /// # Returns:
    /// `(Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>)`: A tuple containing the following:
    ///   - The ciphertext `c_2` and its accompanying `nonce_c_2`.
    ///   - The ciphertext `psi` and its accompanying `nonce_psi` using authenticated encryption.
    pub fn server_resp(
        &mut self,
        c_1: Vec<u8>,
        nonce_c_1: &[u8],
    ) -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) {
        // Get the kyber instance
        let kyber: MlKemDispatcher = get_kyber_instance(self.protocol_variant);

        // Performing the encapsulation to generate the encapsulated output
        let (c_k_1, k_k_1) = kyber.encapsulate(&self.pk_1.clone().unwrap());

        // Decrypt the received ciphertext
        let pk_2_base_encoded: Vec<u8> = decrypt_data(&self.rw.clone().unwrap(), &c_1, nonce_c_1);

        // Perform the Base Decoding of pk_2
        let pk_2: Vec<u8> = get_base_decoded_pk(self.protocol_variant, &pk_2_base_encoded);

        // Performing the encapsulation to generate the encapsulated output
        let (c_k_2, k_k_2) = kyber.encapsulate(&pk_2);

        // Perform base encoding of c_k_2
        let c_k_2_base_encoded: Vec<u8> =
            get_base_encoded_kem_ciphertext(self.protocol_variant, &c_k_2);

        // Encrypt the kem_ciphertext
        let (c_2, nonce_c_2) = encrypt_data(&self.rw.clone().unwrap(), &c_k_2_base_encoded);

        // Generate authentication tag tau
        let tau: [u8; 32] = generate_tau(
            &self.client_id.clone().unwrap(),
            &SERVER_ID,
            &c_1,
            &c_2,
            &k_k_2,
        );

        // Generate H2 hash digest
        let h2_tau: [u8; 32] = generate_h2_hash_digest(&tau);

        // Perform authenticated encryption. This is psi
        let (psi, nonce_psi) = self.clone().encrypt_data_ae(&h2_tau, &c_k_1);

        // Store the values for future use
        self.pk_2 = Some(pk_2);
        self.c_1 = Some(c_1);
        self.c_2 = Some(c_2.clone());
        self.psi = Some(psi.clone());
        self.tau = Some(tau);
        self.k_k_1 = Some(k_k_1);

        // Return the ciphertexts and nonces
        (c_2, nonce_c_2, psi, nonce_psi)
    }

    /// Performs the `ServerFinish` step of `KEM-AE-PAKE`
    ///
    /// # Parameters:
    /// - `sigma`: `Vec<u8>` - The tag provided by the client for verification.
    ///
    /// # Returns:
    /// - `[u8; 32]`: The derived shared session key.
    ///
    /// # Returns:
    /// - `Result<[u8; 32], String>`: If successful, then returns the generated session key.
    pub fn server_finish(&mut self, sigma: Vec<u8>) -> Result<[u8; 32], String> {
        // Generate sid
        let sid: Vec<u8> = concatenate(self.c_1.clone().unwrap(), self.c_2.clone().unwrap());

        // Generate sid_psi
        let sid_psi: Vec<u8> = concatenate(sid, self.psi.clone().unwrap());

        // Check whether sigma is equal to the hash digest H3
        if !self.clone().check_h3_hash_digest_equality(
            &self.tau.clone().unwrap(),
            &self.k_k_1.clone().unwrap(),
            &sid_psi,
            sigma,
        ) {
            return Err("ERROR: Client's explicit authentication check failed".to_string());
        }

        // Generate H4 hash digest which is the shared session key
        let sk_s: [u8; 32] = generate_h4_hash_digest(&self.tau.unwrap());

        // Return the generated session key
        Ok(sk_s)
    }

    /// Returns the stored client verifier of type `Vec<u8>`
    pub fn get_stored_client_verifier(&self) -> Vec<u8> {
        self.rw.clone().unwrap()
    }

    /// Encrypts the provided plaintext using AES-256-GCM encryption with the given input key.
    ///
    /// # Parameters:
    /// * `input_key`: `&[u8]` - A byte slice representing the 32-byte input key.
    /// * `plaintext`: `&[u8]` - A byte slice representing the data to be encrypted.
    ///
    /// # Returns:
    /// - (`Vec<u8>`, `Vec<u8>`): The resulting ciphertext and the nonce.
    ///
    /// # Panics
    /// Panics if the `input_key` length is not 32 bytes.
    fn encrypt_data_ae(self, input_key: &[u8], plaintext: &[u8]) -> (Vec<u8>, Vec<u8>) {
        if input_key.len() != 32 {
            panic!("Invalid AES Input Key Length. The input key is of {} bytes, which is not the acceptable key size of 32 bytes.", &input_key.len());
        }

        // Create the cipher
        let cipher = Aes256Gcm::new_from_slice(input_key).unwrap();

        // Generate the nonce
        let nonce = Aes256Gcm::generate_nonce(OsRng);

        // Generate the ciphertext
        let ciphertext: Vec<u8> = cipher.encrypt(&nonce, plaintext).unwrap();

        // Return ciphertext
        (ciphertext, nonce.to_vec())
    }

    /// Checks if the verification tag `sigma` matches the server-generated H3 hash digest.
    ///
    /// # Parameters:
    /// - `tau`: `&[u8]` - The authentication tag.
    /// - `k_k_1`: `&[u8]` - The shared secret derived from the first KEM encapsulation.
    /// - `sid_psi`: `&[u8]` - The combined value of session identifiers and ciphertext from authenticated  encryption.
    /// - `sigma`: `Vec<u8>` - The hash digest provided by the client.
    ///
    /// # Returns:
    /// - `bool`: `true` if the tag matches, otherwise `false`.
    fn check_h3_hash_digest_equality(
        self,
        tau: &[u8],
        k_k_1: &[u8],
        sid_psi: &[u8],
        sigma: Vec<u8>,
    ) -> bool {
        let mut result: bool = true;

        if sigma != generate_h3_hash_digest(tau, k_k_1, sid_psi) {
            result = false;
        }

        // Return the result
        result
    }
}

impl Drop for KemAeServer {
    fn drop(&mut self) {
        if let Some(ref mut rw) = self.rw {
            rw.zeroize();
        }
        if let Some(ref mut k_k_1) = self.k_k_1 {
            k_k_1.zeroize();
        }
    }
}
