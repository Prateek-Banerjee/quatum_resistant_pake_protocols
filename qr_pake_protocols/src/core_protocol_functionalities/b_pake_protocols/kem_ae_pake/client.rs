/*
[1] Efficient Asymmetric PAKE Compiler from KEM and AE
https://eprint.iacr.org/2024/1400
*/

use super::{common_details::*, server::SERVER_ID};
use crate::{
    mlkem_variant_wrapper::MlKemDispatcher,
    overall_common_functionalities::{
        decrypt_data, encrypt_data, get_base_decoded_kem_ciphertext, get_base_encoded_pk,
        get_kyber_instance,
    },
    protocol_variants::AvailableVariants,
};
use aes_gcm::{
    aead::{generic_array::GenericArray, Aead},
    Aes256Gcm,
};
use sha2::{digest::Digest, Sha256, Sha512};
use zeroize::Zeroize;

/// Represents the client of the KEM-AE-PAKE protocol.
///
/// # Fields:
/// - `client_id`: `Vec<u8>` - The client’s identifier.
/// - `client_password`: `Vec<u8>` - The client’s password.
/// - `protocol_variant`: `AvailableVariants` - The selected variant.
/// - `kyber_instance`: `Option<MlKemDispatcher>` - Optional dispatcher for instance of ML-KEM.
/// - `pk_1`: `Option<Vec<u8>>` - Optional first KEM public key.
/// - `sk_1`: `Option<Vec<u8>>` - Optional first KEM secret key.
/// - `pk_2`: `Option<Vec<u8>>` - Optional second KEM public key.
/// - `sk_2`: `Option<Vec<u8>>` - Optional second KEM secret key.
/// - `c_1`: `Option<Vec<u8>>` - Optional first ciphertext.
/// - `rw`: `Option<Vec<u8>>` - Optional registration value used in the protocol.
#[derive(Clone)]
pub struct KemAeClient {
    client_id: Vec<u8>,
    client_password: Vec<u8>,
    protocol_variant: AvailableVariants,
    kyber_instance: Option<MlKemDispatcher>,
    pk_1: Option<Vec<u8>>,
    sk_1: Option<Vec<u8>>,
    pk_2: Option<Vec<u8>>,
    sk_2: Option<Vec<u8>>,
    c_1: Option<Vec<u8>>,
    rw: Option<Vec<u8>>,
}

impl Default for KemAeClient {
    fn default() -> Self {
        KemAeClient {
            client_id: b"The KEM-AE PAKE client ID".to_vec(),
            client_password: b"This is the password for client.".to_vec(),
            protocol_variant: AvailableVariants::Recommended,
            kyber_instance: None,
            pk_1: None,
            sk_1: None,
            pk_2: None,
            sk_2: None,
            c_1: None,
            rw: None,
        }
    }
}

impl KemAeClient {
    /// Creates a new instance of `KemAeClient`.
    ///
    /// # Parameters:
    /// - `client_id`: `Vec<u8>` - The client's identifier.
    /// - `client_password`: `Vec<u8>` - The client's password.
    /// - `protocol_variant`: `AvailableVariants` - The protocol variant to be used.
    ///
    /// # Returns:
    /// A new instance of `KemAeClient`.
    pub fn new(
        client_id: Vec<u8>,
        client_password: Vec<u8>,
        protocol_variant: AvailableVariants,
    ) -> Self {
        KemAeClient {
            client_id: client_id,
            client_password: client_password,
            protocol_variant: protocol_variant,
            kyber_instance: None,
            pk_1: None,
            sk_1: None,
            pk_2: None,
            sk_2: None,
            c_1: None,
            rw: None,
        }
    }

    /// Generates registration details of a `KemAeClient` comprising of a hashed value and a KEM public key.
    ///
    /// # Returns:
    /// - `(Vec<u8>, Vec<u8>)`: A tuple containing the verifier `rw` and the KEM public key `pk_1`.
    pub fn generate_registration_details(&mut self) -> (Vec<u8>, Vec<u8>) {
        // Generate rw
        let rw: [u8; 32] = self.clone().generate_h0_hash_digest();

        // Generate r
        let r: [u8; 64] = self.clone().generate_h1_hash_digest();

        // Get the kyber instance
        let kyber_instance: MlKemDispatcher = get_kyber_instance(self.protocol_variant);

        // Generating the first KEM key pair for encapsulation and decapsulation
        let (pk_1, sk_1) = kyber_instance.keygen_seeded(&r);

        // Store the value for future use
        self.kyber_instance = Some(kyber_instance);
        self.pk_1 = Some(pk_1.clone());
        self.sk_1 = Some(sk_1);
        self.rw = Some(rw.to_vec());

        // Return rw and pk_1
        (rw.to_vec(), pk_1)
    }

    /// Performs the `ClientInit` step of `KEM-AE-PAKE`
    ///
    /// # Returns:
    /// - (`Vec<u8>`, `Vec<u8>`): A tuple comprising the ciphertext `c_1` and its accompanying `nonce_c_1`.
    pub fn client_init(&mut self) -> (Vec<u8>, Vec<u8>) {
        // Generating the second KEM key pair for encapsulation and decapsulation
        let (pk_2, sk_2) = self.kyber_instance.unwrap().keygen();

        // Perform Base Encoding of pk_2
        let pk_2_base_encoded: Vec<u8> = get_base_encoded_pk(self.protocol_variant, &pk_2);

        // Encrypt the KEM public key
        let (c_1, nonce_c_1) = encrypt_data(&self.rw.clone().unwrap(), &pk_2_base_encoded);

        // Store the values for future use
        self.c_1 = Some(c_1.clone());
        self.pk_2 = Some(pk_2);
        self.sk_2 = Some(sk_2);

        // Return the ciphertext and nonce
        (c_1, nonce_c_1)
    }

    /// Performs the `ClientFinish` step of `KEM-AE-PAKE`
    ///
    /// # Parameters:
    /// - `c_2`: `Vec<u8>` - The ciphertext from server.
    /// - `nonce_c_2`: `&[u8]` - The nonce with ciphertext `c_2`.
    /// - `psi`: `Vec<u8>` - The authenticated encryption ciphertext from server.
    /// - `nonce_psi`: `&[u8]` - The nonce with ciphertext `psi`.
    ///
    /// # Returns:
    /// - `Result<(Vec<u8>, [u8; 32]), String>`: If successful, returns a tuple containing `sigma` for verification and client's session key `sk_c`.
    pub fn client_finish(
        &mut self,
        c_2: Vec<u8>,
        nonce_c_2: &[u8],
        psi: Vec<u8>,
        nonce_psi: &[u8],
    ) -> Result<(Vec<u8>, [u8; 32]), String> {
        // Decrypt the received ciphertext
        let c_k_2_base_encoded: Vec<u8> = decrypt_data(&self.rw.clone().unwrap(), &c_2, nonce_c_2);

        // Perform the base decoding of c_k_2
        let c_k_2: Vec<u8> =
            get_base_decoded_kem_ciphertext(self.protocol_variant, &c_k_2_base_encoded);

        // Retrieved the shared secret by decapsulating. This is k_k_2
        let k_k_2: Vec<u8> = self
            .kyber_instance
            .unwrap()
            .decapsulate(&c_k_2, &self.sk_2.clone().unwrap());

        // Generate Hash Digest G which is tau
        let tau: [u8; 32] = generate_tau(
            &self.client_id,
            &SERVER_ID,
            &self.c_1.clone().unwrap(),
            &c_2,
            &k_k_2,
        );

        // Generate H2 hash digest which is the input key for Authenticated Encryption
        let h2_tau: [u8; 32] = generate_h2_hash_digest(&tau);

        // Decrypt the received psi
        let decryption_result = self
            .clone()
            .decrypt_data_ae(&h2_tau, psi.clone(), nonce_psi);

        match decryption_result {
            Ok(c_k_1) => {
                // Retrieved the shared secret by decapsulating
                let k_k_1: Vec<u8> = self
                    .kyber_instance
                    .unwrap()
                    .decapsulate(&c_k_1, &self.sk_1.clone().unwrap());

                // Generate sid
                let sid: Vec<u8> = concatenate(self.c_1.clone().unwrap(), c_2);

                // Generate sid_psi
                let sid_psi: Vec<u8> = concatenate(sid, psi);

                // Generate sigma
                let sigma: Vec<u8> = generate_h3_hash_digest(&tau, &k_k_1, &sid_psi);

                // Generate shared session key
                let sk_c: [u8; 32] = generate_h4_hash_digest(&tau);

                // Return sigma and the generated session key
                Ok((sigma, sk_c))
            }
            Err(e) => Err(e),
        }
    }

    /// Returns the client ID of type `Vec<u8>`
    pub fn client_id(&self) -> Vec<u8> {
        self.client_id.clone()
    }

    /// Returns the rw value needed for registration of type `Vec<u8>`
    pub fn get_registration_verifier(&mut self) -> Vec<u8> {
        let (rw, _) = self.generate_registration_details();
        rw
    }

    /// Returns the protocol_variant of type `AvailableVariants`
    pub fn protocol_variant(&self) -> AvailableVariants {
        self.protocol_variant
    }

    /// Decrypts the provided ciphertext using AES-256-GCM decryption with the given input key and nonce.
    ///
    /// # Parameters:
    /// * `input_key`: `&[u8]` - A byte slice representing the 32-byte decryption key.
    /// - `ciphertext`: `&[u8]` - The data to be decrypted.
    /// - `nonce`: `&[u8]` - The nonce accompanying the ciphertext.
    ///
    /// # Returns:
    /// - `Result<Vec<u8>, String>`: If successful, then returns the resulting plaintext.
    fn decrypt_data_ae(
        self,
        input_key: &[u8],
        ciphertext: Vec<u8>,
        nonce: &[u8],
    ) -> Result<Vec<u8>, String> {
        use aes_gcm::aead::KeyInit; // Import only in this function to avoid same name trait conflict with hash functions

        // Create the cipher
        let cipher = Aes256Gcm::new_from_slice(input_key).unwrap();

        // Retrieve the nonce
        let nonce = GenericArray::from_slice(&nonce);

        // Decrypt the ciphertext
        match cipher.decrypt(&nonce, ciphertext.as_ref()) {
            Ok(plaintext) => {
                // Return plaintext
                Ok(plaintext)
            }
            Err(_) => {
                return Err("ERROR: Server's explicit authentication check failed".to_string());
            }
        }
    }

    /// Generates the H0 hash digest using the client's ID, password, and server ID.
    ///
    /// # Returns:
    /// - `[u8; 32]`: The 32-byte verifier `rw` computed using SHA-256.
    fn generate_h0_hash_digest(self) -> [u8; 32] {
        // Create a new SHA-256 instance
        let mut hash_func = Sha256::new();

        // Feed the data to SHA-256 instance
        hash_func.update(self.client_password.clone());
        hash_func.update(self.client_id.clone());
        hash_func.update(SERVER_ID);

        // Generate the hash digest
        let rw: [u8; 32] = hash_func.finalize().into();

        // Return rw
        rw
    }

    /// Generates the H1 hash digest using the client's ID, password, and server ID.
    ///
    /// # Returns:
    /// - `[u8; 64]`: The 64-byte seed `r` computed using SHA-512.
    fn generate_h1_hash_digest(self) -> [u8; 64] {
        // Create a new SHA-512 instance
        let mut hash_func = Sha512::new();

        // Feed the data to SHA-512 instance
        hash_func.update(self.client_password.clone());
        hash_func.update(self.client_id.clone());
        hash_func.update(SERVER_ID);

        // Generate the hash digest
        let r: [u8; 64] = hash_func.finalize().into();

        // Return r
        r
    }
}

impl Drop for KemAeClient {
    fn drop(&mut self) {
        self.client_password.zeroize();
        if let Some(ref mut rw) = self.rw {
            rw.zeroize();
        }
        if let Some(ref mut sk_1) = self.sk_1 {
            sk_1.zeroize();
        }
        if let Some(ref mut sk_2) = self.sk_2 {
            sk_2.zeroize();
        }
    }
}
