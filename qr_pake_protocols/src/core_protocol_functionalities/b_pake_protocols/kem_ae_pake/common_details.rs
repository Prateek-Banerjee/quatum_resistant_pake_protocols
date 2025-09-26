/*
[1] Efficient Asymmetric PAKE Compiler from KEM and AE
https://eprint.iacr.org/2024/1400
*/

use sha2::{digest::Digest, Sha256};

/// Generates a 32-byte SHA-256 hash digest (tau).
///
/// # Parameters:
/// - `client_id`: `&[u8]` - The client identifier.
/// - `server_id`: `&[u8]` - The server identifier.
/// - `c_1`: `&[u8]` - The ciphertext from client.
/// - `c_2`: `&[u8]` - The ciphertext from server.
/// - `k_k_2`: `&[u8]` - The second shared secret key.
///
/// # Returns:
/// - `[u8; 32]`: The resulting 32-byte hash digest `tau`.
pub fn generate_tau(
    client_id: &[u8],
    server_id: &[u8],
    c_1: &[u8],
    c_2: &[u8],
    k_k_2: &[u8],
) -> [u8; 32] {
    // Create a new SHA-256 instance
    let mut hash_func = Sha256::new();

    // Feed the data to SHA-256 instance
    hash_func.update(client_id);
    hash_func.update(server_id);
    hash_func.update(c_1);
    hash_func.update(c_2);
    hash_func.update(k_k_2);

    // Generate the hash digest
    let tau: [u8; 32] = hash_func.finalize().into();

    // Return tau
    tau
}

/// Generates a 32-byte SHA-256 hash digest from the input tau.
/// Used as an input key for authenticated encryption and decryption.
///
/// # Parameters:
/// - `tau`: `&[u8]` - The authentication tag.
///
/// # Returns:
/// - `[u8; 32]`: The resulting 32-byte hash digest.
pub fn generate_h2_hash_digest(tau: &[u8]) -> [u8; 32] {
    // Create a new SHA-256 instance
    let mut hash_func = Sha256::new();

    // Feed the data to SHA-256 instance
    hash_func.update(tau);

    // Generate the hash digest
    let h2_tau: [u8; 32] = hash_func.finalize().into();

    // Return hash_digest_g
    h2_tau
}

/// Concatenates two byte vectors.
///
/// # Parameters:
/// - `input_1`: `Vec<u8>` - The first input byte vector.
/// - `input_2`: `Vec<u8>` - The second input byte vector.
///
/// # Returns:
/// - `Vec<u8>`: A concatenated byte vector generated from the inputs.
pub fn concatenate(input_1: Vec<u8>, input_2: Vec<u8>) -> Vec<u8> {
    input_1.iter().chain(input_2.iter()).copied().collect()
}

/// Generates the H1 hash digest using tau, k_k_1, and sid_psi.
///
/// # Parameters:
/// - `tau`: `&[u8]` - The authentication tag.
/// - `k_k_1`: `&[u8]` - The shared secret key from the first KEM encapsulation.
/// - `sid_psi`: `&[u8]` - The combined value of session identifiers and ciphertext from server.
///
/// # Returns:
/// - `Vec<u8>`: The SHA-256 hash digest `sigma`.
pub fn generate_h3_hash_digest(tau: &[u8], k_k_1: &[u8], sid_psi: &[u8]) -> Vec<u8> {
    // Create a new SHA-256 instance
    let mut hash_func = Sha256::new();

    // Feed the data to SHA-256 instance
    hash_func.update(tau);
    hash_func.update(k_k_1);
    hash_func.update(sid_psi);

    // Generate the hash digest
    let sigma: Vec<u8> = hash_func.finalize().to_vec();

    // Return sigma
    sigma
}

/// Generates a 32-byte SHA-256 hash digest from the input tau.
///
/// # Parameters:
/// - `tau`: `&[u8]` - The authentication tag.
///
/// # Returns:
/// - `[u8; 32]`: The resulting 32-byte hash digest which is the session key.
pub fn generate_h4_hash_digest(tau: &[u8]) -> [u8; 32] {
    generate_h2_hash_digest(tau)
}
