/*
[1] A Generic Construction of Tightly Secure Password-based Authenticated Key Exchange
https://eprint.iacr.org/2023/1334
*/

use sha2::{digest::Digest, Sha256};

/// Generates a session key by hashing multiple input components.
///
/// # Parameters:
/// - `client_id`: `&[u8]` - The client identifier.
/// - `server_id`: `&[u8]` - The server identifier.
/// - `c_1`: `&[u8]` - The ciphertext from client.
/// - `c_2`: `&[u8]` - The ciphertext from server.
/// - `pk`: `&[u8]` - The KEM public key.
/// - `c_k`: `&[u8]` - The KEM ciphertext.
/// - `k_k`: `&[u8]` - The shared secret.
/// - `client_password`: `&[u8]` - The client password.
///
/// # Returns:
/// - `[u8; 32]`: The generated 32-byte session key.
pub fn generate_session_key(
    client_id: &[u8],
    server_id: &[u8],
    c_1: &[u8],
    c_2: &[u8],
    pk: &[u8],
    c_k: &[u8],
    k_k: &[u8],
    client_password: &[u8],
) -> [u8; 32] {
    let mut hash_func = Sha256::new();

    for each_item in [
        client_id,
        server_id,
        c_1,
        c_2,
        pk,
        c_k,
        k_k,
        client_password,
    ] {
        hash_func.update(each_item);
    }

    let session_key: [u8; 32] = hash_func.finalize().into();

    session_key
}
