/*
[1] Towards post-quantum secure PAKE-A tight security proof for OCAKE in the BPR model
https://eprint.iacr.org/2023/1368.pdf
*/

use crate::{frodo_variant_wrapper::FrodoKemDispatcher, protocol_variants::AvailableVariants};
use sha2::{digest::Digest, Sha256};
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake128,
};

const XOF_DIGEST_SIZE: usize = 32;

/// Generates a password digest using SHAKE-128 XOF.
///
/// # Parameters:
/// - `client_password`: `&[u8]` - The client password.
///
/// # Returns:
/// - `Vec<u8>`: The generated password digest of 32 bytes.
pub fn generate_password_digest(client_password: &[u8]) -> Vec<u8> {
    // Create a SHAKE-128 XOF instance
    let mut shake_128_xof = Shake128::default();

    // Feed the password to the SHAKE-128 XOF instance
    shake_128_xof.update(client_password);
    let mut xof_digest_reader = shake_128_xof.finalize_xof();

    // Initialize an XOF output buffer
    let mut xof_output_buffer: Vec<u8> = vec![0u8; XOF_DIGEST_SIZE];
    xof_digest_reader.read(&mut xof_output_buffer);

    // Return
    xof_output_buffer
}

/// Generates an authentication tag by hashing multiple input components.
///
/// # Parameters:
/// - `client_password`: `&[u8]` - The client's password.
/// - `c`: `&[u8]` - The ciphertext.
/// - `pk`: `&[u8]` - The public key.
/// - `c_k`: `&[u8]` - The KEM ciphertext.
/// - `k_k`: `&[u8]` - The shared secret.
/// - `party_id`: `&[u8]` - The identifier of the party generating the tag.
///
/// # Returns:
/// - `[u8; 32]`: The generated 32-byte authentication tag.
pub fn generate_tag(
    client_password: &[u8],
    c: &[u8],
    pk: &[u8],
    c_k: &[u8],
    k_k: &[u8],
    party_id: &[u8],
) -> [u8; 32] {
    // Create a new SHA-256 instance
    let mut hash_func = Sha256::new();

    for each_item in [client_password, c, pk, c_k, k_k, party_id].iter() {
        // Feed the data to the hash function
        Digest::update(&mut hash_func, each_item)
    }

    // Generate the hash digest which is the tag
    let tag: [u8; 32] = hash_func.finalize().into();

    // Return tag
    tag
}

/// Compares a given tag with a freshly generated tag based on provided parameters to verify equality.
///
/// # Parameters:
/// - `client_password`: `&[u8]` - The client's password.
/// - `c`: `&[u8]` - The ciphertext.
/// - `pk`: `&[u8]` - The public key.
/// - `c_k`: `&[u8]` - The KEM ciphertext.
/// - `k_k`: `&[u8]` - The shared secret.
/// - `other_party_id`: `&[u8]` - The identifier of the other party.
/// - `tag`: `&[u8]` - The tag to compare against.
///
/// # Returns:
/// - `bool`: `true` if the tags match, otherwise `false`.
pub fn is_tag_equal(
    client_password: &[u8],
    c: &[u8],
    pk: &[u8],
    c_k: &[u8],
    k_k: &[u8],
    other_party_id: &[u8],
    tag: &[u8],
) -> bool {
    let mut result: bool = true;

    if tag.to_vec() != generate_tag(client_password, c, pk, c_k, k_k, other_party_id).to_vec()
    {
        result = false;
    }

    // Return the result
    result
}

/// Verifies if shared session key derivation is possible by checking the equality of authentication tags.
///
/// # Parameters:
/// - `client_password`: `&[u8]` - The client's password.
/// - `c`: `&[u8]` - The ciphertext.
/// - `pk`: `&[u8]` - The public key.
/// - `c_k`: `&[u8]` - The KEM ciphertext.
/// - `k_k`: `&[u8]` - The shared secret.
/// - `other_party_id`: `&[u8]` - The identifier of the other party.
/// - `tag`: `&[u8]` - The authentication tag to verify.
///
/// # Returns:
/// - `bool`: True, if posssible, else False.
pub fn is_shared_session_key_derivation_possible(
    client_password: &[u8],
    c: &[u8],
    pk: &[u8],
    c_k: &[u8],
    k_k: &[u8],
    other_party_id: &[u8],
    tag: &[u8],
) -> bool {
    is_tag_equal(client_password, c, pk, c_k, k_k, other_party_id, tag)
}

/// Generates a session key by hashing a tag and a shared secret using SHAKE-128 XOF.
///
/// # Parameters
/// - `tag_one`: `&[u8]` - The first authentication tag.
/// - `shared_secret`: `&[u8]` - The shared secret derived from key encapsulation.
///
/// # Returns
/// - `[u8; 32]`: The generated session key of 32 bytes.
pub fn generate_session_key(tag_one: &[u8], shared_secret: &[u8]) -> [u8; 32] {
    // Create a SHAKE-128 XOF instance
    let mut shake_128_xof = Shake128::default();

    // Feed the tag and the shared secret to the SHAKE-128 XOF instance
    shake_128_xof.update(tag_one);
    shake_128_xof.update(shared_secret);
    let mut xof_digest_reader = shake_128_xof.finalize_xof();

    // Initialize an XOF output buffer
    let mut xof_output_buffer: [u8; 32] = [0u8; XOF_DIGEST_SIZE];
    xof_digest_reader.read(&mut xof_output_buffer);

    // Return
    xof_output_buffer
}

/// Retrieves the Frodo-KEM instance for the specified protocol variant.
///
/// # Parameters:
/// - `protocol_variant`: `AvailableVariants` - The variant of the protocol.
///
/// # Returns:
/// - `FrodoKemDispatcher`: The Frodo-KEM instance corresponding to the protocol variant.    
pub fn get_frodo_instance(protocol_variant: AvailableVariants) -> FrodoKemDispatcher {
    protocol_variant.frodo_instance()
}
