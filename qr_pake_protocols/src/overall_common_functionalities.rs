use super::{
    base_converter::*,
    encode_decode::{
        byte_decode_poly, byte_encode_poly, compress_poly, compress_polyvec, decompress_poly,
        decompress_polyvec, Array, ByteEncoderDecoder, FieldElement, Polynomial, PolynomialVector,
        N, Q,
    },
    mlkem_variant_wrapper::MlKemDispatcher,
    protocol_variants::AvailableVariants::{self, *},
};
use aes::{Aes128, Aes192, Aes256};
use ctr::cipher::{KeyIvInit, StreamCipher};
use ctr::Ctr128LE;
use rand::{rngs::OsRng, RngCore};

const TARGET_BASE: u64 = 256;
const D_VALUE_FOR_PK: usize = 12;

/// Retrieves the Kyber instance for the specified protocol variant.
///
/// # Parameters:
/// - `protocol_variant`: `AvailableVariants` - The variant of the protocol.
///
/// # Returns:
/// - `MlKemDispatcher`: The Kyber instance corresponding to the protocol variant.
pub fn get_kyber_instance(protocol_variant: AvailableVariants) -> MlKemDispatcher {
    protocol_variant.kyber_instance()
}

/// Generates a base-encoded KEM public key for a specific Kyber variant.
///
/// # Parameters:
/// - `protocol_variant`: `AvailableVariants` - The chosen variant
/// - `pk_as_slice`: `&[u8]` - The KEM public key bytes
///
/// # Returns:
/// - `(Vec<u8>)` – The base encoded KEM public key.
pub fn get_base_encoded_pk(protocol_variant: AvailableVariants, pk_as_slice: &[u8]) -> Vec<u8> {
    let (remaining_bytes, last_32_bytes) = split_pk_slice(pk_as_slice);

    match protocol_variant {
        LightWeight => {
            const K: usize = 2;
            const PK_BYTES: usize = 768; // This is without the last 32 bytes
            invoke_pk_base_encoder::<K, PK_BYTES>(&remaining_bytes, &last_32_bytes)
        }
        Recommended => {
            const K: usize = 3;
            const PK_BYTES: usize = 1152; // This is without the last 32 bytes
            invoke_pk_base_encoder::<K, PK_BYTES>(&remaining_bytes, &last_32_bytes)
        }
        Paranoid => {
            const K: usize = 4;
            const PK_BYTES: usize = 1536; // This is without the last 32 bytes
            invoke_pk_base_encoder::<K, PK_BYTES>(&remaining_bytes, &last_32_bytes)
        }
    }
}

/// Processes the polynomials of a KEM public key and performs its base conversion from a source base to a target base.
///
/// # Parameters:
/// - `remaining_bytes`: `&[u8]` - The KEM public key bytes to decode into polynomials
/// - `last_32_bytes`: `&[u8]` - The seed of the KEM public key
///
/// # Returns:
/// - `(Vec<u8>)` – The base encoded KEM public key.
fn invoke_pk_base_encoder<const K: usize, const PK_BYTES: usize>(
    remaining_bytes: &[u8],
    last_32_bytes: &[u8],
) -> Vec<u8> {
    // Get the coefficients of the remaining bytes as polynomial vector
    let poly_vec: PolynomialVector<K, N> =
        get_polyvec_coefficients::<K, PK_BYTES>(&remaining_bytes, D_VALUE_FOR_PK);
    let mut poly_vec_base_encoded: Vec<u8> = Vec::new();

    for poly in poly_vec.0.iter() {
        let poly_base_encoded = base_encode_poly(Q as u64, TARGET_BASE, poly);
        poly_vec_base_encoded.extend(poly_base_encoded);
    }

    let pk_base_encoded: Vec<u8> = concatenate(poly_vec_base_encoded, last_32_bytes.to_vec());
    pk_base_encoded
}

pub fn get_base_encoded_kem_ciphertext(
    protocol_variant: AvailableVariants,
    kem_ciphertext_as_slice: &[u8],
) -> Vec<u8> {
    match protocol_variant {
        LightWeight => {
            const K: usize = 2;
            const D_U: usize = 10;
            const D_V: usize = 4;
            const C1_LEN: usize = 32 * D_U * K;
            const C2_LEN: usize = 32 * D_V;
            invoke_kem_ciphertext_base_encoder::<K, D_U, D_V, C1_LEN, C2_LEN>(
                kem_ciphertext_as_slice,
            )
        }
        Recommended => {
            const K: usize = 3;
            const D_U: usize = 10;
            const D_V: usize = 4;
            const C1_LEN: usize = 32 * D_U * K;
            const C2_LEN: usize = 32 * D_V;
            invoke_kem_ciphertext_base_encoder::<K, D_U, D_V, C1_LEN, C2_LEN>(
                kem_ciphertext_as_slice,
            )
        }
        Paranoid => {
            const K: usize = 4;
            const D_U: usize = 11;
            const D_V: usize = 5;
            const C1_LEN: usize = 32 * D_U * K;
            const C2_LEN: usize = 32 * D_V;
            invoke_kem_ciphertext_base_encoder::<K, D_U, D_V, C1_LEN, C2_LEN>(
                kem_ciphertext_as_slice,
            )
        }
    }
}

fn invoke_kem_ciphertext_base_encoder<
    const K: usize,
    const D_U: usize,
    const D_V: usize,
    const C1_LEN: usize,
    const C2_LEN: usize,
>(
    kem_ciphertext_as_slice: &[u8],
) -> Vec<u8> {
    let c1 = &kem_ciphertext_as_slice[0..C1_LEN];
    let c2 = &kem_ciphertext_as_slice[C1_LEN..(C1_LEN + C2_LEN)];
    let polyvec_u = get_polyvec_coefficients::<K, C1_LEN>(c1, D_U);
    let deompressed_polyvec_u = decompress_polyvec::<K, N>(&polyvec_u, D_U);

    let poly_v = get_poly_coefficients::<N>(c2, D_V);
    let decompressed_poly_v = decompress_poly(&poly_v, D_V);

    let mut kem_ciphertext_base_encoded: Vec<u8> = Vec::new();

    for poly in deompressed_polyvec_u.0.iter() {
        let poly_in_u_base_encoded = base_encode_poly(Q as u64, TARGET_BASE, poly);
        kem_ciphertext_base_encoded.extend(poly_in_u_base_encoded);
    }

    let poly_v_base_encoded = base_encode_poly(Q as u64, TARGET_BASE, &decompressed_poly_v);
    kem_ciphertext_base_encoded.extend(poly_v_base_encoded);

    kem_ciphertext_base_encoded
}

/// Encrypts plaintext using AES in Counter Mode with the provided key.
///
/// # Parameters:
/// - `input_key`: `&[u8]` - The input key.
/// - `plaintext`: `&[u8]` - The data to be encrypted.
///
/// # Returns:
/// - (`Vec<u8>`, `Vec<u8>`): The resulting ciphertext and the nonce.
///
/// # Panics
/// Panics if the `input_key` length is not 16, 24, or 32 bytes.
pub fn encrypt_data(input_key: &[u8], plaintext: &[u8]) -> (Vec<u8>, Vec<u8>) {
    if ![16, 24, 32].contains(&input_key.len()) {
        panic!("Invalid AES Input Key Length. The input key is of {} bytes, which is not within the acceptable key sizes of 16, 24 or 32 bytes.", &input_key.len());
    }

    // Generate a 12 byte (96-bit) Nonce for AES in Counter Mode
    let mut nonce: [u8; 12] = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);

    // Construct the IV from the nonce to be used
    let mut iv: [u8; 16] = [0u8; 16];
    iv[..12].copy_from_slice(&nonce);

    // Set the initial counter value to 1 of 32 bits
    iv[12..16].copy_from_slice(&[0, 0, 0, 1]);

    let nonce_vec: Vec<u8> = nonce.to_vec();

    // Create a mutable copy
    let mut ciphertext: Vec<u8> = plaintext.to_vec();

    // Check the input key length and use the AES in Counter Mode Encryption Variant
    if input_key.len() == 16 {
        let mut cipher = Ctr128LE::<Aes128>::new(input_key.into(), iv.as_slice().into());
        cipher.apply_keystream(&mut ciphertext); // In-place encryption
    } else if input_key.len() == 24 {
        let mut cipher = Ctr128LE::<Aes192>::new(input_key.into(), iv.as_slice().into());
        cipher.apply_keystream(&mut ciphertext); // In-place encryption
    } else {
        let mut cipher = Ctr128LE::<Aes256>::new(input_key.into(), iv.as_slice().into());
        cipher.apply_keystream(&mut ciphertext); // In-place encryption
    }

    (ciphertext, nonce_vec)
}

/// Decrypts ciphertext using AES in Counter Mode with the provided key.
///
/// # Parameters:
/// - `input_key`: `&[u8]` - The input key.
/// - `ciphertext`: `&[u8]` - The data to be decrypted.
/// - `nonce`: `&[u8]` - The nonce accompanying the ciphertext.
///
/// # Returns:
/// - `Vec<u8>`: The resulting plaintext.
///
/// # Panics
/// Panics if the `input_key` length is not 16, 24, or 32 bytes.
pub fn decrypt_data(input_key: &[u8], ciphertext: &[u8], nonce: &[u8]) -> Vec<u8> {
    // Construct the IV from the nonce to be used
    let mut iv: [u8; 16] = [0u8; 16];
    iv[..12].copy_from_slice(nonce);

    // Set the initial counter value to 1 of 32 bits
    iv[12..16].copy_from_slice(&[0, 0, 0, 1]);

    // Create a mutable copy
    let mut plaintext: Vec<u8> = ciphertext.to_vec();

    // Check the input key length and use the AES in Counter Mode Encryption Variant
    if input_key.len() == 16 {
        let mut cipher = Ctr128LE::<Aes128>::new_from_slices(input_key, &iv).unwrap();
        cipher.apply_keystream(&mut plaintext); // In-place decryption
    } else if input_key.len() == 24 {
        let mut cipher = Ctr128LE::<Aes192>::new_from_slices(input_key, &iv).unwrap();
        cipher.apply_keystream(&mut plaintext); // In-place decryption
    } else {
        let mut cipher = Ctr128LE::<Aes256>::new_from_slices(input_key, &iv).unwrap();
        cipher.apply_keystream(&mut plaintext); // In-place decryption
    }

    plaintext
}

/// Generates/Restores a base-encoded KEM public key in its original base decoded form for a specific Kyber variant.
///
/// # Parameters:
/// - `protocol_variant`: `AvailableVariants` - The chosen variant
/// - `pk_base_converted_as_slice`: `&[u8]` - The base encoded KEM public key bytes
///
/// # Returns:
/// - `(Vec<u8>)` – The restored/base decoded KEM public key.
pub fn get_base_decoded_pk(
    protocol_variant: AvailableVariants,
    pk_base_converted_as_slice: &[u8],
) -> Vec<u8> {
    let (remaining_bytes, last_32_bytes): (Vec<u8>, Vec<u8>) =
        split_pk_slice(pk_base_converted_as_slice);

    match protocol_variant {
        LightWeight => {
            const K: usize = 2;
            const PK_BYTES: usize = 768; // This is without the last 32 bytes
            invoke_pk_base_decoder::<K, PK_BYTES>(&remaining_bytes, &last_32_bytes)
        }
        Recommended => {
            const K: usize = 3;
            const PK_BYTES: usize = 1152; // This is without the last 32 bytes
            invoke_pk_base_decoder::<K, PK_BYTES>(&remaining_bytes, &last_32_bytes)
        }
        Paranoid => {
            const K: usize = 4;
            const PK_BYTES: usize = 1536; // This is without the last 32 bytes
            invoke_pk_base_decoder::<K, PK_BYTES>(&remaining_bytes, &last_32_bytes)
        }
    }
}

/// Reconstructs the KEM public key from the base-encoded KEM public key.
///
/// # Parameters:
/// - `remaining_bytes`: `&[u8]` - The base encoded KEM public key bytes
/// - `last_32_bytes`: `&[u8]` - The seed of the KEM public key
///
/// # Returns:
/// - `(Vec<u8>)` – The restored/base decoded KEM public key.
fn invoke_pk_base_decoder<const K: usize, const PK_BYTES: usize>(
    remaining_bytes: &[u8],
    last_32_bytes: &[u8],
) -> Vec<u8> {
    let mut polys: [Polynomial<N>; K] = [Polynomial(Array([FieldElement(0); N])); K];

    let mut offset: usize = 0;
    let expected_len: usize =
        (N as f64 * (Q as f64).log2() / (TARGET_BASE as f64).log2()).ceil() as usize;
    for k in 0..K {
        let base_decoded_poly: Polynomial<N> = base_decode_poly(
            TARGET_BASE,
            Q as u64,
            &remaining_bytes[offset..offset + expected_len],
        );
        polys[k] = base_decoded_poly;
        offset += expected_len;
    }
    let poly_vec_base_decoded: PolynomialVector<K, N> = PolynomialVector(Array(polys));

    // Byte encode the base decoded polynomial vector
    let poly_vec: Vec<u8> =
        <PolynomialVector<K, N> as ByteEncoderDecoder<K, N, PK_BYTES>>::byte_encode(
            &poly_vec_base_decoded,
            D_VALUE_FOR_PK,
        )
        .to_vec();

    let pk_recovered: Vec<u8> = concatenate(poly_vec, last_32_bytes.to_vec());
    pk_recovered
}

pub fn get_base_decoded_kem_ciphertext(
    protocol_variant: AvailableVariants,
    kem_ciphertext_base_converted_as_slice: &[u8],
) -> Vec<u8> {
    match protocol_variant {
        LightWeight => {
            const K: usize = 2;
            const D_U: usize = 10;
            const D_V: usize = 4;
            const C1_LEN: usize = 32 * D_U * K;
            const C2_LEN: usize = 32 * D_V;
            invoke_kem_ciphertext_base_decoder::<K, D_U, D_V, C1_LEN, C2_LEN>(
                kem_ciphertext_base_converted_as_slice,
            )
        }
        Recommended => {
            const K: usize = 3;
            const D_U: usize = 10;
            const D_V: usize = 4;
            const C1_LEN: usize = 32 * D_U * K;
            const C2_LEN: usize = 32 * D_V;
            invoke_kem_ciphertext_base_decoder::<K, D_U, D_V, C1_LEN, C2_LEN>(
                kem_ciphertext_base_converted_as_slice,
            )
        }
        Paranoid => {
            const K: usize = 4;
            const D_U: usize = 11;
            const D_V: usize = 5;
            const C1_LEN: usize = 32 * D_U * K;
            const C2_LEN: usize = 32 * D_V;
            invoke_kem_ciphertext_base_decoder::<K, D_U, D_V, C1_LEN, C2_LEN>(
                kem_ciphertext_base_converted_as_slice,
            )
        }
    }
}

fn invoke_kem_ciphertext_base_decoder<
    const K: usize,
    const D_U: usize,
    const D_V: usize,
    const C1_LEN: usize,
    const C2_LEN: usize,
>(
    kem_ciphertext_base_converted_as_slice: &[u8],
) -> Vec<u8> {
    let mut polys_in_u: [Polynomial<N>; K] = [Polynomial(Array([FieldElement(0); N])); K];

    let mut offset: usize = 0;
    let expected_len: usize =
        (N as f64 * (Q as f64).log2() / (TARGET_BASE as f64).log2()).ceil() as usize;

    for k in 0..K {
        let base_decoded_poly_in_u: Polynomial<N> = base_decode_poly(
            TARGET_BASE,
            Q as u64,
            &kem_ciphertext_base_converted_as_slice[offset..offset + expected_len],
        );
        polys_in_u[k] = base_decoded_poly_in_u;
        offset += expected_len;
    }
    let polyvec_u_base_decoded: PolynomialVector<K, N> = PolynomialVector(Array(polys_in_u));
    let poly_v_base_decoded: Polynomial<N> = base_decode_poly(
        TARGET_BASE,
        Q as u64,
        &kem_ciphertext_base_converted_as_slice[offset..offset + expected_len],
    );

    let compressed_polyvec_u_base_decoded: PolynomialVector<K, N> =
        compress_polyvec(&polyvec_u_base_decoded, D_U);
    let compressed_poly_v: Polynomial<N> = compress_poly(&poly_v_base_decoded, D_V);

    let c1 = <PolynomialVector<K, N> as ByteEncoderDecoder<K, N, C1_LEN>>::byte_encode(
        &compressed_polyvec_u_base_decoded,
        D_U,
    )
    .to_vec();
    let mut c2: [u8; C2_LEN] = [0u8; C2_LEN];
    byte_encode_poly(&compressed_poly_v, D_V, &mut c2);

    let kem_ciphertext_recovered: Vec<u8> = concatenate(c1, c2.to_vec());
    kem_ciphertext_recovered
}

/// Splits the KEM public key and extracts the seed and the remaining bytes.
///
/// # Parameters:
/// - `pk_as_slice`: `&[u8]` - The byte slice representing the whole byte encoded KEM public key.
///
/// # Returns:
/// A tuple containing:
/// - `(Vec<u8>)` – The remaining bytes after extracting the seed.
/// - `(Vec<u8>)` – The last 32 bytes which is the seed of KEM public key.
fn split_pk_slice(pk_as_slice: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let length: usize = pk_as_slice.len();
    assert!(
        length >= 32,
        "The pk_as_slice slice must be at least 32 bytes long"
    );

    let (remaining_bytes, last_32_bytes) = pk_as_slice.split_at(length - 32);
    (remaining_bytes.to_vec(), last_32_bytes.to_vec())
}

fn get_polyvec_coefficients<const K: usize, const BYTES: usize>(
    polyvec_as_slice: &[u8],
    d_value: usize,
) -> PolynomialVector<K, N> {
    let polyvec_array = Array::<u8, BYTES>::try_from(polyvec_as_slice).unwrap();
    PolynomialVector::<K, N>::byte_decode(&polyvec_array, d_value)
}

fn get_poly_coefficients<const N: usize>(poly_as_slice: &[u8], d_value: usize) -> Polynomial<N> {
    byte_decode_poly::<N>(poly_as_slice, d_value)
}

/// Concatenates two byte vectors.
///
/// # Parameters:
/// - `input_1`: `Vec<u8>` - The first input byte vector.
/// - `input_2`: `Vec<u8>` - The second input byte vector.
///
/// # Returns:
/// - `Vec<u8>`: A concatenated byte vector generated from the inputs.
fn concatenate(input_1: Vec<u8>, input_2: Vec<u8>) -> Vec<u8> {
    input_1.iter().chain(input_2.iter()).copied().collect()
}
