/*
[1] NIST FIPS-2023 ML-KEM
https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.203.pdf
*/

use core::convert::TryFrom;

pub const N: usize = 256;
pub const Q: usize = 3329;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Array<T, const N: usize>(pub [T; N]);

impl<T: Default + Copy, const N: usize> Default for Array<T, N> {
    fn default() -> Self {
        Self([T::default(); N])
    }
}

impl<T, const N: usize> AsRef<[T]> for Array<T, N> {
    fn as_ref(&self) -> &[T] {
        &self.0
    }
}

impl<T, const N: usize> AsMut<[T]> for Array<T, N> {
    fn as_mut(&mut self) -> &mut [T] {
        &mut self.0
    }
}

impl<T, const N: usize> std::ops::Deref for Array<T, N> {
    type Target = [T; N];
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T: Copy + Default, const N: usize> TryFrom<&[T]> for Array<T, N> {
    type Error = &'static str;

    fn try_from(slice: &[T]) -> Result<Self, Self::Error> {
        if slice.len() != N {
            return Err("Slice length does not match array length");
        }
        let mut arr: [T; N] = [T::default(); N];
        arr.copy_from_slice(slice);
        Ok(Array(arr))
    }
}

pub type Integer = u16;

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct FieldElement(pub Integer);

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct Polynomial<const N: usize>(pub Array<FieldElement, N>);

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct PolynomialVector<const K: usize, const N: usize>(pub Array<Polynomial<N>, K>);

/// Converts a bit array to a byte array (Algorithm 3 in [1]).
fn bits_to_bytes(bits: &[u8], out: &mut [u8]) {
    assert_eq!(
        bits.len() % 8,
        0,
        "The provided bits are not multiple of 8."
    );

    for (i, chunk) in bits.chunks(8).enumerate() {
        let mut byte: u8 = 0u8;
        for (j, &bit) in chunk.iter().enumerate() {
            byte |= (bit & 1) << j;
        }
        out[i] = byte;
    }
}

/// Converts a byte array into a bit array (Algorithm 4 in [1]).
fn bytes_to_bits(bytes: &[u8], bits: &mut [u8]) {
    for (i, &byte) in bytes.iter().enumerate() {
        let mut c: u8 = byte;
        for j in 0..8 {
            bits[8 * i + j] = c & 1;
            c >>= 1;
        }
    }
}

/// Encodes a polynomial of N coefficients, each `d_value` bits, into a byte array (Algorithm 5 in [1]).
pub fn byte_encode_poly<const N: usize>(poly: &Polynomial<N>, d_value: usize, out: &mut [u8]) {
    let mut b: Vec<u8> = vec![0u8; N * d_value];
    for i in 0..N {
        let mut a: u32 = poly.0[i].0 as u32;
        for j in 0..d_value {
            b[i * d_value + j] = (a & 1) as u8;
            a >>= 1;
        }
    }
    bits_to_bytes(&b, out);
}

/// Decodes a byte array into a polynomial of N coefficients, each `d_value` bits (Algorithm 6 in [1]).
pub fn byte_decode_poly<const N: usize>(bytes: &[u8], d_value: usize) -> Polynomial<N> {
    let mut bits = vec![0u8; N * d_value];
    bytes_to_bits(bytes, &mut bits);

    let mut coeffs: [FieldElement; N] = [FieldElement(0); N];
    let m = if d_value < 12 { 1 << d_value } else { Q };

    for i in 0..N {
        let mut val: u32 = 0;
        for j in 0..d_value {
            val |= (bits[i * d_value + j] as u32) << j;
        }
        coeffs[i] = FieldElement((val % m as u32) as u16);
    }
    Polynomial(Array(coeffs))
}

pub fn compress_polyvec<const K: usize, const N: usize>(
    polyvec: &PolynomialVector<K, N>,
    d_value: usize,
) -> PolynomialVector<K, N> {
    let mut out = [Polynomial::<N>(Array([FieldElement(0); N])); K];
    for i in 0..K {
        out[i] = compress_poly(&polyvec.0[i], d_value);
    }
    PolynomialVector(Array(out))
}

pub fn compress_poly<const N: usize>(poly: &Polynomial<N>, d_value: usize) -> Polynomial<N> {
    let mut out = [FieldElement(0); N];
    let two_d = 1 << d_value;
    for i in 0..N {
        let x = poly.0[i].0 as usize;
        // ( (2^d / q) * x ).round() mod 2^d
        let compressed = (((two_d * x + Q / 2) / Q) % two_d) as u16;
        out[i] = FieldElement(compressed);
    }
    Polynomial(Array(out))
}

pub fn decompress_polyvec<const K: usize, const N: usize>(
    polyvec: &PolynomialVector<K, N>,
    d_value: usize,
) -> PolynomialVector<K, N> {
    let mut out = [Polynomial::<N>(Array([FieldElement(0); N])); K];
    for i in 0..K {
        out[i] = decompress_poly(&polyvec.0[i], d_value);
    }
    PolynomialVector(Array(out))
}

pub fn decompress_poly<const N: usize>(poly: &Polynomial<N>, d_value: usize) -> Polynomial<N> {
    let mut out = [FieldElement(0); N];
    let two_d = 1 << d_value;
    for i in 0..N {
        let y = poly.0[i].0 as usize;
        // ( (q / 2^d) * y ).round()
        let decompressed = (((Q * y + two_d / 2) / two_d) % Q) as u16;
        out[i] = FieldElement(decompressed);
    }
    Polynomial(Array(out))
}

pub trait ByteEncoderDecoder<const K: usize, const N: usize, const BYTES: usize> {
    fn byte_decode(enc: &Array<u8, BYTES>, d_value: usize) -> PolynomialVector<K, N>;
    fn byte_encode(polyvec: &PolynomialVector<K, N>, d_value: usize) -> Array<u8, BYTES>;
}

impl<const K: usize, const N: usize, const BYTES: usize> ByteEncoderDecoder<K, N, BYTES>
    for PolynomialVector<K, N>
{
    /// Performs ByteDecode according to the FIPS-203 ML-KEM specifications
    fn byte_decode(
        byte_encoded_value: &Array<u8, BYTES>,
        d_value: usize,
    ) -> PolynomialVector<K, N> {
        let mut polys: [Polynomial<N>; K] = [Polynomial(Array([FieldElement(0); N])); K];
        let poly_bytes: usize = BYTES / K;
        for k in 0..K {
            let start: usize = k * poly_bytes;
            let end: usize = start + poly_bytes;
            polys[k] = byte_decode_poly::<N>(&byte_encoded_value.0[start..end], d_value);
        }
        PolynomialVector(Array(polys))
    }

    /// Performs ByteEncode according to the FIPS-203 ML-KEM specifications
    fn byte_encode(polyvec: &PolynomialVector<K, N>, d_value: usize) -> Array<u8, BYTES> {
        let poly_bytes: usize = BYTES / K;
        let mut out: [u8; BYTES] = [0u8; BYTES];
        for k in 0..K {
            byte_encode_poly::<N>(
                &polyvec.0[k],
                d_value,
                &mut out[k * poly_bytes..(k + 1) * poly_bytes],
            );
        }
        Array(out)
    }
}
