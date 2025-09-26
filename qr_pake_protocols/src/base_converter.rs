use super::encode_decode::{Array, FieldElement, Polynomial};
use convert_base::Convert;

/// Converts a polynomial's coefficients from one base representation to another.
/// The polynomial with its `N` coefficients is treated as a single large integer
/// in base `from_base` having `N` digits.
///
/// # Parameters:
/// - `from_base`: `u64` - Original base of polynomial coefficients
/// - `to_base`: `u64` - Target base for encoding output
/// - `poly`: `&Polynomial<N>` - Reference to the polynomial with `N` coefficients which is to be base encoded
///
/// # Returns:
/// - `Vec<u8>`: The serialized base encoded polynomial.
pub fn base_encode_poly<const N: usize>(
    from_base: u64,
    to_base: u64,
    poly: &Polynomial<N>,
) -> Vec<u8> {
    let poly_as_vec: Vec<FieldElement> = poly.0.as_ref().to_vec();
    let poly_as_slice: Vec<u16> = poly_as_vec.iter().map(|fe| fe.0).collect();

    let mut fwd: Convert = Convert::new(from_base, to_base);
    let mut base_encoded_poly: Vec<u8> = fwd.convert::<u16, u8>(&poly_as_slice);

    // Calculate expected length for base-encoded output
    /*
    We are calculating it like this because, N = 256, the number of coefficients in the poly.
    And, all of them are in base 3329, i.e., all the coefficients will be between [0,...,3328],
    both inclusive. So, the total info in the poly is N digits in base 3329 and these N digits
    form 1 big number in base 3329, i.e., the polynomial itself. To represent all those N = 256
    digits in target base 256, we need enough bytes so that all the bits are preserved. This is
    why we calculate it this way which shows that how many base-256 digits are needed to store
    all the bits from N digits of base 3329.
     */
    let expected_len: usize =
        (N as f64 * (from_base as f64).log2() / (to_base as f64).log2()).ceil() as usize;

    // Pad with zeros if necessary
    /*
    This only happens if there is a FieldElement(0) at the last index, i.e. 255, of the polynomial.
    It seems that, in those cases, this zero gets ignored because of how the convert-base crate
    interprets the value. Probably in this case, 0 gets considered as the first digit/coefficient
    in the big whole polynomial, so 0 is not likely to be considered during conversion. So, we pad
    with 0 at the end so that during base decoding, the polynomial is always properly reconstructed
    with this 0 as a coefficient and that the total coefficients are = 256 and not less.
    */
    if base_encoded_poly.len() < expected_len {
        base_encoded_poly.resize(expected_len, 0);
    }

    base_encoded_poly
}

/// Reverses the base encoding process by converting the input bytes from `from_base`
/// representation to the `to_base` representation, then constructs a polynomial from
/// the resulting coefficients, which essentially restores the polynomial.
///
/// # Parameters:
/// - `from_base`: `u64` - Original base of polynomial coefficients
/// - `to_base`: `u64` - Target base for encoding output
/// - `base_encoded_poly`: `&[u8]` - Base-encoded polynomial as byte slice which is to be decoded
///
/// # Returns:
/// - `Polynomial<N>`: The base decoded polynomial with `N` coefficients
///
/// # Panics
/// Panics if decoded coefficient count doesn't match `N`
pub fn base_decode_poly<const N: usize>(
    from_base: u64,
    to_base: u64,
    base_encoded_poly: &[u8],
) -> Polynomial<N> {
    let mut back: Convert = Convert::new(from_base, to_base);

    let mut base_decoded_poly_as_vec: Vec<u16> = back.convert::<u8, u16>(base_encoded_poly);

    // Pad with zeros if necessary
    if base_decoded_poly_as_vec.len() < N {
        base_decoded_poly_as_vec.resize(N, 0);
    } else if base_decoded_poly_as_vec.len() > N {
        base_decoded_poly_as_vec.truncate(N);
    }

    // Converting to Array<FieldElement, N>
    let field_elements: Result<Array<FieldElement, N>, _> = Array::try_from(
        &base_decoded_poly_as_vec
            .iter()
            .map(|&v| FieldElement(v))
            .collect::<Vec<_>>()[..],
    );

    match field_elements {
        Ok(arr) => Polynomial(arr),
        Err(_) => panic!("Decoded polynomial does not have exactly {} elements", N),
    }
}
