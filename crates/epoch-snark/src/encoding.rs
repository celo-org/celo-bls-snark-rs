use ark_bls12_377::{Fq, FqParameters};
use ark_ec::ProjectiveCurve;
use ark_ff::{FpParameters, PrimeField, ToBytes, Zero};
use ark_serialize::SerializationError;
use bls_crypto::{BLSError, PublicKey};
use bls_gadgets::utils::bytes_le_to_bits_be;
use byteorder::{LittleEndian, WriteBytesExt};
use thiserror::Error;

#[derive(Debug, Error)]
/// Union type for data serialization errors
pub enum EncodingError {
    #[error("Zexe Error: {0}")]
    ZexeSerialization(#[from] SerializationError),
    #[error("I/O Error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("BLS Error: {0}")]
    BLSError(#[from] BLSError),
}

/// The function assumes that the public key is not the point in infinity, which is true for
/// BLS public keys
pub fn encode_public_key(public_key: &PublicKey) -> Result<Vec<bool>, EncodingError> {
    let pk_affine = public_key.as_ref().into_affine();
    let x = pk_affine.x;
    let y = pk_affine.y;

    let y_c0_big = y.c0.into_repr();
    let y_c1_big = y.c1.into_repr();

    let zero = Fq::zero().into_repr();
    let half = Fq::modulus_minus_one_div_two();
    let is_over_half = y_c1_big > half || (y_c1_big == zero && y_c0_big > half);

    let mut bits = vec![];
    let mut x_bytes_c0 = vec![];
    x.c0.write(&mut x_bytes_c0)?;
    let bits_c0 = bytes_le_to_bits_be(&x_bytes_c0, FqParameters::MODULUS_BITS as usize);
    bits.extend_from_slice(&bits_c0);
    let mut x_bytes_c1 = vec![];
    x.c1.write(&mut x_bytes_c1)?;
    let bits_c1 = bytes_le_to_bits_be(&x_bytes_c1, FqParameters::MODULUS_BITS as usize);
    bits.extend_from_slice(&bits_c1);
    bits.push(is_over_half);

    Ok(bits)
}

/// LE Encodes a U8 to **bits**
pub(crate) fn encode_u8(num: u8) -> Result<Vec<bool>, EncodingError> {
    let bytes = vec![num];
    let bits = bytes
        .into_iter()
        .map(|x| (0..8).map(move |i| (((x as u8) & u8::pow(2, i)) >> i) == 1))
        .flatten()
        .collect::<Vec<_>>();
    Ok(bits)
}

/// LE Encodes a U16 to **bits**
pub(crate) fn encode_u16(num: u16) -> Result<Vec<bool>, EncodingError> {
    let mut bytes = vec![];
    bytes.write_u16::<LittleEndian>(num)?;
    let bits = bytes
        .into_iter()
        .map(|x| (0..8).map(move |i| (((x as u16) & u16::pow(2, i)) >> i) == 1))
        .flatten()
        .collect::<Vec<_>>();
    Ok(bits)
}

/// LE Encodes a U32 to **bits**
pub(crate) fn encode_u32(num: u32) -> Result<Vec<bool>, EncodingError> {
    let mut bytes = vec![];
    bytes.write_u32::<LittleEndian>(num)?;
    let bits = bytes
        .into_iter()
        .map(|x| (0..8).map(move |i| (((x as u32) & u32::pow(2, i)) >> i) == 1))
        .flatten()
        .collect::<Vec<_>>();
    Ok(bits)
}

#[cfg(test)]
mod test {
    use super::*;
    use ark_bls12_377::FqParameters;
    use ark_ff::FpParameters;
    use bls_gadgets::utils::bits_be_to_bytes_le;
    use byteorder::{LittleEndian, WriteBytesExt};
    use rand::{Rng, SeedableRng};
    use rand_xorshift::XorShiftRng;

    #[test]
    fn test_bytes_to_bits() {
        let mut rng = XorShiftRng::from_seed([
            0x5d, 0xbe, 0x62, 0x59, 0x8d, 0x31, 0x3d, 0x76, 0x32, 0x37, 0xdb, 0x17, 0xe5, 0xbc,
            0x06, 0x54,
        ]);
        for _ in 0..100 {
            let n = rng.gen();
            let mut bytes = vec![];
            bytes.write_u64::<LittleEndian>(n).unwrap();

            let bits = bytes_le_to_bits_be(&bytes, FqParameters::MODULUS_BITS as usize);
            let mut twoi: u64 = 1;
            let mut result: u64 = 0;
            let bits_len = bits.len();
            for i in 0..bits_len {
                result += twoi * (if bits[bits_len - 1 - i] { 1 } else { 0 });
                if i < bits_len - 1 {
                    twoi *= 2;
                }
            }

            assert_eq!(result, n)
        }
    }

    #[test]
    fn test_bits_to_bytes() {
        let mut rng = XorShiftRng::from_seed([
            0x5d, 0xbe, 0x62, 0x59, 0x8d, 0x31, 0x3d, 0x76, 0x32, 0x37, 0xdb, 0x17, 0xe5, 0xbc,
            0x06, 0x54,
        ]);
        for _ in 0..100 {
            let n = rng.gen();
            let mut bytes = vec![];
            bytes.write_u64::<LittleEndian>(n).unwrap();

            let bits = bytes_le_to_bits_be(&bytes, FqParameters::MODULUS_BITS as usize);
            let result_bytes = bits_be_to_bytes_le(&bits);

            assert_eq!(bytes, result_bytes);
        }
    }
}
