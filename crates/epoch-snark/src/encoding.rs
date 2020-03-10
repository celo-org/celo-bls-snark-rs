use algebra::{
    bls12_377::{Fq, FqParameters},
    FpParameters, PrimeField, ProjectiveCurve, ToBytes,
};
use bls_crypto::PublicKey;
use byteorder::{LittleEndian, WriteBytesExt};
use std::error::Error;

/// If bytes is a little endian representation of a number, this would return the bits of the
/// number in descending order
pub fn bytes_to_bits(bytes: &[u8], bits_to_take: usize) -> Vec<bool> {
    let mut bits = vec![];
    for b in bytes {
        let mut byte = *b;
        for _ in 0..8 {
            bits.push((byte & 1) == 1);
            byte >>= 1;
        }
    }

    bits.into_iter()
        .take(bits_to_take)
        .collect::<Vec<bool>>()
        .into_iter()
        .rev()
        .collect()
}

pub fn bits_to_bytes(bits: &[bool]) -> Vec<u8> {
    let mut bytes = vec![];
    let reversed_bits = {
        let mut tmp = bits.to_owned();
        tmp.reverse();
        tmp
    };
    for chunk in reversed_bits.chunks(8) {
        let mut byte = 0;
        let mut twoi: u64 = 1;
        for c in chunk {
            byte += (twoi * (*c as u64)) as u8;
            twoi *= 2;
        }
        bytes.push(byte);
    }

    bytes
}

/// The function assumes that the public key is not the point in infinity, which is true for
/// BLS public keys
pub fn encode_public_key(public_key: &PublicKey) -> Result<Vec<bool>, Box<dyn Error>> {
    let pk_affine = public_key.get_pk().into_affine();
    let x = pk_affine.x;
    let y = pk_affine.y;

    let y_c0_big = y.c0.into_repr();
    let y_c1_big = y.c1.into_repr();

    let half = Fq::modulus_minus_one_div_two();
    let is_over_half = y_c1_big > half || (y_c1_big == half && y_c0_big > half);

    let mut bits = vec![];
    let mut x_bytes_c0 = vec![];
    x.c0.write(&mut x_bytes_c0)?;
    let bits_c0 = bytes_to_bits(&x_bytes_c0, FqParameters::MODULUS_BITS as usize);
    bits.extend_from_slice(&bits_c0);
    let mut x_bytes_c1 = vec![];
    x.c1.write(&mut x_bytes_c1)?;
    let bits_c1 = bytes_to_bits(&x_bytes_c1, FqParameters::MODULUS_BITS as usize);
    bits.extend_from_slice(&bits_c1);
    bits.push(is_over_half);

    Ok(bits)
}

fn encode_u16(num: u16) -> Result<Vec<bool>, Box<dyn Error>> {
    let mut bytes = vec![];
    bytes.write_u16::<LittleEndian>(num)?;
    let bits = bytes
        .into_iter()
        .map(|x| (0..8).map(move |i| (((x as u16) & u16::pow(2, i)) >> i) == 1))
        .flatten()
        .collect::<Vec<_>>();
    Ok(bits)
}

fn encode_u32(num: u32) -> Result<Vec<bool>, Box<dyn Error>> {
    let mut bytes = vec![];
    bytes.write_u32::<LittleEndian>(num)?;
    let bits = bytes
        .into_iter()
        .map(|x| (0..8).map(move |i| (((x as u32) & u32::pow(2, i)) >> i) == 1))
        .flatten()
        .collect::<Vec<_>>();
    Ok(bits)
}

/// The goal of the validator diff encoding is to be a constant-size encoding so it would be
/// more easily processable in SNARKs
pub fn encode_epoch_block_to_bits(
    epoch_index: u16,
    maximum_non_signers: u32,
    aggregated_public_key: &PublicKey,
    new_public_keys: &[&PublicKey],
) -> Result<Vec<bool>, Box<dyn Error>> {
    let mut epoch_bits = vec![];

    epoch_bits.extend_from_slice(&encode_u16(epoch_index)?);
    epoch_bits.extend_from_slice(&encode_u32(maximum_non_signers)?);
    epoch_bits.extend_from_slice(encode_public_key(&aggregated_public_key)?.as_slice());
    for added_public_key in new_public_keys {
        epoch_bits.extend_from_slice(encode_public_key(&added_public_key)?.as_slice());
    }
    Ok(epoch_bits)
}

pub fn encode_epoch_block_to_bytes(
    epoch_index: u16,
    maximum_non_signers: u32,
    aggregated_public_key: &PublicKey,
    added_public_keys: &[&PublicKey],
) -> Result<Vec<u8>, Box<dyn Error>> {
    Ok(bits_to_bytes(&encode_epoch_block_to_bits(
        epoch_index,
        maximum_non_signers,
        aggregated_public_key,
        added_public_keys,
    )?))
}

#[cfg(test)]
mod test {
    use crate::encoding::{bits_to_bytes, bytes_to_bits};
    use algebra::{bls12_377::FqParameters, FpParameters};
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

            let bits = bytes_to_bits(&bytes, FqParameters::MODULUS_BITS as usize);
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

            let bits = bytes_to_bits(&bytes, FqParameters::MODULUS_BITS as usize);
            let result_bytes = bits_to_bytes(&bits);

            assert_eq!(bytes, result_bytes);
        }
    }
}
