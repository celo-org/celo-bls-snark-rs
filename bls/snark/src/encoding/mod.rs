use algebra::{
    fields::{
        PrimeField,
        bls12_377::Fq
    },
    curves::ProjectiveCurve,
    bytes::ToBytes,
};
use bls_zexe::bls::keys::PublicKey;
use std::error::Error;

/// If bytes is a little endian representation of a number, this would return the bits of the
/// number in ascending order
fn bytes_to_bits(bytes: &Vec<u8>) -> Vec<bool> {
    let mut bits = vec![];
    for i in 0..bytes.len() {
        let mut byte = bytes[i];
        for _ in 0..8 {
            bits.push((byte & 1) == 1);
            byte >>= 1;
        }
    }

    bits
}

fn bits_to_bytes(bits: &Vec<bool>) -> Vec<u8> {
    let mut bytes = vec![];
    for chunk in bits.chunks(8) {
        let mut byte = 0;
        let mut twoi = 1;
        for i in 0..8 {
            byte += twoi*(if chunk[i] { 1 } else { 0 });
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

    let half = Fq::modulus_minus_one_div_two();
    let is_over_half = y.into_repr() > half;

    let mut x_bytes = vec![];
    x.write(&mut x_bytes)?;
    let mut bits = bytes_to_bits(&x_bytes);
    bits.push(is_over_half);

    Ok(bits)
}

pub fn encode_zero_value_public_key() -> Result<Vec<bool>, Box<dyn Error>> {
    // x coordinate and a y bit
    Ok(std::iter::repeat(false).take(Fq::size_in_bits() + 1).collect::<Vec<_>>())
}

/// The goal of the validator diff encoding is to be a constant-size encoding so it would be
/// more easily processable in SNARKs
fn encode_epoch_block_to_bits(removed_validators: &Vec<bool>, added_public_keys: &Vec<PublicKey>) -> Result<Vec<bool>, Box<dyn Error>> {
    let mut epoch_bits = vec![];
    epoch_bits.extend_from_slice(&removed_validators);

    let mut current_public_key_index = 0;
    let encoded_zero_value_public_key = encode_zero_value_public_key()?;
    for is_removed in removed_validators {
        if *is_removed {
            epoch_bits.extend_from_slice(&encoded_zero_value_public_key);
        } else {
            epoch_bits.extend_from_slice(&encode_public_key(&added_public_keys[current_public_key_index])?);
        }
        current_public_key_index += 1;
    }

    Ok(epoch_bits)
}

fn encode_epoch_block_to_bytes(removed_validators: &Vec<bool>, added_public_keys: &Vec<PublicKey>) -> Result<Vec<u8>, Box<dyn Error>> {
    Ok(bits_to_bytes(&encode_epoch_block_to_bits(removed_validators, added_public_keys)?))
}

#[cfg(test)]
mod test {
    use byteorder::{LittleEndian, WriteBytesExt};
    use rand::{Rng, SeedableRng};
    use crate::encoding::{bytes_to_bits, bits_to_bytes};
    use rand_xorshift::XorShiftRng;

    #[test]
    fn test_bytes_to_bits() {
        let mut rng = XorShiftRng::from_seed([0x5d, 0xbe, 0x62, 0x59, 0x8d, 0x31, 0x3d, 0x76, 0x32, 0x37, 0xdb, 0x17, 0xe5, 0xbc, 0x06, 0x54]);
        for _ in 0..100 {
            let n = rng.gen();
            let mut bytes = vec![];
            bytes.write_u64::<LittleEndian>(n).unwrap();

            let bits = bytes_to_bits(&bytes);
            let mut twoi = 1;
            let mut result: u64 = 0;
            for i in 0..bits.len() {
                result += twoi * (if bits[i] { 1 } else { 0 });
                twoi *= 2;
            }

            assert_eq!(result, n)
        }
    }

    #[test]
    fn test_bits_to_bytes() {
        let mut rng = XorShiftRng::from_seed([0x5d, 0xbe, 0x62, 0x59, 0x8d, 0x31, 0x3d, 0x76, 0x32, 0x37, 0xdb, 0x17, 0xe5, 0xbc, 0x06, 0x54]);
        for _ in 0..100 {
            let n = rng.gen();
            let mut bytes = vec![];
            bytes.write_u64::<LittleEndian>(n).unwrap();

            let bits = bytes_to_bits(&bytes);
            let result_bytes = bits_to_bytes(&bits);

            assert_eq!(bytes, result_bytes);
        }
    }
}