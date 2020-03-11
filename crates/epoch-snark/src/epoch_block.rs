use super::encoding::{
    bits_to_bytes, bytes_to_bits, encode_public_key, encode_u16, encode_u32, EncodingError,
};
use blake2s_simd::Params;
use bls_crypto::PublicKey;

pub static OUT_DOMAIN: &[u8] = b"ULforout";

pub struct EpochBlock<'a> {
    index: u16,
    maximum_non_signers: u32,
    aggregated_public_key: &'a PublicKey, // TODO: This might be redundant.
    new_public_keys: &'a [&'a PublicKey],
}

impl<'a> EpochBlock<'a> {
    pub fn new(
        index: u16,
        maximum_non_signers: u32,
        aggregated_public_key: &'a PublicKey,
        new_public_keys: &'a [&PublicKey],
    ) -> Self {
        Self {
            index,
            maximum_non_signers,
            aggregated_public_key,
            new_public_keys,
        }
    }

    pub fn blake2(&self) -> Result<Vec<bool>, EncodingError> {
        Ok(hash_to_bits(&self.encode_to_bytes()?))
    }

    /// The goal of the validator diff encoding is to be a constant-size encoding so it would be
    /// more easily processable in SNARKs
    pub fn encode_to_bits(&self) -> Result<Vec<bool>, EncodingError> {
        let mut epoch_bits = vec![];
        epoch_bits.extend_from_slice(&encode_u16(self.index)?);
        epoch_bits.extend_from_slice(&encode_u32(self.maximum_non_signers)?);
        epoch_bits.extend_from_slice(encode_public_key(&self.aggregated_public_key)?.as_slice());
        for added_public_key in self.new_public_keys {
            epoch_bits.extend_from_slice(encode_public_key(&added_public_key)?.as_slice());
        }
        Ok(epoch_bits)
    }

    pub fn encode_to_bytes(&self) -> Result<Vec<u8>, EncodingError> {
        Ok(bits_to_bytes(&self.encode_to_bits()?))
    }
}

/// Serializes the first and last epoch to bytes, hashes them with Blake2 personalized to
/// `OUT_DOMAIN` and returns the LE bit representation
pub fn hash_first_last_epoch_block(
    first: &EpochBlock,
    last: &EpochBlock,
) -> Result<Vec<bool>, EncodingError> {
    let h1 = first.blake2()?;
    let h2 = last.blake2()?;
    Ok([h1, h2].concat())
}

/// Blake2 hash of the input personalized to `OUT_DOMAIN`
pub fn hash_to_bits(bytes: &[u8]) -> Vec<bool> {
    let hash = Params::new()
        .hash_length(32)
        .personal(OUT_DOMAIN)
        .to_state()
        .update(&bytes)
        .finalize()
        .as_ref()
        .to_vec();
    let mut bits = bytes_to_bits(&hash, 256);
    bits.reverse();
    bits
}
