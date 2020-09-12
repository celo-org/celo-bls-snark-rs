use super::encoding::{encode_public_key, encode_u16, encode_u32, EncodingError};
use algebra::bls12_377::G1Projective;
use blake2s_simd::Params;
use bls_crypto::{
    hash_to_curve::{try_and_increment::COMPOSITE_HASH_TO_G1, HashToCurve},
    PublicKey, Signature, OUT_DOMAIN, SIG_DOMAIN,
};
use bls_gadgets::utils::{bits_to_bytes, bytes_to_bits};

/// A header as parsed after being fetched from the Celo Blockchain
/// It contains information about the new epoch, as well as an aggregated
/// signature and bitmap from the validators from the previous block that
/// signed on it
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EpochTransition {
    /// The new epoch block which is being processed
    pub block: EpochBlock,
    /// The aggregate signature produced over the `EpochBlock`
    /// by the validators of the previous epoch
    pub aggregate_signature: Signature,
    /// The bitmap which determined the state transition
    pub bitmap: Vec<bool>,
}

/// Metadata about the next epoch
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EpochBlock {
    /// The block number
    pub index: u16,
    /// The entropy from this epoch, derived from the epoch block hash.
    pub epoch_entropy: Vec<u8>,
    /// The entropy from the parent epoch.
    pub parent_entropy: Vec<u8>,
    /// The maximum allowed number of signers that may be absent
    pub maximum_non_signers: u32,
    /// The public keys of the new validators
    pub new_public_keys: Vec<PublicKey>,
}

impl EpochBlock {
    /// Each epoch entropy value is 128 bits.
    pub const ENTROPY_BYTES: usize = 16;

    /// Creates a new epoch block
    pub fn new(index: u16, epoch_entropy: Vec<u8>, parent_entropy: Vec<u8>, maximum_non_signers: u32, new_public_keys: Vec<PublicKey>) -> Self {
        Self {
            index,
            epoch_entropy,
            parent_entropy,
            maximum_non_signers,
            new_public_keys,
        }
    }

    /// Encodes the block to bytes and then proceeds to hash it to BLS12-377's G1
    /// group using `SIG_DOMAIN` as a domain separator
    pub fn hash_to_g1(&self) -> Result<G1Projective, EncodingError> {
        let input = self.encode_to_bytes()?;
        let expected_hash: G1Projective =
            COMPOSITE_HASH_TO_G1.hash(SIG_DOMAIN, &input, &[]).unwrap();
        Ok(expected_hash)
    }

    /// Encodes the block to bytes and then hashes it with Blake2
    pub fn blake2(&self) -> Result<Vec<bool>, EncodingError> {
        Ok(hash_to_bits(&self.encode_to_bytes()?))
    }

    /// Encodes the block appended with the aggregate signature to bytes and then hashes it with Blake2
    pub fn blake2_with_aggregated_pk(&self) -> Result<Vec<bool>, EncodingError> {
        Ok(hash_to_bits(&self.encode_to_bytes_with_aggregated_pk()?))
    }

    /// Encodes the block to LE bits
    pub fn encode_to_bits(&self) -> Result<Vec<bool>, EncodingError> {
        let mut epoch_bits = vec![];
        epoch_bits.extend_from_slice(&encode_u16(self.index)?);
        // DO NOT MERGE: Handle the 0 pointer case here.
        epoch_bits.extend_from_slice(&bytes_to_bits(&self.epoch_entropy, Self::ENTROPY_BYTES * 8));
        epoch_bits.extend_from_slice(&bytes_to_bits(&self.parent_entropy, Self::ENTROPY_BYTES * 8));
        epoch_bits.extend_from_slice(&encode_u32(self.maximum_non_signers)?);
        for added_public_key in &self.new_public_keys {
            epoch_bits.extend_from_slice(encode_public_key(&added_public_key)?.as_slice());
        }
        Ok(epoch_bits)
    }

    /// Encodes the block with the aggregated public key from the vector of pubkeys to LE bits
    pub fn encode_to_bits_with_aggregated_pk(&self) -> Result<Vec<bool>, EncodingError> {
        let mut epoch_bits = self.encode_to_bits()?;
        let aggregated_pk = PublicKey::aggregate(&self.new_public_keys);
        epoch_bits.extend_from_slice(encode_public_key(&aggregated_pk)?.as_slice());
        Ok(epoch_bits)
    }

    /// Encodes the block to LE bytes
    pub fn encode_to_bytes(&self) -> Result<Vec<u8>, EncodingError> {
        Ok(bits_to_bytes(&self.encode_to_bits()?))
    }

    /// Encodes the block with the aggregated public key from the vector of pubkeys to LE bytes
    pub fn encode_to_bytes_with_aggregated_pk(&self) -> Result<Vec<u8>, EncodingError> {
        Ok(bits_to_bytes(&self.encode_to_bits_with_aggregated_pk()?))
    }
}

/// Serializes the first and last epoch to bytes, hashes them with Blake2 personalized to
/// `OUT_DOMAIN` and returns the LE bit representation
pub fn hash_first_last_epoch_block(
    first: &EpochBlock,
    last: &EpochBlock,
) -> Result<Vec<bool>, EncodingError> {
    let h1 = first.blake2()?;
    let h2 = last.blake2_with_aggregated_pk()?;
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
