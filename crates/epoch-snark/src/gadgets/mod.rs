mod epoch_data;
pub use epoch_data::EpochData;

mod hash_to_bits;
pub use hash_to_bits::HashToBits;

mod single_update;
pub use single_update::{ConstrainedEpoch, SingleUpdate};

mod pack;
pub use pack::MultipackGadget;

mod epoch_bits;
pub use epoch_bits::EpochBits;

mod epochs;
pub use epochs::{HashToBitsHelper, ValidatorSetUpdate};

// some helpers
use ark_bls12_377::{constraints::G2Var, Parameters as Bls12_377_Parameters};
use ark_bw6_761::Fr;
use ark_ec::bls12::Bls12Parameters;
use ark_ff::{BigInteger, FpParameters, PrimeField};
use ark_r1cs_std::{fields::fp::FpVar, prelude::*, Assignment};
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};

type FrVar = FpVar<Fr>;
pub type Bool = Boolean<<Bls12_377_Parameters as Bls12Parameters>::Fp>;
use bls_gadgets::{utils::bytes_le_to_bits_be, YToBitGadget};

#[cfg(test)]
pub mod test_helpers {
    use super::*;
    use crate::epoch_block::EpochBlock;
    use bls_crypto::{
        hash_to_curve::try_and_increment_cip22::COMPOSITE_HASH_TO_G1_CIP22, PublicKey, SIG_DOMAIN,
    };

    use ark_bls12_377::{Bls12_377, G1Projective};

    /// Maps a slice to a vector of Option values
    pub fn to_option_iter<T: Copy>(it: &[T]) -> Vec<Option<T>> {
        it.iter().map(|t| Some(*t)).collect()
    }

    /// Generate hashed point of epoch data without generating constraints
    #[tracing::instrument(target = "r1cs")]
    pub fn hash_epoch(epoch: &EpochData<Bls12_377>) -> G1Projective {
        let mut pubkeys = Vec::new();
        for pk in &epoch.public_keys {
            pubkeys.push(PublicKey::from(pk.unwrap()));
        }

        // Calculate the hash from our to_bytes function
        let (epoch_bytes, extra_data) = EpochBlock::new(
            epoch.index.unwrap(),
            epoch.round.unwrap(),
            epoch.epoch_entropy.as_ref().map(|v| v.to_vec()),
            epoch.parent_entropy.as_ref().map(|v| v.to_vec()),
            epoch.maximum_non_signers,
            pubkeys.len(),
            pubkeys,
        )
        .encode_inner_to_bytes_cip22()
        .unwrap();
        let (hash, _) = COMPOSITE_HASH_TO_G1_CIP22
            .hash_with_attempt_cip22(SIG_DOMAIN, &epoch_bytes, &extra_data)
            .unwrap();

        hash
    }
}

/// Returns a vector of field elements given a big-endian slice of booleans
pub fn pack<F: PrimeField, P: FpParameters>(values: &[bool]) -> Result<Vec<F>, SynthesisError> {
    values
        .chunks(P::CAPACITY as usize)
        .map(|c| {
            let b = F::BigInt::from_bits_be(c);
            F::from_repr(b).get()
        })
        .collect::<Result<Vec<_>, _>>()
}

/// Returns a constrained field element given a list of bytes in little endian order
fn bytes_to_fr(cs: ConstraintSystemRef<Fr>, bytes: Option<&[u8]>) -> Result<FrVar, SynthesisError> {
    FrVar::new_witness(cs, || {
        let bits = bytes_le_to_bits_be(bytes.get()?, 64 * <Fr as PrimeField>::BigInt::NUM_LIMBS);
        Ok(Fr::from(<Fr as PrimeField>::BigInt::from_bits_be(&bits)))
    })
}

/// Returns the bit representation of the Fr element in *little-endian* ordering.
#[tracing::instrument(target = "r1cs")]
fn fr_to_bits(input: &FrVar, length: usize) -> Result<Vec<Bool>, SynthesisError> {
    let input = input.to_bits_le()?;
    let result = input[0..length].to_vec();
    Ok(result)
}

/// Returns elements in big-endian order
#[tracing::instrument(target = "r1cs")]
fn g2_to_bits(input: &G2Var) -> Result<Vec<Bool>, SynthesisError> {
    let x_0 = input.x.c0.to_bits_be()?;
    let x_1 = input.x.c1.to_bits_be()?;
    let y_bit = input.y_to_bit()?;
    let mut output = Vec::new();
    output.extend_from_slice(&x_0);
    output.extend_from_slice(&x_1);
    output.push(y_bit);
    Ok(output)
}

/// Constrains booleans to be witness variables
#[tracing::instrument(target = "r1cs")]
fn constrain_bool<F: PrimeField>(
    input: &[Option<bool>],
    cs: ConstraintSystemRef<F>,
) -> Result<Vec<Boolean<F>>, SynthesisError> {
    input
        .iter()
        .map(|b| Boolean::new_witness(cs.clone(), || b.get()))
        .collect::<Result<Vec<_>, _>>()
}
