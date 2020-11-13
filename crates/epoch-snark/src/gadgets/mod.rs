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
use algebra::{
    bls12_377::Parameters as Bls12_377_Parameters, bw6_761::Fr, curves::bls12::Bls12Parameters,
    BigInteger, FpParameters, PrimeField,
};
use r1cs_core::{ConstraintSystemRef, SynthesisError};
use r1cs_std::{bls12_377::G2Var, fields::fp::FpVar, prelude::*, Assignment};

type FrVar = FpVar<Fr>;
pub type Bool = Boolean<<Bls12_377_Parameters as Bls12Parameters>::Fp>;
use bls_gadgets::{utils::bytes_le_to_bits_be, YToBitGadget};

#[cfg(test)]
pub mod test_helpers {
    use super::*;
    use crate::epoch_block::EpochBlock;
    use bls_crypto::{
        hash_to_curve::try_and_increment::COMPOSITE_HASH_TO_G1, PublicKey, SIG_DOMAIN,
    };

    use algebra::{bls12_377::G1Projective, Bls12_377};

    pub fn to_option_iter<T: Copy>(it: &[T]) -> Vec<Option<T>> {
        it.iter().map(|t| Some(*t)).collect()
    }

    pub fn hash_epoch(epoch: &EpochData<Bls12_377>) -> G1Projective {
        let mut pubkeys = Vec::new();
        for pk in &epoch.public_keys {
            pubkeys.push(PublicKey::from(pk.unwrap()));
        }

        // Calculate the hash from our to_bytes function
        let (epoch_bytes, extra_data) = EpochBlock::new(
            epoch.index.unwrap(),
            epoch.epoch_entropy.as_ref().map(|v| v.to_vec()),
            epoch.parent_entropy.as_ref().map(|v| v.to_vec()),
            epoch.maximum_non_signers,
            pubkeys,
        )
        .encode_inner_to_bytes()
        .unwrap();
        let (hash, _) = COMPOSITE_HASH_TO_G1
            .hash_with_attempt_cip22(SIG_DOMAIN, &epoch_bytes, &extra_data)
            .unwrap();

        hash
    }
}

pub(super) fn pack<F: PrimeField, P: FpParameters>(
    values: &[bool],
) -> Result<Vec<F>, SynthesisError> {
    values
        .chunks(P::CAPACITY as usize)
        .map(|c| {
            let b = F::BigInt::from_bits(c);
            F::from_repr(b).get()
        })
        .collect::<Result<Vec<_>, _>>()
}

fn bytes_to_fr(cs: ConstraintSystemRef<Fr>, bytes: Option<&[u8]>) -> Result<FrVar, SynthesisError> {
    FrVar::new_witness(cs, || {
        let bits = bytes_le_to_bits_be(bytes.get()?, 64 * <Fr as PrimeField>::BigInt::NUM_LIMBS);
        Ok(Fr::from(<Fr as PrimeField>::BigInt::from_bits(&bits)))
    })
}

/// Returns the bit representation of the Fr element in *little-endian* ordering.
fn fr_to_bits(input: &FrVar, length: usize) -> Result<Vec<Bool>, SynthesisError> {
    println!("here");
    let input = input.to_bits_le()?;
    let result = input[0..length].to_vec(); 
    Ok(result)
}

/// Returns elements in big-endian order
fn g2_to_bits(input: &G2Var) -> Result<Vec<Bool>, SynthesisError> {
    let mut x_0 = input.x.c0.to_bits_le()?;
    let mut x_1 = input.x.c1.to_bits_le()?;
    x_0.reverse();
    x_1.reverse();
    let y_bit = input.y_to_bit()?;
    let mut output = Vec::new();
    output.extend_from_slice(&x_0);
    output.extend_from_slice(&x_1);
    output.push(y_bit);
    Ok(output)
}

fn constrain_bool<F: PrimeField>(
    input: &[Option<bool>],
    cs: ConstraintSystemRef<F>,
) -> Result<Vec<Boolean<F>>, SynthesisError> {
    input
        .iter()
        .map(|b| Boolean::new_witness(cs.clone(), || b.get()))
        .collect::<Result<Vec<_>, _>>()
}
