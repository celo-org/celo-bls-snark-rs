use algebra::{
    curves::bls12::Bls12Parameters,
    bls12_377::{Parameters as Bls12_377_Parameters, FqParameters},
    FpParameters, 
    PrimeField
};
use algebra_core::biginteger::BigInteger;
use bls_gadgets::utils::is_setup;
use r1cs_core::{ConstraintSystemRef, SynthesisError};
use r1cs_std::{Assignment, fields::fp::FpVar, prelude::*};
use tracing::{span, trace, Level};

type Bool = Boolean<<Bls12_377_Parameters as Bls12Parameters>::Fp>;
type Fp = FpVar<<Bls12_377_Parameters as Bls12Parameters>::Fp>;
/// Gadget which packs and unpacks boolean constraints in field elements for efficiency
pub struct MultipackGadget;

impl MultipackGadget {
    /// Packs the provided boolean constraints to a vector of field element gadgets of
    /// `element_size` each. If `should_alloc_input` is set to true, then the allocations
    /// will be made as public inputs.
    pub fn pack<F: PrimeField, Fp: FpParameters>(
        bits: &[Boolean<F>],
        element_size: usize,
        should_alloc_input: bool,
    ) -> Result<Vec<FpVar<F>>, SynthesisError> {
        let span = span!(Level::TRACE, "multipack_gadget");
        let _enter = span.enter();
        let mut packed = vec![];
        let fp_chunks = bits.chunks(element_size);
        for (i, chunk) in fp_chunks.enumerate() {
            trace!(iteration = i);
            let alloc = if should_alloc_input {
                FpVar::<F>::new_input
            } else {
                FpVar::<F>::new_witness
            };
            let fp = alloc(bits.cs().unwrap_or(ConstraintSystemRef::None),
            || {
                if is_setup(&chunk) {
                    return Err(SynthesisError::AssignmentMissing);
                }
                let fp_val = F::BigInt::from_bits(
                    &chunk
                        .iter()
                        .map(|x| x.value())
                        .collect::<Result<Vec<bool>, _>>()?,
                );
                Ok(F::from_repr(fp_val).get()?)
            })?;
            let mut fp_bits = fp.to_bits_le()?;
            fp_bits.reverse();
            let chunk_len = chunk.len();
            for j in 0..chunk_len {
                fp_bits[Fp::MODULUS_BITS as usize - chunk_len + j]
                    .enforce_equal(&chunk[j])?;
            }

            packed.push(fp);
        }
        Ok(packed)
    }

/*    /// Unpacks the provided field element gadget to a vector of boolean constraints
    #[allow(unused)]
    pub fn unpack(
        packed: &[Fp],
        target_bits: usize,
        source_capacity: usize,
    ) -> Result<Vec<Bool>, SynthesisError> {
        let bits_vecs = packed
            .iter()
            .enumerate()
            .map(|(i, x)| x.to_bits_le())
            .collect::<Result<Vec<_>, _>>()?;
        let mut bits = vec![];
        let mut chunk = 0;
        let mut current_index = 0;
        while current_index < target_bits {
            let diff = if (target_bits - current_index) < source_capacity as usize {
                target_bits - current_index
            } else {
                source_capacity as usize
            };
            bits.extend_from_slice(
                &bits_vecs[chunk][<FqParameters as FpParameters>::MODULUS_BITS as usize - diff..],
            );
            current_index += diff;
            chunk += 1;
        }
        Ok(bits)
    }*/
}
