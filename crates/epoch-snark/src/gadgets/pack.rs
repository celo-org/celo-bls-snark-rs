use algebra::{
    curves::bls12::Bls12Parameters,
    bls12_377::Parameters as Bls12_377_Parameters,
    BigInteger, 
    FpParameters, 
    PrimeField
};
use bls_gadgets::utils::is_setup;
use r1cs_core::SynthesisError;
use r1cs_std::{fields::fp::FpVar, prelude::*, Assignment};
use tracing::{span, trace, Level};

pub type Bool = Boolean<<Bls12_377_Parameters as Bls12Parameters>::Fp>;
/// Gadget which packs and unpacks boolean constraints in field elements for efficiency
pub struct MultipackGadget;

impl MultipackGadget {
    /// Packs the provided boolean constraints to a vector of field element gadgets of
    /// `element_size` each. If `should_alloc_input` is set to true, then the allocations
    /// will be made as public inputs.
    pub fn pack<F: PrimeField>(
        bits: &[Bool],
        element_size: usize,
        should_alloc_input: bool,
    ) -> Result<Vec<FpVar<Bls12_377_Parameters>>, SynthesisError> {
        let span = span!(Level::TRACE, "multipack_gadget");
        let _enter = span.enter();
        let mut packed = vec![];
        let fp_chunks = bits.chunks(element_size);
        for (i, chunk) in fp_chunks.enumerate() {
            trace!(iteration = i);
            let alloc = if should_alloc_input {
                FpVar::alloc_input
            } else {
                FpVar::alloc
            };
            let fp = alloc(|| {
                if is_setup(&chunk) {
                    return Err(SynthesisError::AssignmentMissing);
                }
                let fp_val = Bls12_377_Parameters::BigInt::from_bits(
                    &chunk
                        .iter()
                        .map(|x| x.get_value().get())
                        .collect::<Result<Vec<bool>, _>>()?,
                );
                Ok(Bls12_377_Parameters::from_repr(fp_val).get()?)
            })?;
            let fp_bits = fp.to_bits()?;
            let chunk_len = chunk.len();
            for j in 0..chunk_len {
                fp_bits[Bls12_377_Parameters::Params::MODULUS_BITS as usize - chunk_len + j]
                    .enforce_equal(&chunk[j])?;
            }

            packed.push(fp);
        }
        Ok(packed)
    }

    /// Unpacks the provided field element gadget to a vector of boolean constraints
    #[allow(unused)]
    pub fn unpack(
        packed: &[FpVar<Bls12_377_Parameters>],
        target_bits: usize,
        source_capacity: usize,
    ) -> Result<Vec<Bool>, SynthesisError> {
        let bits_vecs = packed
            .iter()
            .enumerate()
            .map(|(i, x)| x.to_bits())
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
                &bits_vecs[chunk][<Bls12_377_Parameters::Params as FpParameters>::MODULUS_BITS as usize - diff..],
            );
            current_index += diff;
            chunk += 1;
        }
        Ok(bits)
    }
}
