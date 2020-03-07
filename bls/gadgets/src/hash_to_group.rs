use std::{borrow::Borrow, marker::PhantomData};

use algebra::curves::models::bls12::Bls12Parameters;
use algebra::{
    curves::{bls12::G1Projective, short_weierstrass_jacobian::GroupProjective, SWModelParameters},
    AffineCurve, BigInteger, BitIterator, One, PrimeField, ProjectiveCurve,
};
use crypto_primitives::prf::{
    blake2s::constraints::blake2s_gadget_with_parameters, Blake2sWithParameterBlock,
};

use r1cs_core::{ConstraintSystem, SynthesisError};
use r1cs_std::{
    alloc::AllocGadget, bits::ToBitsGadget, boolean::Boolean, groups::bls12::G1Gadget,
    groups::GroupGadget, Assignment,
};

use crate::YToBitGadget;
use bls_zexe::curve::hash::try_and_increment::get_point_from_x_g1;

/// Hash to curve requires 378 bits (377 for field element, 1 for y)
///
/// Parameters for Blake2x as specified in: https://blake2.net/blake2x.pdf
/// • “Key length” is set to 0 (even if the root hash was keyed)
/// • “Fanout” is set to 0 (unlimited)
/// • “Maximal depth” is set to 0
/// • “Leaf maximal byte length” is set to 32 for BLAKE2Xs, and 64 for BLAKE2Xb
/// • “XOF digest length” is set to the length of the final output digest
/// • “Node depth” is set to 0 (leaves)
/// • “Inner hash byte length” is set to 32 for BLAKE2Xs and 64 for BLAKE2Xb
fn blake2xs_params(
    hash_length: u16,
    offset: u32,
    personalization: [u8; 8],
) -> Blake2sWithParameterBlock {
    Blake2sWithParameterBlock {
        digest_length: 32,
        key_length: 0,
        fan_out: 0,
        depth: 0,
        leaf_length: 32,
        node_offset: offset,
        xof_digest_length: hash_length / 8, // need to convert to bits
        node_depth: 0,
        inner_length: 32,
        salt: [0; 8],
        personalization,
    }
}

pub struct HashToBitsGadget;

impl HashToBitsGadget {
    /// Hashes the message to produce a `hash_length` hash with the provided personalization
    pub fn hash_to_bits<P: Bls12Parameters, F: PrimeField, CS: ConstraintSystem<F>>(
        mut cs: CS,
        message: &[Boolean],
        hash_length: u16,
        personalization: [u8; 8],
    ) -> Result<Vec<Boolean>, SynthesisError> {
        // Reverse the message to LE
        let mut message = message.to_vec();
        message.reverse();

        // Blake2 outputs 256 bit hashes
        let iterations = hash_length / 256;
        let mut xof_bits = Vec::new();
        // Run Blake on the message N times, each time offset by `i`
        // to get a `hash_length` hash. The hash is in LE.
        for i in 0..iterations {
            // calculate the hash
            let blake2s_parameters = blake2xs_params(hash_length, i.into(), personalization);
            let xof_result = blake2s_gadget_with_parameters(
                cs.ns(|| format!("xof result {}", i)),
                &message,
                &blake2s_parameters.parameters(),
            )?;
            // convert hash result to LE bits
            let xof_bits_i = xof_result
                .into_iter()
                .map(|n| n.to_bits_le())
                .flatten()
                .collect::<Vec<Boolean>>();
            xof_bits.extend_from_slice(&xof_bits_i);
        }

        // TODO: Should we re-arrange the chunks?
        // let xof_bits = [
        //     &xof_bits[..<F::Params as FpParameters>::MODULUS_BITS as usize],
        //     &[xof_bits[<F::Params as FpParameters>::MODULUS_BITS as usize]][..],
        // ]
        // .concat();

        Ok(xof_bits)
    }
}

pub struct HashToGroupGadget<P> {
    parameters_type: PhantomData<P>,
}

impl<P: Bls12Parameters> HashToGroupGadget<P> {
    // Receives the output of `HashToBitsGadget::hash_to_bits` in Little Endian
    // decodes the G1 point and then multiplies it by the curve's cofactor to
    // get the hash
    pub fn hash_to_group<CS: ConstraintSystem<P::Fp>>(
        mut cs: CS,
        xof_bits: &[Boolean],
    ) -> Result<G1Gadget<P>, SynthesisError> {
        // if we're in setup mode, just return an error
        if xof_bits.iter().any(|x| x.get_value().is_none()) {
            return Err(SynthesisError::AssignmentMissing);
        }

        let x_bits = &xof_bits[..377];
        let greatest = xof_bits[377];

        let expected_point_before_cofactor =
            G1Gadget::<P>::alloc(cs.ns(|| "expected point before cofactor"), || {
                // get the bits from the Boolean constraints
                // we assume that these are already encoded as LE
                let mut bits = x_bits
                    .iter()
                    .map(|x| x.get_value().get())
                    .collect::<Result<Vec<bool>, _>>()?;

                // `BigInt::from_bits` takes BigEndian representations so we need to
                // reverse them since they are read in LE
                bits.reverse();
                let big = <P::Fp as PrimeField>::BigInt::from_bits(&bits);
                let x = P::Fp::from_repr(big);
                let greatest = greatest.get_value().get()?;

                // Converts the point read from the xof bits to a G1 element
                // with point decompression
                // TODO: Figure out why this fails here.
                let p = get_point_from_x_g1::<P>(x, greatest).unwrap();
                // .ok_or(SynthesisError::AssignmentMissing)?;

                Ok(p.into_projective())
            })?;

        // Point compression on the G1 Gadget
        let compressed_point: Vec<Boolean> = {
            // Convert x to LE
            let mut bits: Vec<Boolean> =
                expected_point_before_cofactor.x.to_bits(cs.ns(|| "bits"))?;
            bits.reverse();

            // Get a constraint about the y point's sign
            let greatest_bit = YToBitGadget::<P>::y_to_bit_g1(
                cs.ns(|| "y to bit"),
                &expected_point_before_cofactor,
            )?;

            // return the x point plus the greatest bit constraint
            bits.push(greatest_bit);

            bits
        };

        compressed_point
            .iter()
            .zip(xof_bits.iter())
            .enumerate()
            .for_each(|(i, (a, b))| {
                cs.enforce(
                    || format!("enforce bit {}", i),
                    |lc| lc + (P::Fp::one(), CS::one()),
                    |_| a.lc(CS::one(), P::Fp::one()),
                    |_| b.lc(CS::one(), P::Fp::one()),
                );
            });

        let scaled_point = Self::scale_by_cofactor_g1(
            cs.ns(|| "scale by cofactor"),
            &expected_point_before_cofactor,
        )?;

        Ok(scaled_point)
    }

    fn scale_by_cofactor_g1<CS: r1cs_core::ConstraintSystem<P::Fp>>(
        mut cs: CS,
        p: &G1Gadget<P>,
    ) -> Result<G1Gadget<P>, SynthesisError>
    where
        G1Projective<P>: Borrow<GroupProjective<P::G1Parameters>>,
    {
        // get the cofactor's bits
        let mut x_bits = BitIterator::new(P::G1Parameters::COFACTOR)
            .map(|b| Boolean::constant(b))
            .collect::<Vec<Boolean>>();

        // Zexe's mul_bits requires that inputs _MUST_ be in LE form, so we have to reverse
        x_bits.reverse();

        // return p * cofactor - [g]_1
        let generator = G1Gadget::<P>::alloc(cs.ns(|| "generator"), || {
            Ok(G1Projective::<P>::prime_subgroup_generator())
        })?;
        let scaled = p
            .mul_bits(cs.ns(|| "scaled"), &generator, x_bits.iter())?
            .sub(cs.ns(|| "scaled finalize"), &generator)?;
        Ok(scaled)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use algebra::{bls12_377, ProjectiveCurve};
    use r1cs_std::{
        boolean::Boolean, groups::GroupGadget, test_constraint_system::TestConstraintSystem,
    };

    use bls_zexe::{
        bls::keys::SIG_DOMAIN,
        curve::hash::try_and_increment::TryAndIncrement,
        hash::composite::CompositeHasher,
    };

    use crypto_primitives::FixedLengthCRHGadget;
    use bls_zexe::hash::composite::CRH;
    use r1cs_std::edwards_sw6::EdwardsSWGadget;
    use algebra::edwards_sw6::EdwardsProjective;
    use algebra::edwards_sw6::Fq as Fr;
    use r1cs_std::bits::uint8::UInt8;
    use crypto_primitives::crh::bowe_hopwood::constraints::BoweHopwoodPedersenCRHGadget;

    type CRHGadget = BoweHopwoodPedersenCRHGadget<EdwardsProjective, Fr, EdwardsSWGadget>;

    #[test]
    fn test_hash_to_group() {
        let composite_hasher = CompositeHasher::new().unwrap();
        let try_and_increment = TryAndIncrement::new(&composite_hasher);
        let expected_hash_with_attempt = try_and_increment
            .hash_with_attempt::<bls12_377::Parameters>(SIG_DOMAIN, &[0xFF], &[])
            .unwrap();

        let (expected_hash, attempt) = (expected_hash_with_attempt.0.into_affine(), expected_hash_with_attempt.1);
        assert_eq!(attempt, 0);
            
        let message = [
            // The counter is 0

            // bit representation of 0xFE (11111110)
            Boolean::constant(true),
            Boolean::constant(true),
            Boolean::constant(true),
            Boolean::constant(true),
            Boolean::constant(true),
            Boolean::constant(true),
            Boolean::constant(true),
            Boolean::constant(true),
            Boolean::constant(false),
            Boolean::constant(false),
            Boolean::constant(false),
            Boolean::constant(false),
            Boolean::constant(false),
            Boolean::constant(false),
            Boolean::constant(false),
            Boolean::constant(false),
        ];

        let mut cs = TestConstraintSystem::<bls12_377::Fq>::new();

        let input_bytes: Vec<UInt8> = message.into_iter().map(|b| b.clone()).rev().collect::<Vec<_>>().chunks(8).map(|chunk| {
                let mut chunk_padded = chunk.clone().to_vec();
                if chunk_padded.len() < 8 {
                    chunk_padded.resize(8, Boolean::constant(false));
                }
                UInt8::from_bits_le(&chunk_padded)
            }).collect();

        let crh_params =
        <CRHGadget as FixedLengthCRHGadget<CRH, Fr>>::ParametersGadget::alloc(
            &mut cs.ns(|| "pedersen parameters"),
            || {
                match CompositeHasher::setup_crh() {
                    Ok(x) => Ok(x),
                    Err(e) => {
                        println!("error: {}", e);
                        Err(SynthesisError::AssignmentMissing)
                    },
                }
            }
        ).unwrap();

        let crh_result = <CRHGadget as FixedLengthCRHGadget<CRH, Fr>>::check_evaluation_gadget(
            &mut cs.ns(|| "pedersen evaluation"),
            &crh_params,
            &input_bytes,
        ).unwrap();

        let crh_bits = crh_result.x.to_bits(
            cs.ns(|| "crh bits"),
        ).unwrap();

        let crh_bits_len = crh_bits.len();
        let crh_bits_len_rounded = ((crh_bits_len + 7) / 8) * 8;

        let mut first_bits = crh_bits[0..8 - (crh_bits_len_rounded - crh_bits_len)].to_vec();
        first_bits.reverse();
        let mut crh_bits = crh_bits[8 - (crh_bits_len_rounded - crh_bits_len)..].to_vec();

        crh_bits.reverse();
        crh_bits.extend_from_slice(&first_bits);
        for _ in 0..(crh_bits_len_rounded - crh_bits_len) {
            crh_bits.push(Boolean::constant(false));
        }

        let crh_bits = crh_bits.iter().rev().map(|b| b.clone()).collect::<Vec<_>>();

        let mut personalization = [0; 8];
        personalization.copy_from_slice(SIG_DOMAIN);
        let xof_bits = HashToBitsGadget::hash_to_bits::<bls12_377::Parameters, _, _>(
            cs.ns(|| "hash to bits"),
            &crh_bits,
            512,
            personalization,
        )
        .unwrap();
        assert_eq!(xof_bits.len(), 512);

        let hash = HashToGroupGadget::<bls12_377::Parameters>::hash_to_group(
            cs.ns(|| "hash to group"),
            //xof_bits.into_iter().map(|x| x.clone()).rev().collect::<Vec<_>>().as_slice(),
            &xof_bits,
        )
        .unwrap();

        assert!(cs.is_satisfied());
        assert_eq!(expected_hash, hash.get_value().unwrap().into_affine());
    }
}
