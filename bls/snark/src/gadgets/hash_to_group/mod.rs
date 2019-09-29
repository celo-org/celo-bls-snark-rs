use algebra::{
    Field,
    PrimeField,
    curves::{
        ProjectiveCurve,
        edwards_sw6::{
            EdwardsAffine,
            EdwardsProjective,
            EdwardsParameters,
        },
        models::{
            bls12::Bls12Parameters,
            SWModelParameters,
        }
    }, fields::{
        sw6::Fr as SW6Fr
    }, ModelParameters, Group, BitIterator
};

use r1cs_core::{SynthesisError, LinearCombination};
use r1cs_std::{
    Assignment,
    fields::{
        fp::FpGadget,
        FieldGadget,
    },
    groups::{
        GroupGadget,
        curves::{
            short_weierstrass::bls12::{
                G1Gadget,
                G2Gadget,
            },
            twisted_edwards::edwards_sw6::{
                EdwardsSWGadget,
            }
        },
    },
    alloc::AllocGadget,
    boolean::Boolean,
    bits::{
        ToBitsGadget,
    },
    select::CondSelectGadget,
};
use dpc::{
    gadgets::{
        crh::pedersen::{PedersenCRHGadget, PedersenCRHGadgetParameters},
        prf::blake2s::blake2s_gadget
    }
};
use std::{
    ops::Neg,
    marker::PhantomData
};

use bls_zexe::hash::composite::{CompositeHasher, Window, CRH};
use dpc::gadgets::FixedLengthCRHGadget;
use dpc::crypto_primitives::FixedLengthCRH;
use algebra::curves::sw6::SW6;
use r1cs_std::bits::uint8::UInt8;
use crate::gadgets::y_to_bit::YToBitGadget;
use algebra::curves::bls12_377::{Bls12_377Parameters, G2Projective as Bls12_377G2Projective};
use algebra::curves::bls12_377::g2::Bls12_377G2Parameters;
use r1cs_std::bits::boolean::AllocatedBit;

type CRHGadget = PedersenCRHGadget<EdwardsProjective, SW6Fr, EdwardsSWGadget>;

pub struct HashToGroupGadget {
}

impl HashToGroupGadget {
    pub fn hash_to_group<CS: r1cs_core::ConstraintSystem<SW6Fr>>(
        mut cs: CS,
        message: &[Boolean],
        expected_point_before_cofactor: &G2Gadget<Bls12_377Parameters>,
    ) -> Result<G2Gadget<Bls12_377Parameters>, SynthesisError> {
        let crh_params =
            <CRHGadget as FixedLengthCRHGadget<CRH, SW6Fr>>::ParametersGadget::alloc(
            &mut cs.ns(|| "pedersen parameters"),
            || {
                match CompositeHasher::setup_crh() {
                    Ok(x) => Ok(x),
                    Err(e) => Err(SynthesisError::AssignmentMissing),
                }
            }
        )?;
        let input_bytes: Vec<UInt8> = message.chunks(8).map(|chunk| {
            let mut chunk_padded = chunk.clone().to_vec();
            if chunk_padded.len() < 8 {
                chunk_padded.resize(8, Boolean::constant(false));
            }
            UInt8::from_bits_le(&chunk_padded)
        }).collect();
        let crh_result = <CRHGadget as FixedLengthCRHGadget<CRH, SW6Fr>>::check_evaluation_gadget(
            &mut cs.ns(|| "pedersen evaluation"),
            &crh_params,
            &input_bytes,
        )?;
        let mut crh_bits = crh_result.x.to_bits(
            cs.ns(|| "crh bits"),
        )?;
        let padded_len = (crh_bits.len() + 7)/8;
        crh_bits.resize(padded_len, Boolean::constant(false));
        let mut xof_bits = vec![];
        for i in 0..3 {
            let xof_result = blake2s_gadget(
                cs.ns(|| format!("xof result {}", i)),
                &crh_bits,
            )?;
            let xof_bits_i = xof_result.into_iter().map(|n| n.to_bits_le()).flatten().collect::<Vec<Boolean>>();
            xof_bits.extend_from_slice(&xof_bits_i);
        }
        let c0_bits: Vec<Boolean> = expected_point_before_cofactor.x.c0.to_bits(
            cs.ns(|| "c0 bits")
        )?;
        let c1_bits: Vec<Boolean> = expected_point_before_cofactor.x.c1.to_bits(
            cs.ns(|| "c1 bits")
        )?;
        let greatest_bit = YToBitGadget::<Bls12_377Parameters>::y_to_bit_g2(
            cs.ns(|| "y to bit"),
            &expected_point_before_cofactor,
        )?;

        let mut serialized_bits = vec![];
        serialized_bits.extend_from_slice(&c0_bits);
        serialized_bits.extend_from_slice(&c1_bits);
        serialized_bits.push(greatest_bit);

        serialized_bits.iter().zip(xof_bits[0..(377*2+1)].iter())
            .enumerate()
            .for_each(
                |(i, (a,b))| {
                    cs.enforce(
                        || format!("enforce bit {}", i),
                        |lc| lc + (SW6Fr::one(), CS::one()),
                        |lc| a.lc(CS::one(), SW6Fr::one()),
                        |lc| b.lc(CS::one(), SW6Fr::one()),
                    );
                }
            );

        let generator = Bls12_377G2Projective::prime_subgroup_generator();
        let generator_var =
            G2Gadget::<Bls12_377Parameters>::alloc(cs.ns(|| "generator"), || Ok(generator))?;


        let cofactor_bits = BitIterator::new(Bls12_377G2Parameters::COFACTOR).map(|b| Boolean::constant(b)).collect::<Vec<Boolean>>();
        let mut scaled_point = expected_point_before_cofactor.mul_bits(
            cs.ns(|| "scaled point"),
            &generator_var,
            cofactor_bits.iter(),
        )?;

        scaled_point = scaled_point.sub(
            cs.ns(|| "subtract generator"),
            &generator_var,
        )?;

        Ok(scaled_point)
    }
}

#[cfg(test)]
mod test {
    use rand::SeedableRng;
    use rand_xorshift::XorShiftRng;

    use algebra::{
        curves::{
            bls12_377::{
                G1Projective as Bls12_377G1Projective,
                G2Projective as Bls12_377G2Projective,
                Bls12_377Parameters,
            },
            models::bls12::Bls12Parameters,
            ProjectiveCurve,
        },
        fields::{
            bls12_377::Fr as Bls12_377Fr,
            sw6::Fr as SW6Fr,
            PrimeField,
        },
        UniformRand,
    };
    use r1cs_core::ConstraintSystem;
    use r1cs_std::{
        Assignment,
        groups::{
            curves::short_weierstrass::bls12::G1Gadget,
        },
        fields::FieldGadget,
        test_constraint_system::TestConstraintSystem,
        alloc::AllocGadget,
        boolean::Boolean,
    };

    use super::HashToGroupGadget;
    use r1cs_std::groups::curves::short_weierstrass::bls12::G2Gadget;

    #[test]
    fn test_hash_to_group() {
        let mut cs = TestConstraintSystem::<SW6Fr>::new();

        let generator = Bls12_377G2Projective::prime_subgroup_generator();
        let generator_var = G2Gadget::<Bls12_377Parameters>::alloc(
            &mut cs.ns(|| "alloc"),
            || Ok(generator),
        ).unwrap();

        let message = [Boolean::constant(true)];

        HashToGroupGadget::hash_to_group(
            cs.ns(|| "hash to group"),
            &message,
            &generator_var,
        ).unwrap();

        println!("number of constraints: {}", cs.num_constraints());
    }
}
