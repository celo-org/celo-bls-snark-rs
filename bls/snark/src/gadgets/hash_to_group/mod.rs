use algebra::{BigInteger, Field, curves::{
    ProjectiveCurve,
    edwards_sw6::{
        EdwardsProjective,
    },
    edwards_bls12::{
        EdwardsProjective as EdwardsBls,
    },
    models::{
        SWModelParameters,
    }
}, fields::{
    FpParameters,
    sw6::Fr as SW6Fr,
    sw6::FrParameters as SW6FrParameters,
    bls12_377::Fr as Bls12_377Fr,
    bls12_377::FrParameters as Bls12_377FrParameters,
    bls12_377::Fq as Bls12_377Fp,
    bls12_377::Fq2 as Bls12_377Fp2,
    bls12_377::Fq6 as Bls12_377Fp6,
    bls12_377::Fq12 as Bls12_377Fp12,
}, BitIterator, PrimeField, AffineCurve, Group, Fp2Parameters};
use r1cs_core::{SynthesisError, ConstraintSystem};
use r1cs_std::{Assignment, eq::EqGadget, groups::{
    GroupGadget,
    curves::{
        short_weierstrass::bls12::{
            G1Gadget,
            G2Gadget,
        },
        twisted_edwards::edwards_sw6::{
            EdwardsSWGadget,
        },
        twisted_edwards::edwards_bls12::{
            EdwardsBlsGadget,
        },
    },
}, fields::{
    FieldGadget,
    edwards_sw6::FqGadget as EdwardsFqGadget,
    bls12_377::{
        Fq2Gadget as Fp2Gadget,
        Fq6Gadget as Fp6Gadget,
        Fq12Gadget as Fp12Gadget
    }
}, alloc::AllocGadget, boolean::Boolean, bits::{
    ToBitsGadget,
}, ToBytesGadget};
use crypto_primitives::{
    FixedLengthCRHGadget,
    crh::bowe_hopwood::constraints::{BoweHopwoodPedersenCRHGadget},
};

use bls_zexe::{
    curve::hash::try_and_increment::get_point_from_x_g1,
    hash::composite::{CompositeHasher, CRH},
    bls::keys::SIG_DOMAIN,
};
use r1cs_std::bits::uint8::UInt8;
use crate::gadgets::y_to_bit::YToBitGadget;
use algebra::curves::bls12_377::{Bls12_377Parameters, G1Projective as Bls12_377G1Projective, G2Projective as Bls12_377G2Projective, g1::Bls12_377G1Parameters, Bls12_377};
use algebra::fields::models::fp6_3over2::Fp6Parameters;
use algebra::fields::models::fp12_2over3over2::Fp12Parameters;
use algebra::curves::models::bls12::Bls12Parameters;
use crypto_primitives::prf::blake2s::constraints::blake2s_gadget_with_parameters;
use crypto_primitives::prf::Blake2sWithParameterBlock;
use algebra::curves::sw6::SW6;
use r1cs_std::fields::fp::FpGadget;

type CRHGadget = BoweHopwoodPedersenCRHGadget<EdwardsProjective, SW6Fr, EdwardsSWGadget>;

pub struct MultipackGadget {

}

impl MultipackGadget {
    pub fn pack<F: PrimeField, CS: r1cs_core::ConstraintSystem<F>>(
        mut cs: CS,
        bits: &[Boolean],
        target_capacity: usize,
        should_alloc_input: bool,
    ) ->  Result<Vec<FpGadget<F>>, SynthesisError> {
        let mut packed = vec![];
        let fp_chunks = bits.chunks(target_capacity);
        for (i, chunk) in fp_chunks.enumerate() {
            let alloc = if should_alloc_input { FpGadget::<F>::alloc_input } else { FpGadget::<F>::alloc };
            let fp = alloc(cs.ns(|| format!("chunk {}", i)), || {
                if chunk.iter().any(|x| x.get_value().is_none()) {
                    Err(SynthesisError::AssignmentMissing)
                } else {
                    let fp_val = F::BigInt::from_bits(
                        &chunk.iter().map(|x| x.get_value().unwrap()).collect::<Vec<bool>>()
                    );
                    Ok(F::from_repr(fp_val))
                }
            })?;
            let fp_bits = fp.to_bits(
                cs.ns(|| format!("chunk bits {}", i)),
            )?;
            let chunk_len = chunk.len();
            for j in 0..chunk_len {
                fp_bits[F::Params::MODULUS_BITS as usize - chunk_len + j].enforce_equal(
                    cs.ns(|| format!("fp bit {} for chunk {}", j, i)),
                    &chunk[j],
                )?;
            }

            packed.push(fp);
        }
        Ok(packed)
    }

    pub fn unpack<F: PrimeField, CS: r1cs_core::ConstraintSystem<F>>(
        mut cs: CS,
        packed: &[FpGadget<F>],
        target_bits: usize,
        source_capacity: usize,
    ) ->  Result<Vec<Boolean>, SynthesisError> {
        let bits_vecs = packed
            .into_iter()
            .enumerate()
            .map(|(i, x)| {
                x.to_bits(cs.ns(|| format!("elem {} bits", i)))
            })
            .collect::<Vec<_>>();
        let bits_vecs = if bits_vecs.iter().any(|x| x.is_err()) {
            Err(SynthesisError::AssignmentMissing)
        } else {
            Ok(bits_vecs.into_iter().map(|x| x.unwrap().to_vec()).collect::<Vec<_>>())
        }?;
        let mut bits = vec![];
        let mut chunk = 0;
        let mut current_index = 0;
        while current_index < target_bits {
            let diff = if (target_bits - current_index ) < source_capacity as usize {
                target_bits - current_index
            } else {
                source_capacity as usize
            };
            bits.extend_from_slice(&bits_vecs[chunk][<F::Params as FpParameters>::MODULUS_BITS as usize - diff..]);
            current_index += diff;
            chunk += 1;
        }
        Ok(bits)
    }
}

pub type HashToBitsField = Bls12_377Fr;
pub type HashToBitsFieldParameters = SW6FrParameters;

pub struct HashToBitsGadget {
}

impl HashToBitsGadget {
    pub fn hash_to_bits<CS: r1cs_core::ConstraintSystem<HashToBitsField>>(
        mut cs: CS,
        message: &[Boolean],
        source_capacity: usize,
        target_capacity: usize,
    ) -> Result<Vec<Boolean>, SynthesisError> {

        let message = message.into_iter().map(|x| x.clone()).rev().collect::<Vec<_>>();

        let mut xof_bits = vec![];
        let mut personalization = [0; 8];
        personalization.copy_from_slice(SIG_DOMAIN);
        for i in 0..2 {
            let blake2s_parameters = Blake2sWithParameterBlock {
                digest_length: 32,
                key_length: 0,
                fan_out: 0,
                depth: 0,
                leaf_length: 32,
                node_offset: i,
                xof_digest_length: 512/8,
                node_depth: 0,
                inner_length: 32,
                salt: [0; 8],
                personalization: personalization,
            };
            let xof_result = blake2s_gadget_with_parameters(
                cs.ns(|| format!("xof result {}", i)),
                &message,
                &blake2s_parameters.parameters(),
            )?;
            let xof_bits_i = xof_result.into_iter().map(|n| n.to_bits_le()).flatten().collect::<Vec<Boolean>>();
            xof_bits.extend_from_slice(&xof_bits_i);
        }

        let modulus_bit_rounded = (((HashToBitsFieldParameters::MODULUS_BITS + 7)/8)*8) as usize;
        let xof_bits = [
            &xof_bits[..HashToBitsFieldParameters::MODULUS_BITS as usize],
            &[xof_bits[HashToBitsFieldParameters::MODULUS_BITS as usize]][..],
        ].concat();

        Ok(xof_bits)
    }
}

pub struct HashToGroupGadget {

}

impl HashToGroupGadget {
    pub fn hash_to_group<CS: r1cs_core::ConstraintSystem<SW6Fr>>(
        mut cs: CS,
        xof_bits: &[Boolean],
        source_capacity: usize,
    ) -> Result<G1Gadget<Bls12_377Parameters>, SynthesisError> {
        let expected_point_before_cofactor = G1Gadget::<Bls12_377Parameters>::alloc(
            cs.ns(|| "expected point before cofactor"),
            || {
                if xof_bits.iter().any(|x| x.get_value().is_none()) {
                    Err(SynthesisError::AssignmentMissing)
                } else {
                    let mut bits = xof_bits[..377].iter().map(|x| x.get_value().get().unwrap()).collect::<Vec<bool>>();
                    bits.reverse();
                    let big = <Bls12_377Fp as PrimeField>::BigInt::from_bits(&bits);
                    let x = Bls12_377Fp::from_repr(big);
                    let greatest = xof_bits[377].get_value().get().unwrap();
                    let p = get_point_from_x_g1::<Bls12_377Parameters>(x, greatest).unwrap();
                    Ok(p.into_projective())
                }
            }
        )?;

        let mut bits: Vec<Boolean> = expected_point_before_cofactor.x.to_bits(
            cs.ns(|| "bits")
        )?;
        bits.reverse();
        let greatest_bit = YToBitGadget::<Bls12_377Parameters>::y_to_bit_g1(
            cs.ns(|| "y to bit"),
            &expected_point_before_cofactor,
        )?;

        let mut serialized_bits = vec![];
        serialized_bits.extend_from_slice(&bits);
        serialized_bits.push(greatest_bit);

        let calculated_bits = &[&xof_bits[..377], &[xof_bits[377]][..]].concat().to_vec();
        serialized_bits.iter().zip(calculated_bits.iter())
            .enumerate()
            .for_each(
                |(i, (a,b))| {
                    cs.enforce(
                        || format!("enforce bit {}", i),
                        |lc| lc + (SW6Fr::one(), CS::one()),
                        |_| a.lc(CS::one(), SW6Fr::one()),
                        |_| b.lc(CS::one(), SW6Fr::one()),
                    );
                }
            );

        let scaled_point = Self::scale_by_cofactor_g1(cs.ns(|| "scale by cofactor"), &expected_point_before_cofactor)?;

        Ok(scaled_point)
    }

    pub fn psi<CS: r1cs_core::ConstraintSystem<SW6Fr>>(mut cs: CS, p: &G2Gadget<Bls12_377Parameters>, power:usize) -> Result<G2Gadget<Bls12_377Parameters>, SynthesisError> {
        let (omega2, omega3) = {
            (Bls12_377Fp12::new(
                Bls12_377Fp6::new(
                    Bls12_377Fp2::zero(),
                    Bls12_377Fp2::one(),
                    Bls12_377Fp2::zero(),
                ),
                Bls12_377Fp6::zero(),
            ),
             Bls12_377Fp12::new(
                 Bls12_377Fp6::zero(),
                 Bls12_377Fp6::new(
                     Bls12_377Fp2::zero(),
                     Bls12_377Fp2::one(),
                     Bls12_377Fp2::zero(),
                 ),
             ))
        };

        let x = Fp12Gadget::new(
            Fp6Gadget::new(
                Fp2Gadget::new(p.x.c0.clone(), p.x.c1.clone()),
                Fp2Gadget::zero(cs.ns(|| "x zero fp2 1"))?,
                Fp2Gadget::zero(cs.ns(|| "x zero fp2 2"))?,
            ),
            Fp6Gadget::zero(cs.ns(|| "x zero fp6 1"))?,
        );
        let y = Fp12Gadget::new(
            Fp6Gadget::new(
                Fp2Gadget::new(p.y.c0.clone(), p.y.c1.clone()),
                Fp2Gadget::zero(cs.ns(|| "y zero fp2 1"))?,
                Fp2Gadget::zero(cs.ns(|| "y zero fp2 2"))?,
            ),
            Fp6Gadget::zero(cs.ns(|| "y zero fp6 1"))?,
        );

        let mut untwisted_x = x.mul_by_constant(cs.ns(|| "untwist x"), &omega2)?;
        let mut untwisted_y = y.mul_by_constant(cs.ns(|| "untwist y"), &omega3)?;

        let frobenius_fp12 = |mut cs: r1cs_core::Namespace<_, _>, f: &mut Fp12Gadget, power: usize| -> Result<(), SynthesisError> {
            f.c0.c0.c1.mul_by_constant_in_place(cs.ns(|| "c0 c0 c1"), &<<Bls12_377Parameters as Bls12Parameters>::Fp2Params as Fp2Parameters>::FROBENIUS_COEFF_FP2_C1[power % 2])?;
            f.c0.c1.c1.mul_by_constant_in_place(cs.ns(|| "c0 c1 c1"), &<<Bls12_377Parameters as Bls12Parameters>::Fp2Params as Fp2Parameters>::FROBENIUS_COEFF_FP2_C1[power % 2])?;
            f.c0.c2.c1.mul_by_constant_in_place(cs.ns(|| "c0 c2 c1"), &<<Bls12_377Parameters as Bls12Parameters>::Fp2Params as Fp2Parameters>::FROBENIUS_COEFF_FP2_C1[power % 2])?;

            f.c0.c1.mul_by_constant_in_place(cs.ns(|| "c0 c1"), &<<Bls12_377Parameters as Bls12Parameters>::Fp6Params as Fp6Parameters>::FROBENIUS_COEFF_FP6_C1[power % 6])?;
            f.c0.c2.mul_by_constant_in_place(cs.ns(|| "c0 c2"), &<<Bls12_377Parameters as Bls12Parameters>::Fp6Params as Fp6Parameters>::FROBENIUS_COEFF_FP6_C2[power % 6])?;

            f.c1.c0.c1.mul_by_constant_in_place(cs.ns(|| "c1 c0 c1"), &<<Bls12_377Parameters as Bls12Parameters>::Fp2Params as Fp2Parameters>::FROBENIUS_COEFF_FP2_C1[power % 2])?;
            f.c1.c1.c1.mul_by_constant_in_place(cs.ns(|| "c1 c1 c1"), &<<Bls12_377Parameters as Bls12Parameters>::Fp2Params as Fp2Parameters>::FROBENIUS_COEFF_FP2_C1[power % 2])?;
            f.c1.c2.c1.mul_by_constant_in_place(cs.ns(|| "c1 c2 c1"), &<<Bls12_377Parameters as Bls12Parameters>::Fp2Params as Fp2Parameters>::FROBENIUS_COEFF_FP2_C1[power % 2])?;

            f.c1.c1.mul_by_constant_in_place(cs.ns(|| "c1 c1 fp6"), &<<Bls12_377Parameters as Bls12Parameters>::Fp6Params as Fp6Parameters>::FROBENIUS_COEFF_FP6_C1[power % 6])?;
            f.c1.c2.mul_by_constant_in_place(cs.ns(|| "c1 c2 fp6"), &<<Bls12_377Parameters as Bls12Parameters>::Fp6Params as Fp6Parameters>::FROBENIUS_COEFF_FP6_C2[power % 6])?;

            f.c1.c0.mul_by_constant_in_place(cs.ns(|| "c1 c0"), &<<Bls12_377Parameters as Bls12Parameters>::Fp12Params as Fp12Parameters>::FROBENIUS_COEFF_FP12_C1[power % 12])?;
            f.c1.c1.mul_by_constant_in_place(cs.ns(|| "c1 c1"), &<<Bls12_377Parameters as Bls12Parameters>::Fp12Params as Fp12Parameters>::FROBENIUS_COEFF_FP12_C1[power % 12])?;
            f.c1.c2.mul_by_constant_in_place(cs.ns(|| "c1 c2"), &<<Bls12_377Parameters as Bls12Parameters>::Fp12Params as Fp12Parameters>::FROBENIUS_COEFF_FP12_C1[power % 12])?;

            Ok(())
        };

        frobenius_fp12(cs.ns(|| "x frobenius fp12"), &mut untwisted_x, power)?;
        frobenius_fp12(cs.ns(|| "y frobenius fp12"), &mut untwisted_y, power)?;

        let twisted_x = untwisted_x.mul_by_constant(cs.ns(|| "twist x"), &omega2.inverse().ok_or(SynthesisError::UnexpectedIdentity)?)?;
        let twisted_y = untwisted_y.mul_by_constant(cs.ns(|| "twist y"), &omega3.inverse().ok_or(SynthesisError::UnexpectedIdentity)?)?;

        let processed_p = G2Gadget::<Bls12_377Parameters>::new(
            twisted_x.c0.c0,
            twisted_y.c0.c0,
        );
        Ok(processed_p)
    }

    fn scale_by_cofactor_g1<CS: r1cs_core::ConstraintSystem<SW6Fr>>(mut cs: CS, p: &G1Gadget<Bls12_377Parameters>) -> Result<G1Gadget<Bls12_377Parameters>, SynthesisError> {
        let generator = Bls12_377G1Projective::prime_subgroup_generator();
        let generator_var =
            G1Gadget::<Bls12_377Parameters>::alloc(cs.ns(|| "generator"), || Ok(generator))?;
        let mut x_bits = BitIterator::new(Bls12_377G1Parameters::COFACTOR).map(|b| Boolean::constant(b)).collect::<Vec<Boolean>>();
        x_bits.reverse();
        let scaled = p
            .mul_bits(cs.ns(|| "scaled"), &generator_var, x_bits.iter()).unwrap()
            .sub(cs.ns(|| "scaled finalize"), &generator_var).unwrap(); //x
        Ok(scaled)
    }

    fn scale_by_cofactor_fuentes<CS: r1cs_core::ConstraintSystem<SW6Fr>>(mut cs: CS, p: &G2Gadget<Bls12_377Parameters>) -> Result<G2Gadget<Bls12_377Parameters>, SynthesisError> {
        let generator = Bls12_377G2Projective::prime_subgroup_generator();
        let generator_var =
            G2Gadget::<Bls12_377Parameters>::alloc(cs.ns(|| "generator"), || Ok(generator))?;

        let mut x_bits = BitIterator::new(Bls12_377Parameters::X).map(|b| Boolean::constant(b)).collect::<Vec<Boolean>>();
        x_bits.reverse();
        let p1 = p
            .mul_bits(cs.ns(|| "p1"), &generator_var, x_bits.iter()).unwrap()
            .sub(cs.ns(|| "p1 finalize"), &generator_var).unwrap(); //x
        let p2 = p1.sub(cs.ns(|| "p2"), &p).unwrap();
        let mut x_plus_one_bits = BitIterator::new(&[Bls12_377Parameters::X[0] + 1]).map(|b| Boolean::constant(b)).collect::<Vec<Boolean>>();
        x_plus_one_bits.reverse();
        let p1_neg = p1.negate(cs.ns(|| "negate p1")).unwrap();
        let p4 = p2.mul_bits(cs.ns(|| "p3"), &p1_neg, x_plus_one_bits.iter())?; //x^2-1

        let mut p5 = p.clone();
        p5.double_in_place(cs.ns(|| "p double"))?;

        let psi_p5 = Self::psi(cs.ns(|| "psi p5"), &p5, 2)?;
        let psi_p2 = Self::psi(cs.ns(|| "psi p2"), &p2, 1)?;
        let scaled_point = p4
            .add(cs.ns(|| "add psi p4"), &psi_p5)?
            .add(cs.ns(|| "add psi p2"), &psi_p2)?;

        Ok(scaled_point)
    }

}
/*
#[cfg(test)]
mod test {
    use rand::SeedableRng;
    use rand_xorshift::XorShiftRng;

    use algebra::{curves::{
        bls12_377::{
            G1Projective as Bls12_377G1Projective,
            G2Projective as Bls12_377G2Projective,
            Bls12_377Parameters,
        },
        models::bls12::Bls12Parameters,
        ProjectiveCurve,
    }, fields::{
        bls12_377::{
            Fq as Bls12_377Fp,
            Fr as Bls12_377Fr,
        },
        sw6::Fr as SW6Fr,
        sw6::FrParameters as SW6FrParameters,
        PrimeField,
    }, UniformRand, FpParameters};
    use r1cs_core::ConstraintSystem;
    use r1cs_std::{
        Assignment,
        groups::{
            GroupGadget,
            curves::short_weierstrass::bls12::{G1Gadget, G2Gadget},
        },
        fields::FieldGadget,
        test_constraint_system::TestConstraintSystem,
        alloc::AllocGadget,
        boolean::Boolean,
    };

    use super::HashToGroupGadget;
    use bls_zexe::curve::cofactor::scale_by_cofactor_fuentes;
    use bls_zexe::hash::composite::CompositeHasher;
    use bls_zexe::curve::hash::{
        HashToG2,
        try_and_increment::TryAndIncrement
    };
    use bls_zexe::bls::keys::SIG_DOMAIN;
    use crate::gadgets::hash_to_group::{HashToBitsGadget, MultipackGadget};
    use r1cs_std::fields::fp::FpGadget;


    #[test]
    fn test_hash_to_group() {
        let composite_hasher = CompositeHasher::new().unwrap();
        let try_and_increment = TryAndIncrement::new(&composite_hasher);
        let expected_hash = try_and_increment.hash::<Bls12_377Parameters>( SIG_DOMAIN, &[0xFE], &[]).unwrap().into_affine();

        let mut cs = TestConstraintSystem::<SW6Fr>::new();

        let message = [
            Boolean::constant(false),
            Boolean::constant(false),
            Boolean::constant(false),
            Boolean::constant(false),
            Boolean::constant(false),
            Boolean::constant(false),
            Boolean::constant(false),
            Boolean::constant(false),
            Boolean::constant(false),
            Boolean::constant(true),
            Boolean::constant(true),
            Boolean::constant(true),
            Boolean::constant(true),
            Boolean::constant(true),
            Boolean::constant(true),
            Boolean::constant(true),
        ];

        let message_packed = MultipackGadget::pack(
            cs.ns(|| "pack message"),
            &message,
        ).unwrap();

        let xof_bits_packed = HashToBitsGadget::hash_to_bits(
            cs.ns(|| "hash to bits"),
            &message_packed,
            message.len(),
        ).unwrap();

        let packed_for_group = xof_bits_packed.iter().enumerate().map(|(i, x)| {
            let big = x.get_value().unwrap().into_repr();
            let mut big_ints = [0; 6];
            big_ints.copy_from_slice(&big.0);
            let big = <SW6FrParameters as FpParameters>::BigInt::new(big_ints);

            FpGadget::<SW6Fr>::alloc(
                cs.ns(|| format!("alloc fp {}", i)),
                || Ok(SW6Fr::from_repr(big))
            ).unwrap()
        }).collect::<Vec<_>>();

        let hash = HashToGroupGadget::hash_to_group(
            cs.ns(|| "hash to group"),
            xof_bits_packed.as_slice(),
        ).unwrap();

        println!("number of constraints: {}", cs.num_constraints());
        if (!cs.is_satisfied()) {
            println!("{}", cs.which_is_unsatisfied().unwrap());
        }
        assert!(cs.is_satisfied());
        assert_eq!(expected_hash, hash.get_value().unwrap().into_affine());

    }

    #[test]
    fn test_scale_by_cofactor() {
        let rng = &mut XorShiftRng::from_seed([0x5d, 0xbe, 0x62, 0x59, 0x8d, 0x31, 0x3d, 0x76, 0x32, 0x37, 0xdb, 0x17, 0xe5, 0xbc, 0x06, 0x54]);

        let mut cs = TestConstraintSystem::<SW6Fr>::new();

        let p = Bls12_377G2Projective::rand(rng);
        let p_g = G2Gadget::<Bls12_377Parameters>::alloc(
            &mut cs.ns(|| "alloc"),
            || Ok(p),
        ).unwrap();

        let scaled = HashToGroupGadget::scale_by_cofactor_fuentes(
            cs.ns(|| "hash to group"),
            &p_g,
        ).unwrap();

        assert_eq!(scaled.get_value().unwrap(), scale_by_cofactor_fuentes::<Bls12_377Parameters>(&p));

        println!("number of constraints: {}", cs.num_constraints());
        assert!(cs.is_satisfied());
    }
}
*/
