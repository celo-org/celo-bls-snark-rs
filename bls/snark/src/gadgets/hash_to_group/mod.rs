use algebra::{BigInteger, Field, curves::{
    ProjectiveCurve,
    edwards_sw6::{
        EdwardsProjective,
    },
    models::{
        SWModelParameters,
    }
}, fields::{
    sw6::Fr as SW6Fr,
    bls12_377::Fr as Bls12_377Fr,
    bls12_377::Fq as Bls12_377Fp,
    bls12_377::Fq2 as Bls12_377Fp2,
    bls12_377::Fq6 as Bls12_377Fp6,
    bls12_377::Fq12 as Bls12_377Fp12,
}, BitIterator, PrimeField, AffineCurve, Group, Fp2Parameters};
use r1cs_core::{SynthesisError, ConstraintSystem};
use r1cs_std::{
    Assignment,
    groups::{
        GroupGadget,
        curves::{
            short_weierstrass::bls12::{
                G2Gadget,
            },
            twisted_edwards::edwards_sw6::{
                EdwardsSWGadget,
            }
        },
    },
    fields::{
        FieldGadget,
        bls12_377::{
            Fq2Gadget as Fp2Gadget,
            Fq6Gadget as Fp6Gadget,
            Fq12Gadget as Fp12Gadget
        }
    },
    alloc::AllocGadget,
    boolean::Boolean,
    bits::{
        ToBitsGadget,
    },
};
use crypto_primitives::{
    FixedLengthCRHGadget,
    crh::bowe_hopwood::constraints::{BoweHopwoodPedersenCRHGadget},
    prf::blake2s::constraints::blake2s_gadget,
};

use bls_zexe::{
    curve::hash::try_and_increment::get_point_from_x,
    hash::composite::{CompositeHasher, CRH},
};
use r1cs_std::bits::uint8::UInt8;
use crate::gadgets::y_to_bit::YToBitGadget;
use algebra::curves::bls12_377::{
    Bls12_377Parameters,
    G2Projective as Bls12_377G2Projective,
    g2::Bls12_377G2Parameters,
};
use algebra::fields::models::fp6_3over2::Fp6Parameters;
use algebra::fields::models::fp12_2over3over2::Fp12Parameters;
use algebra::curves::models::bls12::Bls12Parameters;

type CRHGadget = BoweHopwoodPedersenCRHGadget<EdwardsProjective, SW6Fr, EdwardsSWGadget>;

pub struct HashToGroupGadget {
}

impl HashToGroupGadget {
    pub fn hash_to_group<CS: r1cs_core::ConstraintSystem<SW6Fr>>(
        mut cs: CS,
        message: &[Boolean],
    ) -> Result<G2Gadget<Bls12_377Parameters>, SynthesisError> {
        let crh_params =
            <CRHGadget as FixedLengthCRHGadget<CRH, SW6Fr>>::ParametersGadget::alloc(
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

        let expected_point_before_cofactor = G2Gadget::<Bls12_377Parameters>::alloc(
            cs.ns(|| "expected point before cofactor"),
            || {
                let c0_bits = xof_bits[..377].iter().map(|x| x.get_value().get().unwrap()).collect::<Vec<bool>>();
                let c0_big = <Bls12_377Fp as PrimeField>::BigInt::from_bits(&c0_bits);
                let c0 = Bls12_377Fp::from_repr(c0_big);
                let c1_bits = xof_bits[377..377*2].iter().map(|x| x.get_value().get().unwrap()).collect::<Vec<bool>>();
                let c1_big = <Bls12_377Fp as PrimeField>::BigInt::from_bits(&c1_bits);
                let c1 = Bls12_377Fp::from_repr(c1_big);
                let x = Bls12_377Fp2::new(c0, c1);
                let greatest = xof_bits[377*2].get_value().get().unwrap();
                let p = get_point_from_x::<Bls12_377Parameters>(x, greatest).unwrap();
                Ok(p.into_projective())
            }
        )?;

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
                        |_| a.lc(CS::one(), SW6Fr::one()),
                        |_| b.lc(CS::one(), SW6Fr::one()),
                    );
                }
            );

        let scaled_point = Self::scale_by_cofactor_fuentes(cs.ns(|| "scale by cofactor"), &expected_point_before_cofactor)?;

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
            bls12_377::{
                Fq as Bls12_377Fp,
                Fr as Bls12_377Fr,
            },
            sw6::Fr as SW6Fr,
            PrimeField,
        },
        UniformRand,
    };
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

    #[test]
    fn test_hash_to_group() {
        let mut cs = TestConstraintSystem::<SW6Fr>::new();

        let message = [Boolean::constant(true)];

        HashToGroupGadget::hash_to_group(
            cs.ns(|| "hash to group"),
            &message,
        ).unwrap();

        println!("number of constraints: {}", cs.num_constraints());
        assert!(cs.is_satisfied());
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
