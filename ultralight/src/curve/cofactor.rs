use std::{
    ops::{Mul, Neg, Div},
};

use algebra::{
    biginteger::BigInteger,
    fields::{
        Field,
        Fp2,
        fp6_3over2::Fp6,
        fp12_2over3over2::Fp12,
        BitIterator,
        PrimeField,
        FpParameters,
    },
    curves::{
        AffineCurve,
        ProjectiveCurve,
        models::{
            ModelParameters,
            bls12::{
                Bls12Parameters,
                G2Affine,
                G2Projective,
            }
        }
    }
};

fn twist_omega<P: Bls12Parameters>() -> (Fp12<P::Fp12Params>, Fp12<P::Fp12Params>) {
    let omega2 = Fp12::<P::Fp12Params>::new(
        Fp6::<P::Fp6Params>::new(
            Fp2::<P::Fp2Params>::zero(),
            Fp2::<P::Fp2Params>::one(),
            Fp2::<P::Fp2Params>::zero(),
        ),
        Fp6::<P::Fp6Params>::zero()
    ); //w^2 = u

    let omega3 = Fp12::<P::Fp12Params>::new(
        Fp6::<P::Fp6Params>::zero(),
        Fp6::<P::Fp6Params>::new(
            Fp2::<P::Fp2Params>::zero(),
            Fp2::<P::Fp2Params>::one(),
            Fp2::<P::Fp2Params>::zero(),
        ),
    ); //w^3 = u*v

    (omega2, omega3)
}

pub fn untwist<P: Bls12Parameters>(x: &Fp2<P::Fp2Params>, y: &Fp2<P::Fp2Params>) -> (Fp12<P::Fp12Params>, Fp12<P::Fp12Params>) {
    let (omega2, omega3) = twist_omega::<P>();
    let new_x = Fp12::<P::Fp12Params>::new(
        Fp6::<P::Fp6Params>::new(
            *x,
            Fp2::<P::Fp2Params>::zero(),
            Fp2::<P::Fp2Params>::zero(),
        ),
        Fp6::<P::Fp6Params>::zero(),
    ) * &omega2;

    let new_y = Fp12::<P::Fp12Params>::new(
        Fp6::<P::Fp6Params>::new(
            *y,
            Fp2::<P::Fp2Params>::zero(),
            Fp2::<P::Fp2Params>::zero(),
        ),
        Fp6::<P::Fp6Params>::zero(),
    ) * &omega3;

    (new_x, new_y)
}

pub fn twist<P: Bls12Parameters>(x: &Fp12<P::Fp12Params>, y: &Fp12<P::Fp12Params>) -> (Fp2<P::Fp2Params>, Fp2<P::Fp2Params>) {
    let (omega2, omega3) = twist_omega::<P>();

    let omega2x = x.div(&omega2);
    let omega3y = y.div(&omega3);
    //println!("twist x c0: {}\ntwist y c0: {}\ntwist x c1: {}\ntwist y c1: {}", omega2x.c0, omega3y.c0, omega2x.c1, omega3y.c1);
    (omega2x.c0.c0, omega3y.c0.c0)
}

pub fn psi<P: Bls12Parameters>(p: &G2Projective<P>, power: usize) -> G2Projective<P> {
    let p = p.into_affine();
    let (mut untwisted_x, mut untwisted_y) = untwist::<P>(&p.x, &p.y);
    untwisted_x.frobenius_map(power);
    untwisted_y.frobenius_map(power);
    let (twisted_x, twisted_y) = twist::<P>(&untwisted_x, &untwisted_y);
    G2Affine::<P>::new(twisted_x, twisted_y, false).into_projective()
}

fn curve_X<P: Bls12Parameters>() -> <P::G2Parameters as ModelParameters>::ScalarField {
    let X_bits : Vec<bool> = BitIterator::new(P::X).collect();
    let X = <<P::G2Parameters as ModelParameters>::ScalarField as PrimeField>::BigInt::from_bits(&X_bits);

    <P::G2Parameters as ModelParameters>::ScalarField::from_repr(X)
}

fn curve_r_modulus<P: Bls12Parameters>() -> <P::G2Parameters as ModelParameters>::ScalarField {
    let X_bits : Vec<bool> = BitIterator::new(<<P::G2Parameters as ModelParameters>::ScalarField as PrimeField>::Params::MODULUS).collect();
    let X = <<P::G2Parameters as ModelParameters>::ScalarField as PrimeField>::BigInt::from_bits(&X_bits);

    <P::G2Parameters as ModelParameters>::ScalarField::from_repr(X)
}

pub fn scale_by_cofactor_scott<P: Bls12Parameters>(p: &G2Projective<P>) -> G2Projective<P> {
    //println!("p: {}", p);

    let X = curve_X::<P>();

    let one = <P::G2Parameters as ModelParameters>::ScalarField::one();
    let p1 = p.mul(&X); //x
    let p15 = p1 - &p; //x-1
    let p2 = p1.mul(&(X - &one)); //x^2-x
    let p3 = p2.neg() + &p15; //-x^2+2x-1
    let p4 = (p.neg() + &p2).mul(&X); //x^3-x^2-x
    let p5 = p4 + &p; //x^3-x^2-x+1
    let p6 = p4 + &p.double().double(); //x^3-x^2-x+4

    p6 + &psi::<P>(&p5, 1) + &psi::<P>(&p3, 2)
}

pub fn scale_by_cofactor_fuentes<P: Bls12Parameters>(p: &G2Projective<P>) -> G2Projective<P> {
    //println!("p: {}", p);

    let X = curve_X::<P>();

    let one = <P::G2Parameters as ModelParameters>::ScalarField::one();
    let p1 = p.mul(&X); //x
    let p2 = p1 - &p; //x-1
    let p3 = p2.mul(&(X + &one)); //x^2-1
    let p4 = p3 - &p1; //x^2-x-1
    let p5 = p.double(); //2

    p4 + &psi::<P>(&p2, 1) + &psi::<P>(&p5, 2)
}

#[cfg(test)]
mod test {
    use rand::{Rng, SeedableRng, XorShiftRng};
    use std::{
        str::FromStr,
        ops::Mul
    };

    use super::{scale_by_cofactor_scott, scale_by_cofactor_fuentes, psi, curve_X, curve_r_modulus};

    use algebra::{
        fields::{
            Field,
            bls12_377::Fr
        },
        curves::{
            ProjectiveCurve,
            models::{
                SWModelParameters,
                bls12::{
                    Bls12Parameters,
                },
            },
            bls12_377::{
                Bls12_377,
                Bls12_377Parameters,
                G2Affine,
                G2Projective,
            }
        }
    };

    #[test]
    fn test_twist_untwist() {
        let mut rng = XorShiftRng::from_seed([0x5dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

        let p: G2Projective = rng.gen();
        assert_eq!(psi::<Bls12_377Parameters>(&p, 0), p);
    }

    #[test]
    fn test_scale_by_cofactor_scott() {
        let mut rng = XorShiftRng::from_seed([0x5dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

        for _i in 0..5 {
            let p: G2Projective = rng.gen();
            let scott_cofactor = scale_by_cofactor_scott::<Bls12_377Parameters>(&p);

            let three = Fr::from_str("3").unwrap();
            let naive_cofactor = p.into_affine().scale_by_cofactor() * &three;
            assert_eq!(naive_cofactor, scott_cofactor);
            let modulus = curve_r_modulus::<Bls12_377Parameters>();
            assert!(scott_cofactor.mul(&modulus).is_zero());
        }
    }

    #[test]
    fn test_scale_by_cofactor_fuentes() {
        let mut rng = XorShiftRng::from_seed([0x5dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);
        let X = curve_X::<Bls12_377Parameters>();

        for _i in 0..5 {
            let p: G2Projective = rng.gen();
            let fuentes_cofactor = scale_by_cofactor_fuentes::<Bls12_377Parameters>(&p);

            let three = Fr::from_str("3").unwrap();
            let px2 = p.mul(&X).mul(&X);
            let p = px2 - &p;
            let naive_cofactor = p.into_affine().scale_by_cofactor() * &three;
            assert_eq!(naive_cofactor, fuentes_cofactor);
            let modulus = curve_r_modulus::<Bls12_377Parameters>();
            assert!(fuentes_cofactor.mul(&modulus).is_zero());
        }
    }

}
