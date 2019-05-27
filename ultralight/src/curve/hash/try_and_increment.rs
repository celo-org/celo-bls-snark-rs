use failure::Error;
use crate::{
    hash::PRF,
    curve::{
        self,
        hash::HashToG2
    },
};
use algebra::{
    bytes::{ToBytes, FromBytes},
    biginteger::BigInteger,
    fields::{
        Field, Fp2,
        SquareRootField,
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
            SWModelParameters,
            short_weierstrass_projective::{GroupAffine},
            bls12::{
                Bls12Parameters,
                G2Affine,
                G2Projective,
            }
        }
    },
    PairingEngine,
};

pub struct TryAndIncrement<'a, H: PRF> {
    hasher: &'a H,
}

impl<'a, H: PRF> TryAndIncrement<'a, H> {
    pub fn new(h: &'a H) -> Self {
        TryAndIncrement::<H> {
            hasher: h,
        }
    }
}

#[derive(Debug, Fail)]
pub enum HashToCurveError {
    #[fail(display = "cannot find point")]
    CannotFindPoint,
}

fn get_point_from_x<P: Bls12Parameters>(x: <P::G2Parameters as ModelParameters>::BaseField, greatest: bool) -> Option<G2Affine::<P>> {
    // Compute x^3 + ax + b
    let x3b = <P::G2Parameters as SWModelParameters>::add_b(&((x.square() * &x) + &<P::G2Parameters as SWModelParameters>::mul_by_a(&x)));

    x3b.sqrt().map(|y| {
        let negy = -y;

        let y = if (y < negy) ^ greatest { y } else { negy };
        G2Affine::<P>::new(x, y, false)
    })
}

impl<'a, H: PRF, P: Bls12Parameters> HashToG2<P> for TryAndIncrement<'a, H> {
    fn hash(&self, message: &[u8]) -> Result<G2Projective::<P>, Error> {
        let num_bits = 2*(<P::Fp as PrimeField>::Params::MODULUS_BITS as usize) + 64; //2*Fq + 64, generate 2 field elements and 64 extra bits to remove bias
        let hash = self.hasher.hash(message, num_bits)?;
        let possible_x: Fp2::<P::Fp2Params> = FromBytes::read(hash.as_slice())?;
        match get_point_from_x::<P>(possible_x, true) {
            None => Err(HashToCurveError::CannotFindPoint)?,
            Some(x) => Ok(x.into_projective())
        }
    }
}
