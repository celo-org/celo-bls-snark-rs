use failure::Error;
use crate::{
    hash::PRF,
    curve::{
        hash::HashToG2
    },
};
use byteorder::{
    LittleEndian,
    WriteBytesExt
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

fn get_point_from_x<P: Bls12Parameters>(x: <P::G2Parameters as ModelParameters>::BaseField, greatest: bool) -> Option<G2Affine<P>> {
    // Compute x^3 + ax + b
    let x3b = <P::G2Parameters as SWModelParameters>::add_b(&((x.square() * &x) + &<P::G2Parameters as SWModelParameters>::mul_by_a(&x)));

    x3b.sqrt().map(|y| {
        let negy = -y;

        let y = if (y < negy) ^ greatest { y } else { negy };
        G2Affine::<P>::new(x, y, false)
    })
}
impl<'a, H: PRF> HashToG2 for TryAndIncrement<'a, H> {
    fn hash<P: Bls12Parameters>(&self, message: &[u8]) -> Result<G2Projective<P>, Error> {
        const NUM_TRIES: usize = 10000;

        let num_bits = 2*(<P::Fp as PrimeField>::Params::MODULUS_BITS as usize) + 64; //2*Fq + 64, generate 2 field elements and 64 extra bits to remove bias
        let message_hash = self.hasher.crh(message)?;
        let mut counter: [u8; 4] = [0; 4];
        for c in 1..NUM_TRIES {
            println!("try {}", c);
            (&mut counter[..]).write_u32::<LittleEndian>(c as u32)?;
            let hash = self.hasher.prf(&[&counter, message_hash.as_slice()].concat(), num_bits)?;
            let possible_x: Fp2::<P::Fp2Params> = FromBytes::read(hash.as_slice())?;
            match get_point_from_x::<P>(possible_x, true) {
                None => continue,
                Some(x) => return Ok(x.into_projective()),
            }
        }
        Err(HashToCurveError::CannotFindPoint)?
    }
}

#[cfg(test)]
mod test {

    use crate::{
        hash::{
            PRF,
            composite::CompositeHasher,
        },
        curve::{
            hash::{
                HashToG2,
                try_and_increment::{
                    TryAndIncrement,
                },
            },
        },
    };

    use algebra::curves::{
        bls12_377::{
            Bls12_377Parameters,
            G2Projective,
        },
    };

    #[test]
    fn test_hash_to_curve() {
        let composite_hasher = CompositeHasher::new().unwrap();
        let try_and_increment = TryAndIncrement::new(&composite_hasher);
        let _g: G2Projective = try_and_increment.hash::<Bls12_377Parameters>(&[]).unwrap();
    }
}
