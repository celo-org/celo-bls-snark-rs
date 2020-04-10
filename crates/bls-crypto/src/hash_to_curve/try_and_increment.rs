use bench_utils::{end_timer, start_timer};
use byteorder::WriteBytesExt;
use hex;
use log::trace;
use std::marker::PhantomData;

use super::{cofactor::scale_by_cofactor_g1, HashToCurve};
use crate::hashers::{
    composite::{CompositeHasher, COMPOSITE_HASHER, CRH},
    DirectHasher, XOF,
};
use crate::BLSError;

use algebra::{
    bls12_377::Parameters,
    bytes::FromBytes,
    curves::{
        models::{
            bls12::{Bls12Parameters, G1Affine, G1Projective},
            ModelParameters, SWModelParameters,
        },
        AffineCurve,
    },
    fields::{Field, FpParameters, PrimeField, SquareRootField},
    Zero,
};

use once_cell::sync::Lazy;

/// Composite Try-and-Increment hasher for BLS 12-377.
pub static COMPOSITE_HASH_TO_G1: Lazy<TryAndIncrement<CompositeHasher<CRH>, Parameters>> =
    Lazy::new(|| TryAndIncrement::new(&*COMPOSITE_HASHER));

pub static DIRECT_HASH_TO_G1: Lazy<TryAndIncrement<DirectHasher, Parameters>> =
    Lazy::new(|| TryAndIncrement::new(&DirectHasher));

/// A try-and-increment method for hashing to G1 and G2. See page 521 in
/// https://link.springer.com/content/pdf/10.1007/3-540-45682-1_30.pdf.
#[derive(Clone)]
pub struct TryAndIncrement<'a, H: XOF, P: Bls12Parameters> {
    hasher: &'a H,
    curve_params: PhantomData<P>,
}

impl<'a, H: XOF, P: Bls12Parameters> TryAndIncrement<'a, H, P> {
    /// Instantiates a new Try-and-increment hasher with the provided hashing method
    /// and curve parameters based on the type
    pub fn new(h: &'a H) -> Self {
        TryAndIncrement {
            hasher: h,
            curve_params: PhantomData,
        }
    }
}

impl<'a, H, P> HashToCurve for TryAndIncrement<'a, H, P>
where
    H: XOF<Error = BLSError>,
    P: Bls12Parameters,
{
    type Output = G1Projective<P>;

    fn hash(
        &self,
        domain: &[u8],
        message: &[u8],
        extra_data: &[u8],
    ) -> Result<Self::Output, BLSError> {
        self.hash_with_attempt(domain, message, extra_data)
            .map(|res| res.0)
    }
}

impl<'a, H, P> TryAndIncrement<'a, H, P>
where
    H: XOF<Error = BLSError>,
    P: Bls12Parameters,
{
    pub fn hash_with_attempt(
        &self,
        domain: &[u8],
        message: &[u8],
        extra_data: &[u8],
    ) -> Result<(G1Projective<P>, usize), BLSError> {
        const NUM_TRIES: usize = 256;
        const EXPECTED_TOTAL_BITS: usize = 512;
        const LAST_BYTE_MASK: u8 = 1;
        const GREATEST_MASK: u8 = 2;

        let fp_bits =
            (((<P::Fp as PrimeField>::Params::MODULUS_BITS as f64) / 8.0).ceil() as usize) * 8;
        let num_bits = fp_bits;
        let num_bytes = num_bits / 8;

        //round up to a multiple of 8
        let hash_fp_bits =
            (((<P::Fp as PrimeField>::Params::MODULUS_BITS as f64) / 256.0).ceil() as usize) * 256;
        let hash_num_bits = hash_fp_bits;
        assert_eq!(hash_num_bits, EXPECTED_TOTAL_BITS);
        let hash_num_bytes = hash_num_bits / 8;
        let mut counter: [u8; 1] = [0; 1];
        let hash_loop_time = start_timer!(|| "try_and_increment::hash_loop");
        for c in 0..NUM_TRIES {
            (&mut counter[..]).write_u8(c as u8)?;
            let hash = self.hasher.hash(
                domain,
                &[&counter, extra_data, &message].concat(),
                hash_num_bytes,
            )?;
            let (possible_x, greatest) = {
                //zero out the last byte except the first bit, to get to a total of 377 bits
                let mut possible_x_bytes = hash[..num_bytes].to_vec();
                let possible_x_bytes_len = possible_x_bytes.len();
                let greatest =
                    (possible_x_bytes[possible_x_bytes_len - 1] & GREATEST_MASK) == GREATEST_MASK;
                possible_x_bytes[possible_x_bytes_len - 1] &= LAST_BYTE_MASK;
                let possible_x = P::Fp::read(possible_x_bytes.as_slice())?;
                if possible_x == P::Fp::zero() {
                    continue;
                }

                (possible_x, greatest)
            };
            match get_point_from_x_g1::<P>(possible_x, greatest) {
                None => continue,
                Some(x) => {
                    trace!(
                        "succeeded hashing \"{}\" to G1 in {} tries",
                        hex::encode(message),
                        c
                    );
                    end_timer!(hash_loop_time);
                    let scaled = scale_by_cofactor_g1::<P>(&x.into_projective());
                    if scaled.is_zero() {
                        continue;
                    }
                    return Ok((scaled, c));
                }
            }
        }
        Err(BLSError::HashToCurveError)
    }
}

pub fn get_point_from_x_g1<P: Bls12Parameters>(
    x: <P::G1Parameters as ModelParameters>::BaseField,
    greatest: bool,
) -> Option<G1Affine<P>> {
    // Compute x^3 + ax + b
    let x3b = <P::G1Parameters as SWModelParameters>::add_b(
        &((x.square() * &x) + &<P::G1Parameters as SWModelParameters>::mul_by_a(&x)),
    );

    x3b.sqrt().map(|y| {
        let negy = -y;

        let y = if (y < negy) ^ greatest { y } else { negy };
        G1Affine::<P>::new(x, y, false)
    })
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_hash_to_curve() {
        let try_and_increment = &*COMPOSITE_HASH_TO_G1;
        try_and_increment.hash(&[], &[], &[]).unwrap();
    }
}
