use bench_utils::{end_timer, start_timer};
use hex;
use log::trace;
use std::marker::PhantomData;

use super::HashToCurve;
use crate::hashers::{
    composite::{CompositeHasher, COMPOSITE_HASHER, CRH},
    DirectHasher, XOF,
};
use crate::BLSError;

use algebra::{
    bls12_377::Parameters,
    curves::models::short_weierstrass_jacobian::{GroupAffine, GroupProjective},
    curves::models::{bls12::Bls12Parameters, SWModelParameters},
    fields::{Field, SquareRootField},
    Zero,
};

use algebra::CanonicalDeserialize;
use algebra::ConstantSerializedSize;

use once_cell::sync::Lazy;

const NUM_TRIES: u16 = 65535;
const LAST_BYTE_MASK: u8 = 1;
const GREATEST_MASK: u8 = 2;

/// Composite Try-and-Increment hasher for BLS 12-377.
pub static COMPOSITE_HASH_TO_G1: Lazy<
    TryAndIncrement<CompositeHasher<CRH>, <Parameters as Bls12Parameters>::G1Parameters>,
> = Lazy::new(|| TryAndIncrement::new(&*COMPOSITE_HASHER));

pub static DIRECT_HASH_TO_G1: Lazy<
    TryAndIncrement<DirectHasher, <Parameters as Bls12Parameters>::G1Parameters>,
> = Lazy::new(|| TryAndIncrement::new(&DirectHasher));

/// A try-and-increment method for hashing to G1 and G2. See page 521 in
/// https://link.springer.com/content/pdf/10.1007/3-540-45682-1_30.pdf.
#[derive(Clone)]
pub struct TryAndIncrement<'a, H, P> {
    hasher: &'a H,
    curve_params: PhantomData<P>,
}

impl<'a, H, P> TryAndIncrement<'a, H, P>
where
    H: XOF<Error = BLSError>,
    P: SWModelParameters,
{
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
    P: SWModelParameters,
{
    type Output = GroupProjective<P>;

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
    P: SWModelParameters,
{
    /// Hash with attempt takes the input, appends a counter
    pub fn hash_with_attempt(
        &self,
        domain: &[u8],
        message: &[u8],
        extra_data: &[u8],
    ) -> Result<(GroupProjective<P>, usize), BLSError> {
        let num_bytes = GroupAffine::<P>::SERIALIZED_SIZE; // 48 or 96
        let hash_loop_time = start_timer!(|| "try_and_increment::hash_loop");

        for c in 0..NUM_TRIES {
            // concatenate the message with the counter
            let msg = &[&c.to_le_bytes(), extra_data, &message].concat();

            // produce a hash with sufficient length
            let mut candidate_hash = self.hasher.hash(domain, msg, num_bytes)?;

            // get the greatest flag by comparing the last bit with the greatest mask
            let greatest = (candidate_hash[num_bytes - 1] & GREATEST_MASK) == GREATEST_MASK;
            // apply the mask to the last byte
            let candidate_x = &mut candidate_hash[..num_bytes];
            candidate_x[num_bytes - 1] &= LAST_BYTE_MASK;

            // Try to read an element
            let possible_x = P::BaseField::deserialize(&mut candidate_x.as_ref())?;
            if possible_x == P::BaseField::zero() {
                continue;
            }

            if let Some(x) = get_point_from_x::<P>(possible_x, greatest) {
                trace!(
                    "succeeded hashing \"{}\" to curve in {} tries",
                    hex::encode(message),
                    c
                );
                end_timer!(hash_loop_time);

                let scaled = x.scale_by_cofactor();
                if scaled.is_zero() {
                    continue;
                }

                return Ok((scaled, c as usize));
            }
        }
        Err(BLSError::HashToCurveError)
    }
}

/// computes y = sqrt(x^3+ax+b) and returns the corresponding group element
pub fn get_point_from_x<P: SWModelParameters>(
    x: P::BaseField,
    greatest: bool,
) -> Option<GroupAffine<P>> {
    // Compute x^3 + ax + b
    let x3b = P::add_b(&((x.square() * &x) + &P::mul_by_a(&x)));

    x3b.sqrt().map(|y| {
        let negy = -y;

        let y = if (y < negy) ^ greatest { y } else { negy };
        GroupAffine::<P>::new(x, y, false)
    })
}

#[cfg(test)]
mod test {
    use super::*;
    use rand::RngCore;

    #[test]
    fn hash_to_curve_direct_g1() {
        let h = DirectHasher;
        hash_to_curve_test::<<Parameters as Bls12Parameters>::G1Parameters, _>(h)
    }

    #[test]
    fn hash_to_curve_direct_g2() {
        let h = DirectHasher;
        hash_to_curve_test::<<Parameters as Bls12Parameters>::G2Parameters, _>(h)
    }

    #[test]
    fn hash_to_curve_composite_g1() {
        let h = CompositeHasher::<CRH>::new().unwrap();
        hash_to_curve_test::<<Parameters as Bls12Parameters>::G1Parameters, _>(h)
    }

    #[test]
    fn hash_to_curve_composite_g2() {
        let h = CompositeHasher::<CRH>::new().unwrap();
        hash_to_curve_test::<<Parameters as Bls12Parameters>::G2Parameters, _>(h)
    }

    fn hash_to_curve_test<P: SWModelParameters, X: XOF<Error = BLSError>>(h: X) {
        let hasher = TryAndIncrement::<X, P>::new(&h);
        let mut rng = rand::thread_rng();
        for length in &[10, 25, 50, 100, 200, 300] {
            let mut input = vec![0; *length];
            rng.fill_bytes(&mut input);
            hasher.hash(&[], &input, &[]).unwrap();
        }
    }
}
