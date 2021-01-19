/// Implementation of the `MapToGroup` algorithm (Paragraph
/// 3.3) of [this paper](https://link.springer.com/content/pdf/10.1007/3-540-45682-1_30.pdf)
///
/// This method involves hashing the data along with a counter. If the hash can then be interpreted
/// as an elliptic curve point, it returns. If not, it increments the counter and tries again.
///
/// **This algorithm is not constant time**.
///
/// # Examples
///
/// Hashing the data requires instantiating a hasher, importing the `HashToCurve` trait
/// and calling the `hash` function
///
/// ```rust
/// use bls_crypto::{OUT_DOMAIN, hash_to_curve::{HashToCurve, try_and_increment::DIRECT_HASH_TO_G1}};
///
/// // Instantiate the lazily evaluated hasher to BLS 12-377.
/// let hasher = &*DIRECT_HASH_TO_G1;
///
/// // Hash the data. The domain must be exactly 8 bytes.
/// let hash = hasher.hash(OUT_DOMAIN, &b"some_data"[..], &b"extra"[..]).expect("should not fail");
/// ```
///
/// Doing this manually requires importing the curves and instantiating the hashers as follows:
///
/// ```rust
/// use ark_bls12_377::g1::Parameters;
/// use bls_crypto::{
///     OUT_DOMAIN,
///     hashers::composite::{CompositeHasher, CRH}, // We'll use the Composite Hasher
///     hash_to_curve::{HashToCurve, try_and_increment::TryAndIncrement},
/// };
///
/// let composite_hasher = CompositeHasher::<CRH>::new().unwrap();
/// let hasher = TryAndIncrement::<_, Parameters>::new(&composite_hasher);
///
/// // hash the data as before
/// let hash = hasher.hash(OUT_DOMAIN, &b"some_data"[..], &b"extra"[..]).expect("should not fail");
///
/// // You can also use the underlying struct's method to get the counter
/// let (hash, counter) = hasher.hash_with_attempt(OUT_DOMAIN, &b"some_data"[..], &b"extra"[..]).expect("should not fail");
/// assert_eq!(counter, 3);
/// ```
pub mod try_and_increment;
pub mod try_and_increment_cip22;
use crate::BLSError;
use ark_ec::models::{short_weierstrass_jacobian::GroupAffine, SWModelParameters};
use ark_ff::{Field, Zero};
use ark_serialize::Flags;

/// Trait for hashing arbitrary data to a group element on an elliptic curve
pub trait HashToCurve {
    /// The type of the curve being used.
    type Output;

    /// Given a domain separator, a message and potentially some extra data, produces
    /// a hash of them which is a curve point.
    fn hash(
        &self,
        domain: &[u8],
        message: &[u8],
        extra_data: &[u8],
    ) -> Result<Self::Output, BLSError>;
}

/// Given `n` bytes, it returns the value rounded to the nearest multiple of 256 bits (in bytes)
/// e.g. 1. given 48 = 384 bits, it will return 64 bytes (= 512 bits)
///      2. given 96 = 768 bits, it will return 96 bytes (no rounding needed since 768 is already a
///         multiple of 256)
pub fn hash_length(n: usize) -> usize {
    let bits = (n * 8) as f64 / 256.0;
    let rounded_bits = bits.ceil() * 256.0;
    rounded_bits as usize / 8
}

/// The bool signifies whether this is also an infinity point representation
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum YSignFlags {
    PositiveY(bool),
    NegativeY(bool),
}

impl YSignFlags {
    #[inline]
    pub fn from_y_sign(is_positive: bool) -> Self {
        if is_positive {
            YSignFlags::PositiveY(false)
        } else {
            YSignFlags::NegativeY(false)
        }
    }

    #[inline]
    pub fn is_infinity(&self) -> bool {
        matches!(
            self,
            YSignFlags::PositiveY(true) | YSignFlags::NegativeY(true)
        )
    }

    #[inline]
    pub fn is_positive(&self) -> Option<bool> {
        match self {
            YSignFlags::PositiveY(_) => Some(true),
            YSignFlags::NegativeY(_) => Some(false),
        }
    }
}

impl Default for YSignFlags {
    #[inline]
    fn default() -> Self {
        // NegativeY doesn't change the serialization
        YSignFlags::NegativeY(false)
    }
}

impl Flags for YSignFlags {
    const BIT_SIZE: usize = 2;

    #[inline]
    fn u8_bitmask(&self) -> u8 {
        let mut mask = 0;
        match self {
            YSignFlags::PositiveY(true) | YSignFlags::NegativeY(true) => mask |= 1 << 6,
            _ => (),
        }
        match self {
            YSignFlags::PositiveY(false) | YSignFlags::PositiveY(true) => mask |= 1 << 7,
            _ => (),
        }
        mask
    }

    #[inline]
    fn from_u8(value: u8) -> Option<Self> {
        let x_sign = (value >> 7) & 1 == 1;
        let is_infinity = (value >> 6) & 1 == 1;
        match x_sign {
            true => Some(YSignFlags::PositiveY(is_infinity)),
            false => Some(YSignFlags::NegativeY(is_infinity)),
        }
    }
}

pub fn from_random_bytes<P: SWModelParameters>(bytes: &[u8]) -> Option<GroupAffine<P>> {
    P::BaseField::from_random_bytes_with_flags::<YSignFlags>(bytes).and_then(|(x, flags)| {
        if x.is_zero() && flags.is_infinity() {
            Some(GroupAffine::<P>::zero())
        } else if let Some(y_is_positve) = flags.is_positive() {
            GroupAffine::<P>::get_point_from_x(x, y_is_positve) // Unwrap is safe because it's not zero.
        } else {
            None
        }
    })
}

#[cfg(test)]
mod test {

    use super::*;
    use crate::hash_to_curve::try_and_increment::TryAndIncrement;
    use crate::hashers::{
        composite::{CompositeHasher, CRH},
        DirectHasher, Hasher,
    };
    use ark_bls12_377::Parameters;
    use ark_ec::{
        bls12::Bls12Parameters, models::SWModelParameters,
        short_weierstrass_jacobian::GroupProjective, ProjectiveCurve,
    };
    use ark_serialize::CanonicalSerialize;
    use rand::{Rng, RngCore};

    #[test]
    fn test_hash_length() {
        assert_eq!(hash_length(48), 64);
        assert_eq!(hash_length(96), 96);
    }

    #[test]
    fn hash_to_curve_direct_g1() {
        let h = DirectHasher;
        hash_to_curve_test::<<Parameters as Bls12Parameters>::G1Parameters, _>(h)
    }

    #[test]
    fn hash_to_curve_composite_g1() {
        let h = CompositeHasher::<CRH>::new().unwrap();
        hash_to_curve_test::<<Parameters as Bls12Parameters>::G1Parameters, _>(h)
    }

    #[test]
    fn hash_to_curve_direct_g2() {
        let h = DirectHasher;
        hash_to_curve_test::<<Parameters as Bls12Parameters>::G2Parameters, _>(h)
    }

    #[test]
    fn hash_to_curve_composite_g2() {
        let h = CompositeHasher::<CRH>::new().unwrap();
        hash_to_curve_test::<<Parameters as Bls12Parameters>::G2Parameters, _>(h)
    }

    fn hash_to_curve_test<P: SWModelParameters, X: Hasher<Error = BLSError>>(h: X) {
        let hasher = TryAndIncrement::<X, P>::new(&h);
        let mut rng = rand::thread_rng();
        for length in &[10, 25, 50, 100, 200, 300] {
            let mut input = vec![0; *length];
            rng.fill_bytes(&mut input);
            let _ = hasher.hash(&b"domain"[..], &input, &b"extra"[..]).unwrap();
        }
    }

    pub fn generate_test_data<R: Rng>(rng: &mut R) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let msg_size: u8 = rng.gen();
        let mut msg: Vec<u8> = vec![0; msg_size as usize];
        for i in msg.iter_mut() {
            *i = rng.gen();
        }

        let mut domain = vec![0u8; 8];
        for i in domain.iter_mut() {
            *i = rng.gen();
        }

        let extra_data_size: u8 = rng.gen();
        let mut extra_data: Vec<u8> = vec![0; extra_data_size as usize];
        for i in extra_data.iter_mut() {
            *i = rng.gen();
        }

        (domain, msg, extra_data)
    }

    pub fn test_hash_to_group<P: SWModelParameters, H: HashToCurve<Output = GroupProjective<P>>>(
        hasher: &H,
        rng: &mut impl Rng,
        expected_hashes: Vec<Vec<u8>>,
    ) {
        for expected_hash in expected_hashes.into_iter() {
            let (domain, msg, extra_data) = generate_test_data(rng);
            let g = hasher.hash(&domain, &msg, &extra_data).unwrap();
            let mut bytes = vec![];
            g.into_affine().serialize(&mut bytes).unwrap();
            assert_eq!(expected_hash, bytes);
        }
    }

    #[allow(dead_code)]
    pub fn test_hash_to_group_cip22<
        P: SWModelParameters,
        H: HashToCurve<Output = GroupProjective<P>>,
    >(
        hasher: &H,
        rng: &mut impl Rng,
        expected_hashes: Vec<Vec<u8>>,
    ) {
        for expected_hash in expected_hashes.into_iter() {
            let (domain, msg, extra_data) = generate_test_data(rng);
            let g = hasher.hash(&domain, &msg, &extra_data).unwrap();
            let mut bytes = vec![];
            g.into_affine().serialize(&mut bytes).unwrap();
            assert_eq!(expected_hash, bytes);
        }
    }
}

#[cfg(all(test, feature = "compat"))]
mod compat_tests {
    #![allow(clippy::op_ref)]
    use super::*;
    use crate::hash_to_curve::try_and_increment::TryAndIncrement;
    use crate::hash_to_curve::try_and_increment_cip22::TryAndIncrementCIP22;
    use crate::hashers::{composite::COMPOSITE_HASHER, Hasher};
    use ark_bls12_377::Parameters;
    use ark_ec::{
        bls12::{Bls12Parameters, G1Affine, G1Projective},
        models::SWModelParameters,
        ModelParameters, ProjectiveCurve,
    };
    use ark_ff::{Field, FpParameters, FromBytes, PrimeField, SquareRootField, Zero};
    use ark_serialize::CanonicalSerialize;
    use bench_utils::{end_timer, start_timer};
    use byteorder::WriteBytesExt;
    use log::trace;
    use rand::SeedableRng;
    use rand_xorshift::XorShiftRng;

    const RNG_SEED: [u8; 16] = [
        0x5d, 0xbe, 0x62, 0x59, 0x8d, 0x31, 0x3d, 0x76, 0x32, 0x37, 0xdb, 0x17, 0xe5, 0xbc, 0x06,
        0x54,
    ];

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

    fn compat_hasher<P: Bls12Parameters>(
        domain: &[u8],
        message: &[u8],
        extra_data: &[u8],
    ) -> Result<(G1Projective<P>, usize), BLSError> {
        const NUM_TRIES: usize = 256;
        const EXPECTED_TOTAL_BITS: usize = 512;
        const LAST_BYTE_MASK: u8 = 1;
        const GREATEST_MASK: u8 = 2;

        let hasher = &*COMPOSITE_HASHER;

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
            let hash = hasher.hash(
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
                let possible_x = P::Fp::read(possible_x_bytes.as_slice());
                if possible_x.is_err() {
                    continue;
                }

                (possible_x.unwrap(), greatest)
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
                    let scaled = x.scale_by_cofactor();
                    if scaled.is_zero() {
                        continue;
                    }
                    return Ok((scaled, c));
                }
            }
        }
        Err(BLSError::HashToCurveError)
    }

    fn generate_compat_expected_hashes(num_expected_hashes: usize) -> Vec<Vec<u8>> {
        let mut rng = XorShiftRng::from_seed(RNG_SEED);

        let mut expected_hashes = vec![];
        for _ in 0..num_expected_hashes {
            let (domain, msg, extra_data) = super::test::generate_test_data(&mut rng);
            let expected_hash_point = compat_hasher::<Parameters>(&domain, &msg, &extra_data)
                .unwrap()
                .0;

            let mut expected_hash = vec![];
            expected_hash_point
                .into_affine()
                .serialize(&mut expected_hash)
                .unwrap();
            expected_hashes.push(expected_hash);
        }

        expected_hashes
    }

    #[test]
    fn test_hash_to_curve_g1() {
        let mut rng = XorShiftRng::from_seed(RNG_SEED);
        let expected_hashes = generate_compat_expected_hashes(1000);

        let hasher = TryAndIncrement::<_, <Parameters as Bls12Parameters>::G1Parameters>::new(
            &*COMPOSITE_HASHER,
        );
        super::test::test_hash_to_group(&hasher, &mut rng, expected_hashes)
    }

    /// Tests against hashes that were generated from commit 67aa80c1ce5ac5a4e2fe3377ba8b869e982a4f96,
    /// the version deployed before the Donut hardfork.
    #[test]
    fn test_hash_to_curve_g1_test_vectors() {
        let mut rng = XorShiftRng::from_seed(RNG_SEED);
        let expected_hashes = vec![
            "a7e17c99126acf78536e64fffe88e1032d834b483584fe5757b1deafa493c97a132572c7825ca4f617f6bcef93b93980",
            "21e328cfedb263f8c815131cc42f0357ab0ba903d855a11de6e7bcd7e61375a818d1b093bcf9fce224536714efad5c00",
            "fcc8bc80a528b32762ad3b3f72d40b069083b833ad4b6e135040414e2634657e1cf1ec070235ba1425f350df8c585d01",
            "9b99c3cee5f7c486f962b1391b4108cd464b05bc24b2e488e9aa04f848467315ed70d83d3abfa63150564ad0c549c400",
            "9df1b6ba0e8d2a42866d78a90b5fdf56cea80b2ec588774ceb7cc4f414d7b49ca55f81169535a4c3a4c7c39148af3e01",
            "f365f54ba587b863d5d5ecef6a2932f4eb225c0cd2c4e727c3fa5b1a30fbcfa8e2a2e0d7a68476ee10d90b3b8846b480",
            "1cb6008bca08b85df6f9a87ca141533145ed88abb0bbace96f4b1ca42d15ba888d4948c21548207a0abd22d5c234d180",
            "1c529f631ddaffde7cbe62bbb8d48cc8dbe59b8548dc69b156d0568c7aae898d8051a3ef31ad17c60a85ad82203a9b81",
            "de54da7a8813a30c267d662d428e28520a159b51a9e226ceb663d460d9065b66a9586cb8b3a9ba0ef0e27c626f20dc80",
            "b68e1db4b648801676a79ac199eaf003757bf2a96cdbb804bfefe0484afdc0cc299d50d660221d1de374e92c44291280",
        ].into_iter().map(|x| hex::decode(&x).unwrap()).collect::<Vec<_>>();

        let hasher = TryAndIncrement::<_, <Parameters as Bls12Parameters>::G1Parameters>::new(
            &*COMPOSITE_HASHER,
        );
        super::test::test_hash_to_group(&hasher, &mut rng, expected_hashes)
    }

    /// Tests expected hashes after the Donut hardfork.
    #[test]
    fn test_hash_to_curve_g1_test_vectors_cip22() {
        let mut rng = XorShiftRng::from_seed(RNG_SEED);
        let expected_hashes = vec![
            "c24b44bf3aef0949a25f614a89fd20e457b89e4c5d63923b7a63748443275ad47210e7fb8eff38d5582e7d301ee1d400",
            "30caf0778a1d5a30f53c42cc58bbf0b0b9ec0c969e01d805b47f0d556025dbd395af2a506cc6fda3c41e361290c76d01",
            "d9a4b28b8159977581a16ccfa69d1e93b220ccfeafa90a391cbc93c5beedd89953a8df8dcd99be80620fba1b5a191281",
            "e9a2f008d68a446bed6580a7fea89fcce8a9d71d4e876b9929f3813e46f2000f2dc2b26a52c538198469a920cff15201",
            "3d5c112c90df69a5034eaa1dafb067b2091f5f2696206b91cdcf36158497c7bd53e8adae87fff795307497d45dfa9900",
            "c3e18aa19af6c99621b6954e08f786708427a1c87beca919775ae25e5da4599050a95ef12ef74b1f0b6ea512503c6800",
            "241d9d821c503e48bfc2c93a5b59567f235a173a8c3648cb79292993c955c4eee02cba05dd5007b2400c9c251b64fb00",
            "ab7a89228341fce8deb3d86ff0bb9611b1baf2a1d9d0b64710f42cfe6a7c4f789a36308c3fb70e41630396a2c7aa2601",
            "161e32f9621de279b2e3572d5e07c17c33f5e9bf7a532a382e16c2a323a624799f2b187212d12d8eb5fb3032695f0480",
            "acbb3071d0899488ba69ce1592f49c20dada7598690f8393cca80d4abeca0dc6dec112c70228328d68f8f34d3795d100",
        ].into_iter().map(|x| hex::decode(&x).unwrap()).collect::<Vec<_>>();

        let hasher = TryAndIncrementCIP22::<_, <Parameters as Bls12Parameters>::G1Parameters>::new(
            &*COMPOSITE_HASHER,
        );
        super::test::test_hash_to_group_cip22(&hasher, &mut rng, expected_hashes)
    }
}

#[cfg(all(test, not(feature = "compat")))]
mod non_compat_tests {
    use crate::hash_to_curve::try_and_increment::TryAndIncrement;
    use crate::hash_to_curve::try_and_increment::COMPOSITE_HASH_TO_G1;
    use crate::hashers::composite::COMPOSITE_HASHER;
    use ark_bls12_377::Parameters;
    use ark_ec::models::bls12::Bls12Parameters;
    use rand::SeedableRng;
    use rand_xorshift::XorShiftRng;

    #[test]
    fn test_hash_to_curve_g1() {
        let mut rng = XorShiftRng::from_seed([
            0x5d, 0xbe, 0x62, 0x59, 0x8d, 0x31, 0x3d, 0x76, 0x32, 0x37, 0xdb, 0x17, 0xe5, 0xbc,
            0x06, 0x54,
        ]);
        let expected_hashes = vec![
            "a7e17c99126acf78536e64fffe88e1032d834b483584fe5757b1deafa493c97a132572c7825ca4f617f6bcef93b93980",
            "21e328cfedb263f8c815131cc42f0357ab0ba903d855a11de6e7bcd7e61375a818d1b093bcf9fce224536714efad5c80",
            "fcc8bc80a528b32762ad3b3f72d40b069083b833ad4b6e135040414e2634657e1cf1ec070235ba1425f350df8c585d81",
            "9b99c3cee5f7c486f962b1391b4108cd464b05bc24b2e488e9aa04f848467315ed70d83d3abfa63150564ad0c549c480",
            "9df1b6ba0e8d2a42866d78a90b5fdf56cea80b2ec588774ceb7cc4f414d7b49ca55f81169535a4c3a4c7c39148af3e81",
            "f365f54ba587b863d5d5ecef6a2932f4eb225c0cd2c4e727c3fa5b1a30fbcfa8e2a2e0d7a68476ee10d90b3b8846b400",
            "1cb6008bca08b85df6f9a87ca141533145ed88abb0bbace96f4b1ca42d15ba888d4948c21548207a0abd22d5c234d180",
            "1c529f631ddaffde7cbe62bbb8d48cc8dbe59b8548dc69b156d0568c7aae898d8051a3ef31ad17c60a85ad82203a9b81",
            "de54da7a8813a30c267d662d428e28520a159b51a9e226ceb663d460d9065b66a9586cb8b3a9ba0ef0e27c626f20dc00",
            "b68e1db4b648801676a79ac199eaf003757bf2a96cdbb804bfefe0484afdc0cc299d50d660221d1de374e92c44291200",
        ].into_iter().map(|x| hex::decode(&x).unwrap()).collect::<Vec<_>>();

        super::test::test_hash_to_group(&*COMPOSITE_HASH_TO_G1, &mut rng, expected_hashes)
    }

    #[test]
    fn test_hash_to_curve_g2() {
        let mut rng = XorShiftRng::from_seed([
            0x5d, 0xbe, 0x62, 0x59, 0x8d, 0x31, 0x3d, 0x76, 0x32, 0x37, 0xdb, 0x17, 0xe5, 0xbc,
            0x06, 0x54,
        ]);

        let expected_hashes = vec![
            "9c76f364d39ce5747f475088f459a11cb32d39033245c039104dfe88a71047ea078d6f15ed9fc64539410167ffe1800020ec8138f9f8b03c675f4ff33d621c76f41784bf994aa8cf53b2e11961f4c77caaab6681dc29bb2f90e14ecd05a5f500",
            "ffb0b3275d2188bee71e0f626b2bc422ee4ce23692e6d329e085ec74413410cedd354d9571e9de149a286dc48ba83d012ad171f4280acbc3c3d946086fe2a0c9f56d271f0c9bb13e78774cb6244b2e84c24116d8ff76311cf2f76db741ab7200",
            "59af04e977ac914d077d1488639b90dfb5b723bf8516157b9ebc8b584a0f507f20c3b758284fe3c91bc93df86244a9017e06d3f930163642a3c85965aac19ea8a18b0bd08d7bd44e99e343acfe24f98ff6f2401432187a07dd97320f73fa7300",
            "5a1610b23a5a5be0ee255fcc766d0f6d384b3d51b4364d5587102e8905b7233fd5b274973451cb56ca69a945832c1000d0b2744278ffdf5cd33f11bcc4ecc5759b0d5b90f54d454909d73f49c1226e428acfb25995d83ba44826adb8158f1281",
            "d82143317b1a5b90e633a4a208129edd526f9137b9c47221c827aa6317be94cb1bc006ba8afce455be5bf51ee6f184011c535bee7ab3e954731a6a96edb3ea9a6c1d02916817147355a2406757023e27fb2f58fec61f37ddb6125c797bfa5780",
            "48bfa38e3c4a6a7de2a5c4b8c57671c7b1bfb2c225d89786cbcd065b2b7844b910b5cbfc334eff1956bc7245127d970154c38985b770d11994c20072a053f0f720028615753c9c42372580782dd49653b4c0fee2a8e88de1697678a505ffc980",
            "ddc0e29af05439bcb5157802afd9a112394fb190e0dda7b5c7852693da3b3403c911751c24b28af1d05e76326d1117007f14cc765d5c3e73adbbcf7a1d59cf58186d7b576d3e58ccafd2ea527bf31651f4b0d0ba44ee5b54ec6c86c2e1bf1b01",
            "ddc865ffe876a3e19c1401f784eaf88b50c4f04cfaadf7690173a33385cb5af899189478cdbc1abbe8d8a89768e411003a5000c7866f3a5648d7944e97bcbff87f89cd26045dc15494036ce4ce799de532438576bfe32389269a6e3a4ce98201",
            "8de37ce0a7105c14880d9201f2ac1c724e031904f9c88614fa414ad57f00c89e596fadb4f5151c84f4ea04d576931c008fc43faec79d0e300d2192a8e376b25f920f14f467f050e4f2869012fce196e9af5f2041889031e2bbe81c6b3d344480",
            "10341299c41179084a0bfee8b65bac0f48af827daad4f01d3e9925a3b0335736c5d13f44765fecec45941781da5a1000d0bb26a4faa4dc8060b0b2dd0cb6acce7dd10bd081dac7f263b97aec89d6434a55b31a65b3e25f59c40ea92887b03180",
        ].into_iter().map(|x| hex::decode(&x).unwrap()).collect::<Vec<_>>();
        let hasher_g2 = TryAndIncrement::<_, <Parameters as Bls12Parameters>::G2Parameters>::new(
            &*COMPOSITE_HASHER,
        );
        super::test::test_hash_to_group(&hasher_g2, &mut rng, expected_hashes)
    }
}
