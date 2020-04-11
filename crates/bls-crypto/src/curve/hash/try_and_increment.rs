use crate::{
    curve::{
        cofactor,
        hash::{HashToCurveError, HashToG1, HashToG2},
    },
    hash::XOF,
};
use bench_utils::{end_timer, start_timer};
use byteorder::WriteBytesExt;
use hex;
use log::trace;

use algebra::{
    bytes::FromBytes,
    curves::{
        models::{
            bls12::{Bls12Parameters, G1Affine, G1Projective, G2Affine, G2Projective},
            ModelParameters, SWModelParameters,
        },
        AffineCurve,
    },
    fields::{Field, Fp2, FpParameters, PrimeField, SquareRootField},
};
use algebra::{One, Zero};
use std::error::Error;

#[allow(dead_code)]
fn bytes_to_fp<P: Bls12Parameters>(bytes: &[u8]) -> P::Fp {
    let two = {
        let tmp = P::Fp::one();
        tmp + &tmp
    };
    let mut current_power = P::Fp::one();
    let mut element = P::Fp::zero();
    for i in bytes.iter().rev() {
        let current_byte = *i;
        let mut current_bit = 128;
        for _ in 0..8 {
            match (current_byte & current_bit) == 1 {
                true => {
                    element += &current_power;
                }
                false => {}
            }
            current_power *= &two;
            //debug!("current power: {}, elemenet: {}", current_power, element);
            current_bit = current_bit / 2;
        }
    }

    element
}

/// A try-and-increment method for hashing to G1 and G2. See page 521 in
/// https://link.springer.com/content/pdf/10.1007/3-540-45682-1_30.pdf.
pub struct TryAndIncrement<'a, H: XOF> {
    hasher: &'a H,
}

impl<'a, H: XOF> TryAndIncrement<'a, H> {
    pub fn new(h: &'a H) -> Self {
        TryAndIncrement::<H> { hasher: h }
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

pub fn get_point_from_x<P: Bls12Parameters>(
    x: <P::G2Parameters as ModelParameters>::BaseField,
    greatest: bool,
) -> Option<G2Affine<P>> {
    // Compute x^3 + ax + b
    let x3b = <P::G2Parameters as SWModelParameters>::add_b(
        &((x.square() * &x) + &<P::G2Parameters as SWModelParameters>::mul_by_a(&x)),
    );

    x3b.sqrt().map(|y| {
        let negy = -y;

        let y = if (y < negy) ^ greatest { y } else { negy };
        G2Affine::<P>::new(x, y, false)
    })
}

impl<'a, H: XOF> HashToG1 for TryAndIncrement<'a, H> {
    fn hash<P: Bls12Parameters>(
        &self,
        domain: &[u8],
        message: &[u8],
        extra_data: &[u8],
    ) -> Result<G1Projective<P>, Box<dyn Error>> {
        match self.hash_with_attempt::<P>(domain, message, extra_data) {
            Ok(x) => Ok(x.0),
            Err(e) => Err(e),
        }
    }
}

impl<'a, H: XOF> TryAndIncrement<'a, H> {
    pub fn hash_with_attempt<P: Bls12Parameters>(
        &self,
        domain: &[u8],
        message: &[u8],
        extra_data: &[u8],
    ) -> Result<(G1Projective<P>, usize), Box<dyn Error>> {
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
                    let scaled = cofactor::scale_by_cofactor_g1::<P>(&x.into_projective());
                    if scaled.is_zero() {
                        continue;
                    }
                    return Ok((scaled, c));
                }
            }
        }
        Err(HashToCurveError::CannotFindPoint)?
    }
}

impl<'a, H: XOF> HashToG2 for TryAndIncrement<'a, H> {
    fn hash<P: Bls12Parameters>(
        &self,
        domain: &[u8],
        message: &[u8],
        extra_data: &[u8],
    ) -> Result<G2Projective<P>, Box<dyn Error>> {
        const NUM_TRIES: usize = 256;
        const EXPECTED_TOTAL_BITS: usize = 384 * 2;
        const LAST_BYTE_MASK: u8 = 1;
        const GREATEST_MASK: u8 = 2;

        //round up to a multiple of 8
        let fp_bits =
            (((<P::Fp as PrimeField>::Params::MODULUS_BITS as f64) / 8.0).ceil() as usize) * 8;
        let num_bits = 2 * fp_bits;
        assert_eq!(num_bits, EXPECTED_TOTAL_BITS);
        let num_bytes = num_bits / 8;
        let mut counter: [u8; 1] = [0; 1];
        let hash_loop_time = start_timer!(|| "try_and_increment::hash_loop");
        for c in 0..NUM_TRIES {
            (&mut counter[..]).write_u8(c as u8)?;
            let message_with_counter = &[&counter, extra_data, &message].concat();
            let hash = self.hasher.hash(domain, message_with_counter, num_bytes)?;
            let (possible_x, greatest) = {
                //zero out the last byte except the first bit, to get to a total of 377 bits
                let mut possible_x_0_bytes = (&hash[..hash.len() / 2]).to_vec();
                let possible_x_0_bytes_len = possible_x_0_bytes.len();
                possible_x_0_bytes[possible_x_0_bytes_len - 1] &= LAST_BYTE_MASK;
                let possible_x_0 = P::Fp::read(possible_x_0_bytes.as_slice())?;
                if possible_x_0 == P::Fp::zero() {
                    continue;
                }
                let mut possible_x_1_bytes = (&hash[hash.len() / 2..]).to_vec();
                let possible_x_1_bytes_len = possible_x_1_bytes.len();
                let greatest = (possible_x_1_bytes[possible_x_1_bytes_len - 1] & GREATEST_MASK)
                    == GREATEST_MASK;
                possible_x_1_bytes[possible_x_1_bytes_len - 1] &= LAST_BYTE_MASK;
                let possible_x_1 = P::Fp::read(possible_x_1_bytes.as_slice())?;
                if possible_x_1 == P::Fp::zero() {
                    continue;
                }
                (
                    Fp2::<P::Fp2Params>::new(possible_x_0, possible_x_1),
                    greatest,
                )
            };
            match get_point_from_x::<P>(possible_x, greatest) {
                None => continue,
                Some(x) => {
                    trace!(
                        "succeeded hashing \"{}\" to G2 in {} tries",
                        hex::encode(message),
                        c
                    );
                    end_timer!(hash_loop_time);
                    let scaled = cofactor::scale_by_cofactor_fuentes::<P>(&x.into_projective());
                    if scaled.is_zero() {
                        return Err(HashToCurveError::SmallOrderPoint)?;
                    }
                    return Ok(scaled);
                }
            }
        }
        Err(HashToCurveError::CannotFindPoint)?
    }
}

#[cfg(test)]
mod test {

    use crate::{
        curve::hash::{try_and_increment::TryAndIncrement, HashToG1, HashToG2},
        hash::composite::CompositeHasher,
    };

    use algebra::{
        bls12_377::{G1Projective, G2Projective, Parameters},
        curves::ProjectiveCurve,
        CanonicalSerialize,
    };
    use rand::{Rng, SeedableRng};
    use rand_xorshift::XorShiftRng;

    fn generate_test_data<R: Rng>(rng: &mut R) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
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

    #[test]
    fn test_hash_to_curve_g1() {
        let composite_hasher = CompositeHasher::new().unwrap();
        let try_and_increment = TryAndIncrement::new(&composite_hasher);
        let mut rng = XorShiftRng::from_seed([
            0x5d, 0xbe, 0x62, 0x59, 0x8d, 0x31, 0x3d, 0x76, 0x32, 0x37, 0xdb, 0x17, 0xe5, 0xbc,
            0x06, 0x54,
        ]);
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
        for i in 0..10 {
            let (domain, msg, extra_data) = generate_test_data(&mut rng);
            let g: G1Projective = <TryAndIncrement<_> as HashToG1>::hash::<Parameters>(
                &try_and_increment,
                &domain,
                &msg,
                &extra_data,
            )
            .unwrap();
            let mut bytes = vec![];
            g.into_affine().serialize(&mut bytes).unwrap();
            assert_eq!(expected_hashes[i], bytes);
        }
    }

    #[test]
    fn test_hash_to_curve_g2() {
        let composite_hasher = CompositeHasher::new().unwrap();
        let try_and_increment = TryAndIncrement::new(&composite_hasher);
        let mut rng = XorShiftRng::from_seed([
            0x5d, 0xbe, 0x62, 0x59, 0x8d, 0x31, 0x3d, 0x76, 0x32, 0x37, 0xdb, 0x17, 0xe5, 0xbc,
            0x06, 0x54,
        ]);

        let expected_hashes = vec![
            "2105496e0b6aaeb2f2994906d454f5d3cb73237752be1cbe369ba6c96c2446be59b9db1a5bfe4346c7898738ec0e0801aa55e411a44c1d7cb2f8e7247eeaab452521856faee007c99657fb473857599250b572bd3071f8d433b41840ca208101",
            "b012ffd4a1aac348abcdcfbc69e3d244b7ff52160565b299dc2d4308cfd70d0c82c3a1cc9509e37c04ace76f88499d014392e94c450ea6e5031c5ce0a030eebdb6a0064f8adfcc40276423cc1e5917a8c333fccc61e73202ce62b5ca3ff85601",
            "90b80b990a04670d540cf416040e37ea6adeca46c847cdb14d9c87aac1754bff026d5c142ad51cb75df99b31051de7000767dfe056f941485ee58d9a1844fdd9f25ad728eb0888e909df4cf96ebc1db86f8ced3a5b9c7bc2d4de94bbcfff1781",
            "6f7832b24971b83a46efdfc616b26b927bdf7913ee26d619fe8d0384974001bf90ac8f9a6e86aea31e1d8db0afbc7b01bf2b44d9d7f115ad7e4d7865edb93c998a3a3434f14c597b8a0e7332b0b0afbf501753016011ce1275ef7f86815cae00",
            "d6acfaaa4dd34de61c2f37b4b492dfbf4b9db8bab389491cafeb07bc4f5fdfbf3facbeaa05c28ea4435e8a1045022600671bc5d7f2d83a0f654e4403028867aa79c07e7356d336b1432f6c85697a6fd6a8a3b49de3063c26fdddd01401568400",
            "51c9fd5bfb47d6179fe398f7d78543cd2aae15e41fb6f0aebc8c3df6e00a4ea916b8271ffca290e30cdc1b75794f60008104020dedb4f1753b0bd6407af220394da60893de31ffcce822a612ffa4c1424908ef70fd443f7664b661fed01ac800",
            "e2a74c419c5b3060603c7d7e233572c92db2984aab8ed863bd10b15e36c3b88b8a115681c079509c1eb63c892c3a7f01c94a73043cbb0a6b1d86137424ed881f836e4c7d8b83133f0702065e5e6f493690b450563d503709779986aaaec19a80",
            "b5866a25e6e15dec5cd7f52981f786546ed91236d70a25dcd2bb45d112bb027d841ca77575d2b5b43964e191560ca8007287e95e6ba4fadb7f1ba200493b9149f11f49b685207aca839800f3fabb36b258ec822727331aeabae2e3862a946d81",
            "81cb4a09823e7f49ba5b5c4ca11cfd6929e96bf033c697fd9f8d72efe2877ee68657eed375205b7b8395ae44d2640301d1efe43c290b34e605478219a52e83a3dc225e7e917cc7f70dd7103086cbd4a6a64b814106d4c6fca39b965273a91d80",
            "85152b65c51b392ea3e3cf68f49bf145b41e033d77a9ca9b0fc4657b898d7edbe4d5f250a8f7b2a0249e23b1908b7b00da9d4820f21ce942356cfb9de26e7d1ae9e0d80207279f4a6da85f44e780c9d627e21ccb7652a027577252c7e0cc8300",
        ].into_iter().map(|x| hex::decode(&x).unwrap()).collect::<Vec<_>>();

        for i in 0..10 {
            let (domain, msg, extra_data) = generate_test_data(&mut rng);

            let g: G2Projective = <TryAndIncrement<_> as HashToG2>::hash::<Parameters>(
                &try_and_increment,
                &domain,
                &msg,
                &extra_data,
            )
            .unwrap();
            let mut bytes = vec![];
            g.into_affine().serialize(&mut bytes).unwrap();
            assert_eq!(expected_hashes[i], bytes);
        }
    }
}
