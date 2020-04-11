use crate::curve::hash::HashToG1;

use std::hash::{Hash, Hasher};

use algebra::{
    bls12_377::{
        g2::Parameters as Bls12_377G2Parameters, Bls12_377, Fq, Fq12, Fq2, G2Affine, G2Projective,
        Parameters as Bls12_377Parameters,
    },
    bytes::{FromBytes, ToBytes},
    curves::SWModelParameters,
    AffineCurve, Field, One, PairingEngine, PrimeField, ProjectiveCurve, SquareRootField, Zero,
};

use std::error::Error;

use std::{
    io::{self, Read, Result as IoResult, Write},
    ops::Neg,
};

use super::{cache::PublicKeyCache, BLSError, Signature, POP_DOMAIN, SIG_DOMAIN};

#[derive(Clone, Eq, Debug)]
pub struct PublicKey {
    pk: G2Projective,
}

impl AsRef<G2Projective> for PublicKey {
    fn as_ref(&self) -> &G2Projective {
        &self.pk
    }
}

impl PublicKey {
    pub fn from_pk(pk: G2Projective) -> PublicKey {
        PublicKey { pk }
    }

    pub fn get_pk(&self) -> G2Projective {
        self.pk.clone()
    }

    pub fn clone(&self) -> PublicKey {
        PublicKey::from_pk(self.pk)
    }

    pub fn aggregate(public_keys: &[PublicKey]) -> PublicKey {
        let mut apk = G2Projective::zero();
        for i in public_keys.iter() {
            apk = apk + &(*i).pk;
        }
        PublicKey { pk: apk }
    }

    pub fn from_vec(data: &Vec<u8>) -> IoResult<PublicKey> {
        let mut x_bytes_with_y: Vec<u8> = data.to_owned();
        let x_bytes_with_y_len = x_bytes_with_y.len();
        let y_over_half = (x_bytes_with_y[x_bytes_with_y_len - 1] & 0x80) == 0x80;
        x_bytes_with_y[x_bytes_with_y_len - 1] &= 0xFF - 0x80;
        let x = Fq2::read(x_bytes_with_y.as_slice())?;
        let x3b = <Bls12_377G2Parameters as SWModelParameters>::add_b(
            &((x.square() * &x) + &<Bls12_377G2Parameters as SWModelParameters>::mul_by_a(&x)),
        );
        let y = x3b.sqrt().ok_or(io::Error::new(
            io::ErrorKind::NotFound,
            "couldn't find square root for x",
        ))?;

        let y_c0_big = y.c0.into_repr();
        let y_c1_big = y.c1.into_repr();

        let negy = -y;

        let (bigger, smaller) = {
            let half = Fq::modulus_minus_one_div_two();
            if y_c1_big > half {
                (y, negy)
            } else if y_c1_big == half && y_c0_big > half {
                (y, negy)
            } else {
                (negy, y)
            }
        };

        let chosen_y = if y_over_half { bigger } else { smaller };
        let pk = G2Affine::new(x, chosen_y, false);
        Ok(PublicKey::from_pk(pk.into_projective()))
    }

    pub fn verify<H: HashToG1>(
        &self,
        message: &[u8],
        extra_data: &[u8],
        signature: &Signature,
        hash_to_g1: &H,
    ) -> Result<(), Box<dyn Error>> {
        self.verify_sig(SIG_DOMAIN, message, extra_data, signature, hash_to_g1)
    }

    pub fn verify_pop<H: HashToG1>(
        &self,
        message: &[u8],
        signature: &Signature,
        hash_to_g1: &H,
    ) -> Result<(), Box<dyn Error>> {
        self.verify_sig(POP_DOMAIN, &message, &[], signature, hash_to_g1)
    }

    fn verify_sig<H: HashToG1>(
        &self,
        domain: &[u8],
        message: &[u8],
        extra_data: &[u8],
        signature: &Signature,
        hash_to_g1: &H,
    ) -> Result<(), Box<dyn Error>> {
        let pairing = Bls12_377::product_of_pairings(&vec![
            (
                signature.get_sig().into_affine().into(),
                G2Affine::prime_subgroup_generator().neg().into(),
            ),
            (
                hash_to_g1
                    .hash::<Bls12_377Parameters>(domain, message, extra_data)?
                    .into_affine()
                    .into(),
                self.pk.into_affine().into(),
            ),
        ]);
        if pairing == Fq12::one() {
            Ok(())
        } else {
            Err(BLSError::VerificationFailed)?
        }
    }
}

impl PartialEq for PublicKey {
    fn eq(&self, other: &Self) -> bool {
        // This byte-level equality operator differs from the (much slower) semantic
        // equality operator in G2Projective.  We require byte-level equality here
        // for HashSet to work correctly.  HashSet requires that item equality
        // implies hash equality.
        self.pk.x == other.pk.x && self.pk.y == other.pk.y && self.pk.z == other.pk.z
    }
}

impl Hash for PublicKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        // Only hash based on `y` for slight speed improvement
        self.pk.y.hash(state);
        // self.pk.x.hash(state);
        // self.pk.z.hash(state);
    }
}

impl ToBytes for PublicKey {
    #[inline]
    fn write<W: Write>(&self, mut writer: W) -> IoResult<()> {
        let affine = self.pk.into_affine();
        let mut x_bytes: Vec<u8> = vec![];
        let y_c0_big = affine.y.c0.into_repr();
        let y_c1_big = affine.y.c1.into_repr();
        let half = Fq::modulus_minus_one_div_two();
        affine.x.write(&mut x_bytes)?;
        let num_x_bytes = x_bytes.len();
        if y_c1_big > half {
            x_bytes[num_x_bytes - 1] |= 0x80;
        } else if y_c1_big == half && y_c0_big > half {
            x_bytes[num_x_bytes - 1] |= 0x80;
        }
        writer.write(&x_bytes)?;

        Ok(())
    }
}

impl FromBytes for PublicKey {
    #[inline]
    fn read<R: Read>(mut reader: R) -> IoResult<Self> {
        let mut x_bytes_with_y: Vec<u8> = vec![];
        reader.read_to_end(&mut x_bytes_with_y)?;
        PublicKeyCache::from_vec(&x_bytes_with_y)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::bls::PrivateKey;
    use rand::thread_rng;

    #[test]
    fn test_public_key_serialization() {
        PublicKeyCache::resize(256);
        PublicKeyCache::clear_cache();
        let rng = &mut thread_rng();
        for _i in 0..100 {
            let sk = PrivateKey::generate(rng);
            let pk = sk.to_public();
            let mut pk_bytes = vec![];
            pk.write(&mut pk_bytes).unwrap();
            let pk2 = PublicKey::read(pk_bytes.as_slice()).unwrap();
            assert_eq!(pk.get_pk().into_affine().x, pk2.get_pk().into_affine().x);
            assert_eq!(pk.get_pk().into_affine().y, pk2.get_pk().into_affine().y);
            assert_eq!(pk2.eq(&PublicKey::read(pk_bytes.as_slice()).unwrap()), true);
        }
    }
}
