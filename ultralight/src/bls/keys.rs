use std::ops::{Mul, Neg};
use rand::{thread_rng, Rng};
use failure::Error;
use crate::{
    hash::composite::CompositeHasher,
    curve::hash::HashToG2,
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
        bls12_377::{Fr, Fq12},
    },
    curves::{
        AffineCurve,
        ProjectiveCurve,
        PairingCurve,
        bls12_377::{
            Bls12_377,
            Bls12_377Parameters,
            G1Affine,
            G1Projective,
            G2Affine,
            G2Projective
        },
        models::{
            ModelParameters,
            SWModelParameters,
            bls12::{
                Bls12Parameters,
            }
        },
        PairingEngine,
    },
};

pub struct PrivateKey {
    sk: Fr,
}

impl PrivateKey {
    pub fn generate<R: Rng>(rng: &mut R) -> PrivateKey {
        PrivateKey {
            sk: rng.gen(),
        }
    }

    pub fn from_sk(sk: &Fr) -> PrivateKey {
        PrivateKey {
            sk: sk.clone(),
        }
    }

    pub fn get_sk(&self) -> Fr {
        self.sk
    }

    pub fn sign<H: HashToG2>(&self, message: &[u8], hash_to_g2: &H) -> Result<Signature, Error> {
        Ok(Signature::from_sig(&hash_to_g2.hash::<Bls12_377Parameters>(message)?.mul(&self.sk)))
    }

    pub fn to_public(&self) -> PublicKey {
        PublicKey::from_pk(&G1Projective::prime_subgroup_generator().mul(&self.sk))
    }
}

#[derive(Debug, Fail)]
pub enum BLSError {
    #[fail(display = "signature verification failed")]
    VerificationFailed,
}

pub struct PublicKey {
    pk: G1Projective,
}

impl PublicKey {
    pub fn from_pk(pk: &G1Projective) -> PublicKey {
        PublicKey {
            pk: pk.clone(),
        }
    }

    pub fn get_pk(&self) -> G1Projective {
        self.pk
    }

    pub fn aggregate(public_keys: &[&PublicKey]) -> PublicKey {
        let mut apk = G1Projective::zero();
        for i in public_keys.iter() {
            apk = apk + &(*i).pk;
        }

        PublicKey {
            pk: apk,
        }
    }

    pub fn verify<H: HashToG2>(&self, message: &[u8], signature: &Signature, hash_to_g2: &H) -> Result<(), Error> {
        let pairing = Bls12_377::product_of_pairings(&vec![
            (&G1Affine::prime_subgroup_generator().neg().prepare(), &signature.get_sig().into_affine().prepare()),
            (&self.pk.into_affine().prepare(), &hash_to_g2.hash::<Bls12_377Parameters>(message)?.into_affine().prepare()),
        ]);
        if pairing == Fq12::one() {
            Ok(())
        } else {
            Err(BLSError::VerificationFailed)?
        }
    }
}

pub struct Signature {
    sig: G2Projective
}

impl Signature {
    pub fn from_sig(sig: &G2Projective) -> Signature {
        Signature {
            sig: sig.clone(),
        }
    }

    pub fn get_sig(&self) -> G2Projective {
        self.sig
    }

    pub fn aggregate(signatures: &[&Signature]) -> Signature {
        let mut asig = G2Projective::zero();
        for i in signatures.iter() {
            asig = asig + &(*i).sig;
        }

        Signature {
            sig: asig,
        }
    }
}

#[cfg(test)]
mod test {
    use rand::{thread_rng, Rng};
    use super::*;
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



    #[test]
    fn test_simple_sig() {
        let message = b"hello";
        let rng = &mut thread_rng();

        let composite_hasher = CompositeHasher::new().unwrap();
        let try_and_increment = TryAndIncrement::new(&composite_hasher);
        let sk = PrivateKey::generate(rng);

        let sig = sk.sign(&message[..], &try_and_increment).unwrap();
        let pk = sk.to_public();
        pk.verify(&message[..], &sig, &try_and_increment).unwrap();
        let message2 = b"goodbye";
        pk.verify(&message2[..], &sig, &try_and_increment).unwrap_err();
    }

    #[test]
    fn test_aggregated_sig() {
        let message = b"hello";
        let rng = &mut thread_rng();

        let composite_hasher = CompositeHasher::new().unwrap();
        let try_and_increment = TryAndIncrement::new(&composite_hasher);
        let sk1 = PrivateKey::generate(rng);
        let sk2 = PrivateKey::generate(rng);

        let sig1 = sk1.sign(&message[..], &try_and_increment).unwrap();
        let sig2 = sk2.sign(&message[..], &try_and_increment).unwrap();

        let apk = PublicKey::aggregate(&[&sk1.to_public(), &sk2.to_public()]);
        let asig = Signature::aggregate(&[&sig1, &sig2]);
        apk.verify(&message[..], &asig, &try_and_increment).unwrap();
        apk.verify(&message[..], &sig1, &try_and_increment).unwrap_err();
        sk1.to_public().verify(&message[..], &asig, &try_and_increment).unwrap_err();
        let message2 = b"goodbye";
        apk.verify(&message2[..], &asig, &try_and_increment).unwrap_err();
    }
}
