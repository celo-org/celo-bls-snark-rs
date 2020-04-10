use crate::curve::hash::HashToG1;

use algebra::{
    bls12_377::{Fr, G2Projective, Parameters as Bls12_377Parameters},
    bytes::{FromBytes, ToBytes},
    CanonicalDeserialize, CanonicalSerialize, ProjectiveCurve, SerializationError, UniformRand,
};
use rand::Rng;

use std::error::Error;

use std::io::{Read, Result as IoResult, Write};

use super::{PublicKey, Signature, POP_DOMAIN, SIG_DOMAIN};

#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct PrivateKey {
    sk: Fr,
}

impl PrivateKey {
    pub fn generate<R: Rng>(rng: &mut R) -> PrivateKey {
        PrivateKey { sk: Fr::rand(rng) }
    }

    pub fn from_sk(sk: &Fr) -> PrivateKey {
        PrivateKey { sk: sk.clone() }
    }

    pub fn get_sk(&self) -> Fr {
        self.sk.clone()
    }

    pub fn sign<H: HashToG1>(
        &self,
        message: &[u8],
        extra_data: &[u8],
        hash_to_g1: &H,
    ) -> Result<Signature, Box<dyn Error>> {
        self.sign_message(SIG_DOMAIN, message, extra_data, hash_to_g1)
    }

    pub fn sign_pop<H: HashToG1>(
        &self,
        message: &[u8],
        hash_to_g1: &H,
    ) -> Result<Signature, Box<dyn Error>> {
        self.sign_message(POP_DOMAIN, &message, &[], hash_to_g1)
    }

    fn sign_message<H: HashToG1>(
        &self,
        domain: &[u8],
        message: &[u8],
        extra_data: &[u8],
        hash_to_g1: &H,
    ) -> Result<Signature, Box<dyn Error>> {
        Ok(Signature::from_sig(
            hash_to_g1
                .hash::<Bls12_377Parameters>(domain, message, extra_data)?
                .mul(self.sk),
        ))
    }

    pub fn to_public(&self) -> PublicKey {
        PublicKey::from_pk(G2Projective::prime_subgroup_generator().mul(self.sk))
    }
}

impl ToBytes for PrivateKey {
    #[inline]
    fn write<W: Write>(&self, mut writer: W) -> IoResult<()> {
        self.sk.write(&mut writer)
    }
}

impl FromBytes for PrivateKey {
    #[inline]
    fn read<R: Read>(mut reader: R) -> IoResult<Self> {
        let sk = Fr::read(&mut reader)?;
        Ok(PrivateKey::from_sk(&sk))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        curve::hash::try_and_increment::TryAndIncrement,
        hash::{composite::CompositeHasher, direct::DirectHasher, XOF},
    };
    use rand::{thread_rng, Rng};

    #[test]
    fn test_simple_sig() {
        let direct_hasher = DirectHasher::new().unwrap();
        let composite_hasher = CompositeHasher::new().unwrap();
        test_simple_sig_with_hasher(direct_hasher);
        test_simple_sig_with_hasher(composite_hasher);
    }

    fn test_simple_sig_with_hasher<X: XOF>(hasher: X) {
        let rng = &mut thread_rng();
        let try_and_increment = TryAndIncrement::new(&hasher);
        for _ in 0..10 {
            let mut message: Vec<u8> = vec![];
            for _ in 0..32 {
                message.push(rng.gen());
            }
            let sk = PrivateKey::generate(rng);

            let sig = sk.sign(&message[..], &[], &try_and_increment).unwrap();
            let pk = sk.to_public();
            pk.verify(&message[..], &[], &sig, &try_and_increment)
                .unwrap();
            let message2 = b"goodbye";
            pk.verify(&message2[..], &[], &sig, &try_and_increment)
                .unwrap_err();
        }
    }

    #[test]
    fn test_pop() {
        let rng = &mut thread_rng();
        let direct_hasher = DirectHasher::new().unwrap();
        let try_and_increment = TryAndIncrement::new(&direct_hasher);

        let sk = PrivateKey::generate(rng);
        let sk2 = PrivateKey::generate(rng);

        let pk = sk.to_public();
        let mut pk_bytes = vec![];
        pk.write(&mut pk_bytes).unwrap();

        let sig = sk.sign_pop(&pk_bytes, &try_and_increment).unwrap();

        let pk2 = sk2.to_public();
        pk.verify_pop(&pk_bytes, &sig, &try_and_increment).unwrap();
        pk2.verify_pop(&pk_bytes, &sig, &try_and_increment)
            .unwrap_err();
    }
}
