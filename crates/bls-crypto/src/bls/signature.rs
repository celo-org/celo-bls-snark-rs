use super::PublicKey;
use crate::{BLSError, HashToCurve};

use ark_bls12_377::{Bls12_377, Fq12, G1Affine, G1Projective, G2Affine};
use ark_ec::{AffineCurve, PairingEngine, ProjectiveCurve};
use ark_ff::One;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};

use std::{
    borrow::Borrow,
    io::{Read, Write},
    ops::Neg,
};

/// A BLS signature on G1.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signature(G1Projective);

impl From<G1Projective> for Signature {
    fn from(sig: G1Projective) -> Signature {
        Signature(sig)
    }
}

impl AsRef<G1Projective> for Signature {
    fn as_ref(&self) -> &G1Projective {
        &self.0
    }
}

impl CanonicalSerialize for Signature {
    fn serialize<W: Write>(&self, writer: W) -> Result<(), SerializationError> {
        self.0.into_affine().serialize(writer)
    }

    fn serialize_uncompressed<W: Write>(&self, writer: W) -> Result<(), SerializationError> {
        self.0.into_affine().serialize_uncompressed(writer)
    }

    fn serialized_size(&self) -> usize {
        self.0.into_affine().serialized_size()
    }
}

impl CanonicalDeserialize for Signature {
    fn deserialize<R: Read>(reader: R) -> Result<Self, SerializationError> {
        Ok(Signature::from(
            G1Affine::deserialize(reader)?.into_projective(),
        ))
    }

    fn deserialize_uncompressed<R: Read>(reader: R) -> Result<Self, SerializationError> {
        Ok(Signature::from(
            G1Affine::deserialize_uncompressed(reader)?.into_projective(),
        ))
    }
}

impl Signature {
    /// Sums the provided signatures to produce the aggregate signature.
    pub fn aggregate<S: Borrow<Signature>>(signatures: impl IntoIterator<Item = S>) -> Signature {
        signatures
            .into_iter()
            .map(|s| s.borrow().0)
            .sum::<G1Projective>()
            .into()
    }

    /// Verifies the signature against a vector of pubkey & message tuples, for the provided
    /// messages domain.
    ///
    /// For each message, an optional extra_data field can be provided (empty otherwise).
    ///
    /// The provided hash_to_g1 implementation will be used to hash each message-extra_data pair
    /// to G1.
    ///
    /// The verification equation can be found in pg.11 from
    /// https://eprint.iacr.org/2018/483.pdf: "Batch verification"
    pub fn batch_verify<H: HashToCurve<Output = G1Projective>, P: Borrow<PublicKey>>(
        &self,
        pubkeys: &[P],
        domain: &[u8],
        messages: &[(&[u8], &[u8])],
        hash_to_g1: &H,
    ) -> Result<(), BLSError> {
        if pubkeys.len() != messages.len() {
            return Err(BLSError::UnevenNumKeysMessages);
        };
        let message_hashes = messages
            .iter()
            .map(|(message, extra_data)| hash_to_g1.hash(domain, message, extra_data))
            .collect::<Result<Vec<G1Projective>, _>>()?;

        self.batch_verify_hashes(pubkeys, &message_hashes)
    }

    /// Verifies the signature against a vector of pubkey & message hash tuples
    /// This is a lower level method, if you prefer hashing to be done internally,
    /// consider using the `batch_verify` method.
    ///
    /// The verification equation can be found in pg.11 from
    /// https://eprint.iacr.org/2018/483.pdf: "Batch verification"
    pub fn batch_verify_hashes<P: Borrow<PublicKey>>(
        &self,
        pubkeys: &[P],
        message_hashes: &[G1Projective],
    ) -> Result<(), BLSError> {
        if pubkeys.len() != message_hashes.len() {
            return Err(BLSError::UnevenNumKeysMessages);
        };
        // `.into()` is needed to prepared the points
        let mut els = Vec::with_capacity(message_hashes.len() + 1);
        els.push((
            self.as_ref().into_affine().into(),
            G2Affine::prime_subgroup_generator().neg().into(),
        ));
        message_hashes
            .iter()
            .zip(pubkeys)
            .for_each(|(hash, pubkey)| {
                els.push((
                    hash.into_affine().into(),
                    pubkey.borrow().as_ref().into_affine().into(),
                ));
            });

        let pairing = Bls12_377::product_of_pairings(&els);
        if pairing == Fq12::one() {
            Ok(())
        } else {
            Err(BLSError::VerificationFailed)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        hash_to_curve::{
            try_and_increment::{TryAndIncrement, COMPOSITE_HASH_TO_G1},
            try_and_increment_cip22::COMPOSITE_HASH_TO_G1_CIP22,
        },
        hashers::{composite::COMPOSITE_HASHER, DirectHasher},
        test_helpers::{keygen_batch, sign_batch, sum},
        PrivateKey, PublicKeyCache, SIG_DOMAIN,
    };

    use crate::hash_to_curve::try_and_increment::DIRECT_HASH_TO_G1;
    use crate::hash_to_curve::try_and_increment_cip22::TryAndIncrementCIP22;
    use ark_bls12_377::{Bls12_377, G1Projective, G2Projective, Parameters};
    use ark_ec::bls12::Bls12Parameters;
    use ark_ff::{UniformRand, Zero};
    use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
    use rand::{thread_rng, Rng};

    #[test]
    fn test_aggregated_sig() {
        test_aggregated_sig_inner(&*COMPOSITE_HASH_TO_G1);
        test_aggregated_sig_inner(&*COMPOSITE_HASH_TO_G1_CIP22);
    }

    fn test_aggregated_sig_inner<H: HashToCurve<Output = G1Projective>>(try_and_increment: &H) {
        let message = b"hello";
        let rng = &mut thread_rng();

        let sk1 = PrivateKey::generate(rng);
        let sk2 = PrivateKey::generate(rng);

        let sig1 = sk1.sign(&message[..], &[], try_and_increment).unwrap();
        let sig2 = sk2.sign(&message[..], &[], try_and_increment).unwrap();
        let sigs = &[sig1, sig2];

        let mut cache = PublicKeyCache::new();

        let apk = cache.aggregate(vec![sk1.to_public(), sk2.to_public()]);
        let asig = Signature::aggregate(sigs);
        apk.verify(&message[..], &[], &asig, try_and_increment)
            .unwrap();
        apk.verify(&message[..], &[], &sigs[0], try_and_increment)
            .unwrap_err();
        sk1.to_public()
            .verify(&message[..], &[], &asig, try_and_increment)
            .unwrap_err();
        let message2 = b"goodbye";
        apk.verify(&message2[..], &[], &asig, try_and_increment)
            .unwrap_err();

        let apk2 = cache.aggregate(vec![sk1.to_public()]);
        apk2.verify(&message[..], &[], &asig, try_and_increment)
            .unwrap_err();
        apk2.verify(&message[..], &[], &sigs[0], try_and_increment)
            .unwrap();

        let apk3 = cache.aggregate(vec![sk2.to_public(), sk1.to_public()]);
        apk3.verify(&message[..], &[], &asig, try_and_increment)
            .unwrap();
        apk3.verify(&message[..], &[], &sigs[0], try_and_increment)
            .unwrap_err();

        let apk4 = PublicKey::aggregate(&[sk1.to_public(), sk2.to_public()]);
        apk4.verify(&message[..], &[], &asig, try_and_increment)
            .unwrap();
        apk4.verify(&message[..], &[], &sigs[0], try_and_increment)
            .unwrap_err();
    }

    #[test]
    fn test_batch_verify() {
        let try_and_increment_direct =
            TryAndIncrement::<_, <Parameters as Bls12Parameters>::G1Parameters>::new(&DirectHasher);
        test_batch_verify_with_hasher(&try_and_increment_direct, false, false);
        let try_and_increment_composite = TryAndIncrement::<
            _,
            <Parameters as Bls12Parameters>::G1Parameters,
        >::new(&*COMPOSITE_HASHER);
        for &cip22 in &[false, true] {
            test_batch_verify_with_hasher(&try_and_increment_composite, true, cip22);
            let try_and_increment_composite_cip22 = TryAndIncrementCIP22::<
                _,
                <Parameters as Bls12Parameters>::G1Parameters,
            >::new(&*COMPOSITE_HASHER);
            test_batch_verify_with_hasher(&try_and_increment_composite_cip22, true, cip22);
        }
    }

    #[allow(unused)] // needed when we don't compile with ffi features
    fn test_batch_verify_with_hasher<H: HashToCurve<Output = G1Projective>>(
        try_and_increment: &H,
        is_composite: bool,
        is_cip22: bool,
    ) {
        let rng = &mut thread_rng();
        let num_epochs = 10;
        let num_validators = 7;

        // generate some msgs and extra data
        let mut msgs = Vec::new();
        for _ in 0..num_epochs {
            let message: Vec<u8> = (0..32).map(|_| rng.gen()).collect::<Vec<u8>>();
            let extra_data: Vec<u8> = (0..32).map(|_| rng.gen()).collect::<Vec<u8>>();
            msgs.push((message, extra_data));
        }
        let msgs = msgs
            .iter()
            .map(|(m, d)| (m.as_ref(), d.as_ref()))
            .collect::<Vec<_>>();

        // get each signed by a committee _on the same domain_ and get the agg sigs of the commitee
        let mut asig = G1Projective::zero();
        let mut pubkeys = Vec::new();
        let mut sigs = Vec::new();
        for msg in msgs.iter().take(num_epochs) {
            let mut epoch_pubkey = G2Projective::zero();
            let mut epoch_sig = G1Projective::zero();
            for _ in 0..num_validators {
                let sk = PrivateKey::generate(rng);
                let s = sk.sign(msg.0, msg.1, try_and_increment).unwrap();

                epoch_sig += s.as_ref();
                epoch_pubkey += sk.to_public().as_ref();
            }

            pubkeys.push(PublicKey::from(epoch_pubkey));
            sigs.push(Signature::from(epoch_sig));

            asig += epoch_sig;
        }

        let asig = Signature::from(asig);

        let res = asig.batch_verify(&pubkeys, SIG_DOMAIN, &msgs, try_and_increment);

        assert!(res.is_ok());

        #[cfg(feature = "ffi")]
        {
            use crate::ffi::utils::{Message, MessageFFI};
            let mut messages = Vec::new();
            for i in 0..num_epochs {
                messages.push(Message {
                    data: msgs[i].0,
                    extra: msgs[i].1,
                    public_key: &pubkeys[i],
                    sig: &sigs[i],
                });
            }

            let msgs_ffi = messages.iter().map(MessageFFI::from).collect::<Vec<_>>();

            let mut verified: bool = false;

            let success = crate::ffi::signatures::batch_verify_signature(
                &msgs_ffi[0] as *const MessageFFI,
                msgs_ffi.len(),
                is_composite,
                is_cip22,
                &mut verified as *mut bool,
            );
            assert!(success);
            assert!(verified);
        }
    }

    #[test]
    fn batch_verify_hashes() {
        // generate 5 (aggregate sigs, message hash pairs)
        // verify them all in 1 call
        let batch_size = 5;
        let num_keys = 7;
        let rng = &mut rand::thread_rng();

        // generate some random messages
        let messages = (0..batch_size)
            .map(|_| G1Projective::rand(rng))
            .collect::<Vec<_>>();
        //
        // keygen for multiple rounds (7 keys per round)
        let (secret_keys, public_keys_batches) = keygen_batch::<Bls12_377>(batch_size, num_keys);

        // get the aggregate public key for each rounds
        let aggregate_pubkeys = public_keys_batches
            .iter()
            .map(|pks| sum(pks))
            .map(PublicKey::from)
            .collect::<Vec<_>>();

        // the keys from each epoch sign the messages from the corresponding epoch
        let asigs = sign_batch::<Bls12_377>(&secret_keys, &messages);

        // get the complete aggregate signature
        let asig = sum(&asigs);
        let asig = Signature::from(asig);

        let res = asig.batch_verify_hashes(&aggregate_pubkeys, &messages);

        assert!(res.is_ok());
    }

    #[test]
    fn test_signature_serialization() {
        let try_and_increment_direct = &*DIRECT_HASH_TO_G1;
        test_signature_serialization_inner(try_and_increment_direct);
        let try_and_increment_composite = &*COMPOSITE_HASH_TO_G1;
        test_signature_serialization_inner(try_and_increment_composite);
        let try_and_increment_composite_cip22 = &*COMPOSITE_HASH_TO_G1_CIP22;
        test_signature_serialization_inner(try_and_increment_composite_cip22);
    }

    fn test_signature_serialization_inner<H: HashToCurve<Output = G1Projective>>(
        try_and_increment: &H,
    ) {
        let rng = &mut thread_rng();

        for _ in 0..100 {
            let message = b"hello";
            let sk = PrivateKey::generate(rng);
            let sig = sk.sign(&message[..], &[], try_and_increment).unwrap();
            let mut sig_bytes = vec![];
            sig.serialize(&mut sig_bytes).unwrap();
            let de = Signature::deserialize(&mut &sig_bytes[..]).unwrap();
            assert_eq!(sig, de);
        }
    }
}
