//! # Gadgets

mod bls;
pub use bls::BlsVerifyGadget;

mod bitmap;
pub use bitmap::enforce_maximum_occurrences_in_bitmap;

mod y_to_bit;
pub use y_to_bit::YToBitGadget;

mod hash_to_group;
pub use hash_to_group::{hash_to_bits, HashToGroupGadget};

#[cfg(any(test, feature = "test-helpers"))]
pub mod test_helpers {
    use algebra::{Field, Group, PairingEngine, ProjectiveCurve, UniformRand, Zero};
    use r1cs_core::ConstraintSystem;
    use r1cs_std::groups::GroupGadget;
    use rand::SeedableRng;
    use rand_xorshift::XorShiftRng;

    // Same RNG for all tests
    pub fn rng() -> XorShiftRng {
        XorShiftRng::from_seed([
            0x5d, 0xbe, 0x62, 0x59, 0x8d, 0x31, 0x3d, 0x76, 0x32, 0x37, 0xdb, 0x17, 0xe5, 0xbc,
            0x06, 0x54,
        ])
    }

    /// generate a keypair
    pub fn keygen<E: PairingEngine>() -> (E::Fr, E::G2Projective) {
        let rng = &mut rng();
        let generator = E::G2Projective::prime_subgroup_generator();

        let secret_key = E::Fr::rand(rng);
        let pubkey = generator.mul(secret_key);
        (secret_key, pubkey)
    }

    /// generate N keypairs
    pub fn keygen_mul<E: PairingEngine>(num: usize) -> (Vec<E::Fr>, Vec<E::G2Projective>) {
        let mut secret_keys = Vec::new();
        let mut public_keys = Vec::new();
        for _ in 0..num {
            let (secret_key, public_key) = keygen::<E>();
            secret_keys.push(secret_key);
            public_keys.push(public_key);
        }
        (secret_keys, public_keys)
    }

    /// generate N * sets of keypair vectors, each of size 3-7
    #[allow(clippy::type_complexity)]
    pub fn keygen_batch<E: PairingEngine>(
        batch_size: usize,
        num_per_batch: usize,
    ) -> (Vec<Vec<E::Fr>>, Vec<Vec<E::G2Projective>>) {
        let mut secret_keys = Vec::new();
        let mut public_keys = Vec::new();
        (0..batch_size).for_each(|_| {
            let (secret_keys_i, public_keys_i) = keygen_mul::<E>(num_per_batch);
            secret_keys.push(secret_keys_i);
            public_keys.push(public_keys_i);
        });
        (secret_keys, public_keys)
    }

    /// sum the elements in the provided slice
    pub fn sum<P: ProjectiveCurve>(elements: &[P]) -> P {
        elements.iter().fold(P::zero(), |acc, key| acc + key)
    }

    /// N messages get signed by N committees of varying sizes
    /// N aggregate signatures are returned
    pub fn sign_batch<E: PairingEngine>(
        secret_keys: &[Vec<E::Fr>],
        messages: &[E::G1Projective],
    ) -> Vec<E::G1Projective> {
        secret_keys
            .iter()
            .zip(messages)
            .map(|(secret_keys, message)| {
                let (_, asig) = sign::<E>(*message, &secret_keys);
                asig
            })
            .collect::<Vec<_>>()
    }

    /// Allocates an array of group elements to a group gadget
    pub fn alloc_vec<F: Field, G: Group, GG: GroupGadget<G, F>, CS: ConstraintSystem<F>>(
        cs: &mut CS,
        elements: &[G],
    ) -> Vec<GG> {
        elements
            .iter()
            .enumerate()
            .map(|(i, element)| GG::alloc(&mut cs.ns(|| format!("{}", i)), || Ok(element)).unwrap())
            .collect::<Vec<_>>()
    }

    // signs a message with a vector of secret keys and returns the list of sigs + the agg sig
    pub fn sign<E: PairingEngine>(
        message_hash: E::G1Projective,
        secret_keys: &[E::Fr],
    ) -> (Vec<E::G1Projective>, E::G1Projective) {
        let sigs = secret_keys
            .iter()
            .map(|key| message_hash.mul(*key))
            .collect::<Vec<_>>();
        let asig = sigs
            .iter()
            .fold(E::G1Projective::zero(), |acc, sig| acc + sig);
        (sigs, asig)
    }
}
