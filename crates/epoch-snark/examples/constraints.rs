use ark_bls12_377::Bls12_377;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem, SynthesisMode};
use ark_serialize::CanonicalSerialize;
use blake2s_simd::blake2s;
use epoch_snark::ValidatorSetUpdate;
use std::env;

fn main() {
    let mut args = env::args();
    args.next().unwrap(); // discard the program name
    let num_validators = args
        .next()
        .expect("num validators was expected")
        .parse()
        .expect("NaN");
    let num_epochs = args
        .next()
        .expect("num epochs was expected")
        .parse()
        .expect("NaN");
    let faults = (num_validators - 1) / 3;

    let cs = ConstraintSystem::new_ref();
    cs.set_mode(SynthesisMode::Setup);
    let circuit = ValidatorSetUpdate::<Bls12_377>::empty(num_validators, num_epochs, faults, None);
    circuit.generate_constraints(cs.clone()).unwrap();
    let matrices = cs.to_matrices().unwrap();
    let mut a_bytes = vec![];
    matrices.a.serialize(&mut a_bytes).unwrap();
    let mut b_bytes = vec![];
    matrices.b.serialize(&mut b_bytes).unwrap();
    let mut c_bytes = vec![];
    matrices.c.serialize(&mut c_bytes).unwrap();

    println!(
        "Number of constraints for {} epochs ({} validators, {} faults, hashes in BW6_761): {}, hash: {}",
        num_epochs,
        num_validators,
        faults,
        cs.num_constraints(),
        hex::encode(blake2s(&[blake2s(&a_bytes).as_bytes(),
        blake2s(&b_bytes).as_bytes(),
        blake2s(&c_bytes).as_bytes(),
        ].concat()).as_bytes()),
    )
}
