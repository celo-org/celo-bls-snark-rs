use ark_bls12_377::Bls12_377;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem, SynthesisMode};
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

    println!(
        "Number of constraints for {} epochs ({} validators, {} faults, hashes in BW6_761): {}",
        num_epochs,
        num_validators,
        faults,
        cs.num_constraints()
    )
}
