use algebra::PairingEngine;
use std::hash::Hash;

use crate::{
    crypto_primitives::crh::pedersen::PedersenWindow,
    crypto_primitives::crh::bowe_hopwood::{BoweHopwoodPedersenCRH, BoweHopwoodPedersenParameters, CHUNK_SIZE},
    gadgets::crh::FixedLengthCRHGadget,
};
use algebra::groups::Group;
use snark::{ConstraintSystem, SynthesisError};
use snark_gadgets::{groups::GroupGadget, uint8::UInt8, utils::AllocGadget};

use std::{borrow::Borrow, marker::PhantomData};
use snark_gadgets::bits::boolean::Boolean;

#[derive(Derivative)]
#[derivative(Clone(
    bound = "G: Group, W: PedersenWindow, E: PairingEngine, GG: GroupGadget<G, E>"
))]
pub struct BoweHopwoodPedersenCRHGadgetParameters<
    G: Group,
    W: PedersenWindow,
    E: PairingEngine,
    GG: GroupGadget<G, E>,
> {
    params:   BoweHopwoodPedersenParameters<G>,
    _group_g: PhantomData<GG>,
    _engine:  PhantomData<E>,
    _window:  PhantomData<W>,
}

pub struct BoweHopwoodPedersenCRHGadget<G: Group, E: PairingEngine, GG: GroupGadget<G, E>> {
    _group:        PhantomData<*const G>,
    _group_gadget: PhantomData<*const GG>,
    _engine:       PhantomData<E>,
}

impl<E, G, GG, W> FixedLengthCRHGadget<BoweHopwoodPedersenCRH<G, W>, E> for BoweHopwoodPedersenCRHGadget<G, E, GG>
where
    E: PairingEngine,
    G: Group + Hash,
    GG: GroupGadget<G, E>,
    W: PedersenWindow,
{
    type OutputGadget = GG;
    type ParametersGadget = BoweHopwoodPedersenCRHGadgetParameters<G, W, E, GG>;

    fn check_evaluation_gadget<CS: ConstraintSystem<E>>(
        cs: CS,
        parameters: &Self::ParametersGadget,
        input: &[UInt8],
    ) -> Result<Self::OutputGadget, SynthesisError> {
        // Pad the input if it is not the current length.
        let mut input_in_bits: Vec<_> = input
            .iter()
            .flat_map(|byte| byte.into_bits_le())
            .collect();
        if (input_in_bits.len()) % CHUNK_SIZE != 0 {
            let current_length = input_in_bits.len();
            for _ in 0..(CHUNK_SIZE - current_length % CHUNK_SIZE) {
                input_in_bits.push(Boolean::constant(false));
            }
        }
        assert!(input_in_bits.len() % CHUNK_SIZE == 0);
        assert_eq!(parameters.params.generators.len(), W::NUM_WINDOWS*W::WINDOW_SIZE);

        // Allocate new variable for the result.

        let input_in_bits = input_in_bits.chunks(CHUNK_SIZE);
        let result =
            GG::precomputed_base_scalar_mul_3_bit_with_conditional_negation(cs, &parameters.params.generators, input_in_bits, W::WINDOW_SIZE)?;

        Ok(result)
    }

    fn cost() -> usize {
        GG::cost_of_bowe_hopwood(W::NUM_WINDOWS, W::WINDOW_SIZE, CHUNK_SIZE).unwrap()
    }
}

impl<G: Group, W: PedersenWindow, E: PairingEngine, GG: GroupGadget<G, E>>
    AllocGadget<BoweHopwoodPedersenParameters<G>, E> for BoweHopwoodPedersenCRHGadgetParameters<G, W, E, GG>
{
    fn alloc<F, T, CS: ConstraintSystem<E>>(_cs: CS, value_gen: F) -> Result<Self, SynthesisError>
    where
        F: FnOnce() -> Result<T, SynthesisError>,
        T: Borrow<BoweHopwoodPedersenParameters<G>>,
    {
        let params = value_gen()?.borrow().clone();
        Ok(BoweHopwoodPedersenCRHGadgetParameters {
            params,
            _group_g: PhantomData,
            _engine: PhantomData,
            _window: PhantomData,
        })
    }

    fn alloc_input<F, T, CS: ConstraintSystem<E>>(
        _cs: CS,
        value_gen: F,
    ) -> Result<Self, SynthesisError>
    where
        F: FnOnce() -> Result<T, SynthesisError>,
        T: Borrow<BoweHopwoodPedersenParameters<G>>,
    {
        let params = value_gen()?.borrow().clone();
        Ok(BoweHopwoodPedersenCRHGadgetParameters {
            params,
            _group_g: PhantomData,
            _engine: PhantomData,
            _window: PhantomData,
        })
    }
}

#[cfg(test)]
mod test {
    use algebra::curves::sw6::SW6;
    use rand::{thread_rng, Rng};

    use crate::{
        crypto_primitives::crh::{
            pedersen::PedersenWindow,
            bowe_hopwood::BoweHopwoodPedersenCRH,
            FixedLengthCRH,
        },
        gadgets::crh::{bowe_hopwood::BoweHopwoodPedersenCRHGadget, FixedLengthCRHGadget},
    };
    use algebra::curves::edwards_sw6::EdwardsProjective as Edwards;
    use snark::ConstraintSystem;
    use snark_gadgets::{
        groups::curves::twisted_edwards::edwards_sw6::EdwardsSWGadget,
        test_constraint_system::TestConstraintSystem, uint8::UInt8, utils::AllocGadget,
    };
    use algebra::ProjectiveCurve;

    type TestCRH = BoweHopwoodPedersenCRH<Edwards, Window>;
    type TestCRHGadget = BoweHopwoodPedersenCRHGadget<Edwards, SW6, EdwardsSWGadget>;

    #[derive(Clone, PartialEq, Eq, Hash)]
    pub(super) struct Window;

    impl PedersenWindow for Window {
        const WINDOW_SIZE: usize = 90;
        const NUM_WINDOWS: usize = 8;
    }

    #[test]
    fn num_constraints() {
        let rng = &mut thread_rng();
        let mut cs = TestConstraintSystem::<SW6>::new();

        let (_input, input_bytes) = generate_input(&mut cs, rng);
        let input_constraints = cs.num_constraints();
        println!("number of constraints for input: {}", cs.num_constraints());

        let parameters = TestCRH::setup(rng).unwrap();

        let gadget_parameters =
            <TestCRHGadget as FixedLengthCRHGadget<TestCRH, SW6>>::ParametersGadget::alloc(
                &mut cs.ns(|| "gadget_parameters"),
                || Ok(&parameters),
            )
            .unwrap();
        let param_constraints = cs.num_constraints() - input_constraints;
        println!(
            "number of constraints for input + params: {}",
            cs.num_constraints()
        );

        let _ =
            <TestCRHGadget as FixedLengthCRHGadget<TestCRH, SW6>>::check_evaluation_gadget(
                &mut cs.ns(|| "gadget_evaluation"),
                &gadget_parameters,
                &input_bytes,
            )
            .unwrap();

        println!("number of constraints total: {}", cs.num_constraints());
        let eval_constraints = cs.num_constraints() - param_constraints - input_constraints;
        assert_eq!(
            <TestCRHGadget as FixedLengthCRHGadget<TestCRH, SW6>>::cost(),
            eval_constraints
        );
        assert_eq!(
            <TestCRHGadget as FixedLengthCRHGadget<TestCRH, SW6>>::cost(),
            8 * (89*3 + 90 * (1 + 2) + 2) + 7*6
        );
    }

    fn generate_input<CS: ConstraintSystem<SW6>>(
        mut cs: CS,
        rng: &mut dyn Rng,
    ) -> ([u8; 270], Vec<UInt8>) {
        let mut input = [1u8; 270];
        rng.fill_bytes(&mut input);

        let mut input_bytes = vec![];
        for (byte_i, input_byte) in input.into_iter().enumerate() {
            let cs = cs.ns(|| format!("input_byte_gadget_{}", byte_i));
            input_bytes.push(UInt8::alloc(cs, || Ok(*input_byte)).unwrap());
        }
        (input, input_bytes)
    }

    #[test]
    fn crh_primitive_gadget_test() {
        let rng = &mut thread_rng();
        let mut cs = TestConstraintSystem::<SW6>::new();

        let (input, input_bytes) = generate_input(&mut cs, rng);
        println!("number of constraints for input: {}", cs.num_constraints());

        let parameters = TestCRH::setup(rng).unwrap();
        let primitive_result = TestCRH::evaluate(&parameters, &input).unwrap();

        let gadget_parameters =
            <TestCRHGadget as FixedLengthCRHGadget<TestCRH, SW6>>::ParametersGadget::alloc(
                &mut cs.ns(|| "gadget_parameters"),
                || Ok(&parameters),
            )
            .unwrap();
        println!(
            "number of constraints for input + params: {}",
            cs.num_constraints()
        );

        let gadget_result =
            <TestCRHGadget as FixedLengthCRHGadget<TestCRH, SW6>>::check_evaluation_gadget(
                &mut cs.ns(|| "gadget_evaluation"),
                &gadget_parameters,
                &input_bytes,
            )
            .unwrap();

        println!("number of constraints total: {}", cs.num_constraints());

        let primitive_result = primitive_result.into_affine();
        assert_eq!(primitive_result.x, gadget_result.x.value.unwrap());
        assert_eq!(primitive_result.y, gadget_result.y.value.unwrap());
        assert!(cs.is_satisfied());
    }
}
