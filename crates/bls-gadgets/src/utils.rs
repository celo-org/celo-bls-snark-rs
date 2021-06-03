/// Converts the provided big endian bits to LE bytes
pub fn bits_be_to_bytes_le(bits: &[bool]) -> Vec<u8> {
    let reversed_bits = {
        let mut tmp = bits.to_owned();
        tmp.reverse();
        tmp
    };

    let mut bytes = vec![];
    for chunk in reversed_bits.chunks(8) {
        let mut byte = 0;
        let mut twoi: u64 = 1;
        for c in chunk {
            byte += (twoi * (*c as u64)) as u8;
            twoi *= 2;
        }
        bytes.push(byte);
    }

    bytes
}

/// Converts the provided little endian bits to LE bytes
pub fn bits_le_to_bytes_le(bits: &[bool]) -> Vec<u8> {
    bits_be_to_bytes_le(&bits.iter().cloned().rev().collect::<Vec<_>>())
}

/// If bytes is a little endian representation of a number, this returns the bits
/// of the number in descending order
pub fn bytes_le_to_bits_be(bytes: &[u8], bits_to_take: usize) -> Vec<bool> {
    let mut bits = vec![];
    for b in bytes {
        let mut byte = *b;
        for _ in 0..8 {
            bits.push((byte & 1) == 1);
            byte >>= 1;
        }
    }

    bits.into_iter()
        .take(bits_to_take)
        .collect::<Vec<bool>>()
        .into_iter()
        .rev()
        .collect()
}

/// Converts the provided little endian bytes to LE bits
pub fn bytes_le_to_bits_le(bytes: &[u8], bits_to_take: usize) -> Vec<bool> {
    bytes_le_to_bits_be(bytes, bits_to_take)
        .into_iter()
        .rev()
        .collect()
}

#[cfg(any(test, feature = "test-helpers"))]
pub mod test_helpers {
    use ark_ff::PrimeField;
    use ark_relations::r1cs::{ConstraintLayer, ConstraintSystemRef};
    use tracing_subscriber::layer::SubscriberExt;

    // private fields preclude functional update syntax
    #[allow(clippy::field_reassign_with_default)]
    pub fn run_profile_constraints<T>(f: impl FnOnce() -> T) -> T {
        let layer = ConstraintLayer::new(ark_relations::r1cs::TracingMode::OnlyConstraints);
        let subscriber = tracing_subscriber::Registry::default().with(layer);
        tracing::subscriber::with_default(subscriber, f)
    }

    pub fn print_unsatisfied_constraints<F: PrimeField>(cs: ConstraintSystemRef<F>) {
        if !cs.is_satisfied().unwrap() {
            println!("=========================================================");
            println!("Unsatisfied constraints:");
            println!("{}", cs.which_is_unsatisfied().unwrap().unwrap());
            println!("=========================================================");
        }
    }
}
