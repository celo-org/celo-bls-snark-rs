use crate::{fields::Field, TEModelParameters, MontgomeryModelParameters};

pub(crate) fn montgomery_conversion_test<P>()
    where
        P: TEModelParameters + MontgomeryModelParameters,
{
    // A = 2 * (a + d) / (a - d)
    let a = P::BaseField::one().double()*&(<P as TEModelParameters>::COEFF_A + &<P as TEModelParameters>::COEFF_D)*&(<P as TEModelParameters>::COEFF_A - &<P as TEModelParameters>::COEFF_D).inverse().unwrap();
    // B = 4 / (a - d)
    let b = P::BaseField::one().double().double()*&(<P as TEModelParameters>::COEFF_A - &<P as TEModelParameters>::COEFF_D).inverse().unwrap();

    assert_eq!(a, <P as MontgomeryModelParameters>::COEFF_A);
    assert_eq!(b, <P as MontgomeryModelParameters>::COEFF_B);
}