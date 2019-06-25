use crate::{
    curves::{edwards_bls12::*, tests::curve_tests, AffineCurve, ProjectiveCurve},
    groups::tests::group_test,
};
use rand;

#[test]
fn test_projective_curve() {
    curve_tests::<EdwardsProjective>();
}

#[test]
fn test_projective_group() {
    let a = rand::random();
    let b = rand::random();
    for _i in 0..100 {
        group_test::<EdwardsProjective>(a, b);
    }
}

#[test]
fn test_affine_group() {
    let a: EdwardsAffine = rand::random();
    let b: EdwardsAffine = rand::random();
    for _i in 0..100 {
        group_test::<EdwardsAffine>(a, b);
    }
}

#[test]
fn test_generator() {
    let generator = EdwardsAffine::prime_subgroup_generator();
    assert!(generator.is_on_curve());
    assert!(generator.is_in_correct_subgroup_assuming_on_curve());
}

#[test]
fn test_conversion() {
    let a: EdwardsAffine = rand::random();
    let b: EdwardsAffine = rand::random();
    let a_b = {
        use crate::groups::Group;
        (a + &b).double().double()
    };
    let a_b2 = (a.into_projective() + &b.into_projective())
        .double()
        .double();
    assert_eq!(a_b, a_b2.into_affine());
    assert_eq!(a_b.into_projective(), a_b2);
}
<<<<<<< Updated upstream
=======
// If we want just the x-coordinate to be injective in the Edwards prime subgroup, we need that
// 1/d is a non-residue, and a is a quad residue (This is equivalent to the curve beings what is sometimes
// called a complete twisted Edwards curve
// (See thm 5.4.3 in Zcash Sapling spec)
#[test]
fn test_injectivity() {
    use crate::fields::LegendreSymbol::*;
    let d = EdwardsParameters::COEFF_D;
    assert_eq!(d.legendre(),QuadraticNonResidue);
    let a = EdwardsParameters::COEFF_A;
    assert_eq!(d.legendre(),QuadraticNonResidue);
}
>>>>>>> Stashed changes
