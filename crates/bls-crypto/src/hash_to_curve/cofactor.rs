use algebra::{
    bls12::{Bls12Parameters, G1Projective},
    ProjectiveCurve,
};

pub fn scale_by_cofactor_g1<P: Bls12Parameters>(p: &G1Projective<P>) -> G1Projective<P> {
    p.into_affine().scale_by_cofactor()
}
