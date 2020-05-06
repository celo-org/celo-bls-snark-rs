/// Implementation of the `MapToGroup` algorithm (Paragraph
/// 3.3) of [this paper](https://link.springer.com/content/pdf/10.1007/3-540-45682-1_30.pdf)
///
/// This method involves hashing the data along with a counter. If the hash can then be interpreted
/// as an elliptic curve point, it returns. If not, it increments the counter and tries again.
///
/// **This algorithm is not constant time**.
///
/// # Examples
///
/// Hashing the data requires instantiating a hasher, importing the `HashToCurve` trait
/// and calling the `hash` function
///
/// ```rust
/// use bls_crypto::{OUT_DOMAIN, hash_to_curve::{HashToCurve, try_and_increment::DIRECT_HASH_TO_G1}};
///
/// // Instantiate the lazily evaluated hasher to BLS 12-377.
/// let hasher = &*DIRECT_HASH_TO_G1;
///
/// // Hash the data. The domain must be exactly 8 bytes.
/// let hash = hasher.hash(OUT_DOMAIN, &b"some_data"[..], &b"extra"[..]).expect("should not fail");
/// ```
///
/// Doing this manually requires importing the curves and instantiating the hashers as follows:
///
/// ```rust
/// use algebra::bls12_377::g1::Parameters;
/// use bls_crypto::{
///     OUT_DOMAIN,
///     hashers::composite::{CompositeHasher, CRH}, // We'll use the Composite Hasher
///     hash_to_curve::{HashToCurve, try_and_increment::TryAndIncrement},
/// };
///
/// let composite_hasher = CompositeHasher::<CRH>::new().unwrap();
/// let hasher = TryAndIncrement::<_, Parameters>::new(&composite_hasher);
///
/// // hash the data as before
/// let hash = hasher.hash(OUT_DOMAIN, &b"some_data"[..], &b"extra"[..]).expect("should not fail");
///
/// // You can also use the underlying struct's method to get the counter
/// let (hash, counter) = hasher.hash_with_attempt(OUT_DOMAIN, &b"some_data"[..], &b"extra"[..]).expect("should not fail");
/// assert_eq!(counter, 3);
/// ```
pub mod try_and_increment;

use crate::BLSError;

/// Trait for hashing arbitrary data to a group element on an elliptic curve
pub trait HashToCurve {
    /// The type of the curve being used.
    type Output;

    /// Given a domain separator, a message and potentially some extra data, produces
    /// a hash of them which is a curve point.
    fn hash(
        &self,
        domain: &[u8],
        message: &[u8],
        extra_data: &[u8],
    ) -> Result<Self::Output, BLSError>;
}
