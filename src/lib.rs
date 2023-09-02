//! This crate implements BLS12-381 signatures on top of the [`arkworks`](https://github.com/arkworks-rs) crates ecosystem.
//!
//! The interface for BLS signatures is defined in the following IRTF spec:
//! <https://www.ietf.org/archive/id/draft-irtf-cfrg-bls-signature-05.html>
//!
//! This crate aims to implement BLS Signatures in a way that's compatible with Ethereum. The variant selected by
//! Ethereum are explained in [the beacon chain spec](https://github.com/ethereum/consensus-specs/blob/v1.0.0/specs/phase0/beacon-chain.md#bls-signatures).
//! The scheme used by Ethereum is `BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_`.
//! Its parameters are defined [here](https://www.ietf.org/archive/id/draft-irtf-cfrg-bls-signature-05.html#section-4.2.3):
//!  * SC: proof-of-possession
//!  * SV: minimal-pubkey-size
//!  * EC: BLS12-381, as defined in Appendix A.
//!  * H: SHA-256
//!  * hash_to_point: `BLS12381G2_XMD:SHA-256_SSWU_RO_` with the ASCII-encoded domain separation tag `BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_`
//!  * hash_pubkey_to_point: `BLS12381G2_XMD:SHA-256_SSWU_RO_` with the ASCII-encoded domain separation tag `BLS_POP_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_`
//!
//! While the Domain Separation Tag (DST) isn't hardcoded in this crate, we are hardcoding the choice of elliptic curve (BLS12-381), hash function (SHA-256), and variant (minimal-pubkey-size).
#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::string::ToString;
use alloc::vec::Vec;
use core::ops::{Add, AddAssign};

use ark_bls12_381::g2::Config as G2Config;
use ark_bls12_381::Bls12_381;
use ark_ec::hashing::curve_maps::wb::WBMap;
use ark_ec::hashing::map_to_curve_hasher::MapToCurveBasedHasher;
use ark_ec::hashing::HashToCurve;
use ark_ec::pairing::Pairing;
use ark_ec::AffineRepr;
use ark_ff::field_hashers::DefaultFieldHasher;
use ark_ff::PrimeField;
use ark_std::Zero;
use hkdf::Hkdf;
use num_bigint::{BigInt, Sign};
use sha2::{Digest, Sha256};

mod serialization;
pub mod types;
pub mod errors;

use types::*;
use errors::*;

/// Domain separation tags to use if you're working with Ethereum
pub const DST_ETHEREUM: &str = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

/// ([spec link](https://www.ietf.org/archive/id/draft-irtf-cfrg-bls-signature-05.html#section-1.3))
/// A function that invokes the function e of Section 1.3, with argument order depending on signature variant
/// For minimal-pubkey-size: `pairing(U, V) := e(V, U)`
///
/// `e` is defined in <https://www.ietf.org/archive/id/draft-irtf-cfrg-bls-signature-05.html#section-1.3>:
/// > e : G1 x G2 -> GT: a non-degenerate bilinear map
/// > where GT is a subgroup, of prime order r, of the multiplicative group of a field extension
fn pairing(u: G2AffinePoint, v: G1AffinePoint) -> BLS12381Pairing {
    Bls12_381::pairing(v, u)
}

/// ([spec link](https://datatracker.ietf.org/doc/html/rfc8017#section-4.1))
/// I2OSP converts a nonnegative integer to an octet string of a specified length.
///
/// Implementation:
/// ```plain
///    1.  If x >= 256^xLen, output "integer too large" and stop.
///    2.  Write the integer x in its unique xLen-digit representation in base 256:
///        x = x_(xLen-1) 256^(xLen-1) + x_(xLen-2) 256^(xLen-2) + ... + x_1 256 + x_0,
///        where 0 <= x_i < 256 (note that one or more leading digits will be zero if x is less than 256^(xLen-1)).
///    3.  Let the octet X_i have the integer value x_(xLen-i) for 1 <= i <= xLen.
///        Output the octet string X = X_1 X_2 ... X_xLen.
/// ```
fn i2osp(x: u64, x_len: usize) -> Result<Vec<u8>, BLSError> {
    // 1
    if x > 256_u64.pow(x_len.try_into().unwrap()) {
        return Err(BLSError::IntegerTooLarge(x, x_len));
    }

    // 2
    // The description in the spec might seem confusing,
    // but a rephrasing is: encode the input integer `x` as a big-endian byte vector.
    let bytes = x.to_be_bytes();
    let last_byte_idx = bytes.len();

    // 3
    Ok(bytes[last_byte_idx - x_len..last_byte_idx].to_vec())
}

/// ([spec link](https://datatracker.ietf.org/doc/html/rfc8017#section-4.2))
/// OS2IP converts an octet string to a nonnegative integer.
///
/// Implementation:
/// ```plain
///    1.  Let X_1 X_2 ... X_xLen be the octets of X from first to last,
///        and let x_(xLen-i) be the integer value of the octet X_i for 1 <= i <= xLen.
///    2.  Let x = x_(xLen-1) 256^(xLen-1) + x_(xLen-2) 256^(xLen-2) + ...  + x_1 256 + x_0.
///    3.  Output x.
/// ```
fn os2ip(os: &[u8]) -> BigInt {
    // 1 & 2 & 3
    // The spec is a bit confusing, but step 1 and 2 can be rephrased as "parse bytes as a big-endian integer"
    BigInt::from_bytes_be(Sign::Plus, os)
}

/// ([spec link](https://www.ietf.org/archive/id/draft-irtf-cfrg-bls-signature-05.html#section-1.3))
/// A cryptographic hash function that takes as input an arbitrary octet string and returns a point on an
/// elliptic curve. Functions of this kind are defined in [hash-to-curve-spec](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-16).
///
/// Note: given we're using the "minimal-pubkey-size" variant of the spec, this function must output a point in G2.
///
/// XXX: this function doesn't take DST as an argument in the spec. It should!
pub fn hash_to_point(msg: &Octets, dst: &Octets) -> G2AffinePoint {
    let g2_mapper = MapToCurveBasedHasher::<
        G2ProjectivePoint,
        DefaultFieldHasher<Sha256, 128>,
        WBMap<G2Config>,
    >::new(dst)
    .unwrap();
    let q: G2AffinePoint = g2_mapper.hash(msg).unwrap();
    q
}

/// ([spec link](https://www.ietf.org/archive/id/draft-irtf-cfrg-bls-signature-05.html#section-2.2>))
/// Invoke the appropriate serialization routine depending on signature variant
/// For minimal-pubkey-size: `point_to_pubkey(P) := point_to_octets_E1(P)`
///
/// This returns the compressed representation of the public key.
/// If you want the uncompressed representation, see [`point_to_pubkey_uncompressed`].
pub fn point_to_pubkey(p: G1AffinePoint) -> PublicKey {
    serialization::point_to_octets_e1(p)
}

/// Version of [`point_to_pubkey`] returning uncompressed format.
///
/// XXX: this function is not in the spec.
pub fn point_to_pubkey_uncompressed(p: G1AffinePoint) -> PublicKey {
    serialization::point_to_octets_uncompressed_e1(p)
}

/// ([spec link](https://www.ietf.org/archive/id/draft-irtf-cfrg-bls-signature-05.html#section-2.2))
/// Invoke the appropriate serialization routine depending on signature variant
/// For minimal-pubkey-size: `point_to_signature(P) := point_to_octets_E2(P)`
///
/// This returns the compressed representation of the signature.
/// If you want the uncompressed representation, see [`point_to_signature_uncompressed`].
pub fn point_to_signature(p: G2AffinePoint) -> Signature {
    serialization::point_to_octets_e2(p)
}

/// Version of [`point_to_signature`] returning uncompressed format.
///
/// XXX: this function is not in the spec.
pub fn point_to_signature_uncompressed(p: G2AffinePoint) -> Signature {
    serialization::point_to_octets_uncompressed_e2(p)
}

/// ([spec link](https://www.ietf.org/archive/id/draft-irtf-cfrg-bls-signature-05.html#section-2.2))
/// Invoke the appropriate deserialization routine depending on signature variant
/// For minimal-pubkey-size: `pubkey_to_point(ostr) := octets_to_point_E1(ostr)`
pub fn pubkey_to_point(pk: &PublicKey) -> Result<G1AffinePoint, BLSError> {
    match pk.len() {
        48 => serialization::octets_to_point_e1(pk),
        96 => serialization::octets_to_point_e1_uncompressed(pk),
        _ => Err(BLSError::WrongSizeForPublicKey(pk.len())),
    }
}

/// ([spec link](https://www.ietf.org/archive/id/draft-irtf-cfrg-bls-signature-05.html#section-2.2))
/// Invoke the appropriate deserialization routine depending on signature variant
/// For minimal-pubkey-size: signature_to_point(ostr) := octets_to_point_E2(ostr)
pub fn signature_to_point(signature: &Signature) -> Result<G2AffinePoint, BLSError> {
    match signature.len() {
        96 => serialization::octets_to_point_e2(signature),
        192 => serialization::octets_to_point_e2_uncompressed(signature),
        _ => Err(BLSError::WrongSizeForSignature(signature.len())),
    }
}

/// ([spec link](https://www.ietf.org/archive/id/draft-irtf-cfrg-bls-signature-05.html#section-2.3))
/// Generates a secret key SK deterministically from a secret octet string IKM
///
/// Implementation:
/// ```plain
///    1. while True:
///    2.     PRK = HKDF-Extract(salt, IKM || I2OSP(0, 1))
///    3.     OKM = HKDF-Expand(PRK, key_info || I2OSP(L, 2), L)
///    4.     SK = OS2IP(OKM) mod r
///    5.     if SK != 0:
///    6.         return SK
///    7.     salt = H(salt)
/// ```
pub fn keygen(ikm: &Octets) -> SecretKey {
    // Mentioned by the spec as one of the requirements for IKM
    if ikm.len() < 32 {
        panic!(
            "keygen requires at least 32 bytes of entropy passed in. Got {}",
            ikm.len()
        );
    }

    // Prepare our salt value
    let mut hasher = Sha256::new();
    hasher.update(b"BLS-SIG-KEYGEN-SALT-");
    let mut salt = hasher.finalize();

    // 1
    loop {
        // 2
        let hkdf_extract_input = &mut ikm.clone();
        hkdf_extract_input
            .extend_from_slice(&i2osp(0, 1).expect("hardcoded, working input values"));
        let hk = Hkdf::<Sha256>::new(Some(&salt[..]), hkdf_extract_input);

        // 3
        // L is defined as "the integer given by ceil((3 * ceil(log2(r))) / 16)."
        // Note that `ceil(log2(r))` is, conveniently, the number of bits in `r`. Hence BLSFr::MODULUS_BIT_SIZE.
        // we use the libm crate, since core doesn't have support for math.
        let l = libm::ceil((3_f64 * BLSFr::MODULUS_BIT_SIZE as f64) / 16_f64) as u64;
        let info = i2osp(l, 2).expect("unable to convert L to octet bytes");
        // .try_into().unwrap() is okay here, L is a static value!
        let mut okm = vec![0u8; l.try_into().unwrap()];
        hk.expand(&info, &mut okm).expect("unable to expand HKDF");

        // 4
        // A bit awkward, but we need to convert from arkworks' BigInt to the more standard num-bigint version.
        // The resulting order `r` should be 52435875175126190479447740508185965837690552500527637822603658699938581184513.
        let r = BigInt::parse_bytes(BLSFr::MODULUS.to_string().as_bytes(), 10)
            .expect("parsing a constant");
        let sk = os2ip(&okm) % r;

        // 5
        if !sk.is_zero() {
            // 6
            return sk;
        } else {
            // 7
            let mut hasher = Sha256::new();
            hasher.update(b"BLS-SIG-KEYGEN-SALT-");
            salt = hasher.finalize();
        }
    }
}

/// ([spec link](https://www.ietf.org/archive/id/draft-irtf-cfrg-bls-signature-05.html#section-2.4))
/// Takes a secret key SK and outputs the corresponding public key PK.
///
/// Implementation:
/// ```plain
///    1. xP = SK * P
///    2. PK = point_to_pubkey(xP)
///    3. return PK
/// ```
pub fn sk_to_pk(sk: SecretKey) -> PublicKey {
    // 1
    let g = G1AffinePoint::generator();
    let (_, digits) = sk.to_u64_digits();
    let p = g.mul_bigint(&digits);

    // 2 & 3
    point_to_pubkey(p.into())
}

/// ([spec link](https://www.ietf.org/archive/id/draft-irtf-cfrg-bls-signature-05.html#section-2.6))
/// Computes a signature from SK, a secret key, and message, an octet string.
///
/// The implementation is described as:
/// ```plain
///    1. Q = hash_to_point(message)
///    2. R = SK * Q
///    3. signature = point_to_signature(R)
///    4. return signature
/// ```
///
/// XXX: this function doesn't take DST as an argument in the spec. It should!
pub fn sign(sk: SecretKey, message: &Octets, dst: &Octets) -> Result<Signature, BLSError> {
    // 1
    let q = hash_to_point(message, dst);

    // 2
    let (_sign, digits) = sk.to_u64_digits();
    let r = q.mul_bigint(&digits);

    // Not officially mandated by the standard, but return an error if the signature isn't in the subgroup
    // This can happen if zero is passed as a value for `sk`
    if !signature_subgroup_check(r.into()) {
        return Err(BLSError::SignatureNotInCorrectSubgroup);
    }

    // 3
    let signature = point_to_signature(r.into());

    // 4
    Ok(signature)
}

/// ([spec link](https://www.ietf.org/archive/id/draft-irtf-cfrg-bls-signature-05.html#section-2.8))
/// Aggregates multiple signatures into one.
///
/// Implementation:
/// ```plain
///    1. aggregate = signature_to_point(signature_1)
///    2. If aggregate is INVALID, return INVALID
///    3. for i in 2, ..., n:
///    4.     next = signature_to_point(signature_i)
///    5.     If next is INVALID, return INVALID
///    6.     aggregate = aggregate + next
///    7. signature = point_to_signature(aggregate)
///    8. return signature
/// ```
pub fn aggregate(signatures: &[Signature]) -> Result<Signature, BLSError> {
    // XXX: not explicitly mentioned by the spec, but if there are no signatures
    // to aggregate, the aggregate functionality doesn't make sense. Error out!
    if signatures.is_empty() {
        return Err(BLSError::NoSignaturesToAggregate);
    }

    // 1 & 2
    let mut aggregate = signature_to_point(&signatures[0])?;

    // 3
    for signature in signatures.iter().skip(1) {
        // 4 & 5
        let next = signature_to_point(signature)?;
        // 6
        aggregate = aggregate.add(next).into();
    }
    // 7 & 8
    Ok(point_to_signature(aggregate))
}

/// ([spec link](https://www.ietf.org/archive/id/draft-irtf-cfrg-bls-signature-05.html#section-2.7))
/// Checks that a signature is valid for the octet string message under the public key PK.
///
/// Implementation:
/// ```plain
///    1. R = signature_to_point(signature)
///    2. If R is INVALID, return INVALID
///    3. If signature_subgroup_check(R) is INVALID, return INVALID
///    4. If KeyValidate(PK) is INVALID, return INVALID
///    5. xP = pubkey_to_point(PK)
///    6. Q = hash_to_point(message)
///    7. C1 = pairing(Q, xP)
///    8. C2 = pairing(R, P)
///    9. If C1 == C2, return VALID, else return INVALID
/// ```
///
/// XXX: this function doesn't take DST as an argument in the spec. It should!
pub fn verify(pk: &PublicKey, message: &Octets, signature: &Signature, dst: &Octets) -> bool {
    // 1
    let r = match signature_to_point(signature) {
        Ok(r) => r,
        // 2
        Err(_) => return false,
    };

    // 3
    if !signature_subgroup_check(r) {
        return false;
    }

    // 4
    if !key_validate(pk) {
        return false;
    }

    // 5
    let x_p = match pubkey_to_point(pk) {
        Ok(p) => p,
        // 2
        Err(_) => return false,
    };

    // 6
    let q = hash_to_point(message, dst);

    // 7
    let c1 = pairing(q, x_p);

    // From the spec:
    // > When the signature variant is minimal-pubkey-size, P is the distinguished point P1 that generates the group G1.
    // <https://www.ietf.org/archive/id/draft-irtf-cfrg-bls-signature-05.html#section-2.2>
    let p = G1AffinePoint::generator();

    // 8
    let c2 = pairing(r, p);

    // 9
    c1 == c2
}

/// ([spec link](https://www.ietf.org/archive/id/draft-irtf-cfrg-bls-signature-05.html#section-2.9))
/// Checks an aggregated signature over several (PK, message) pairs.
///
/// Implementation:
/// ```plain
///    1.  R = signature_to_point(signature)
///    2.  If R is INVALID, return INVALID
///    3.  If signature_subgroup_check(R) is INVALID, return INVALID
///    4.  C1 = 1 (the identity element in GT)
///    5.  for i in 1, ..., n:
///    6.      If KeyValidate(PK_i) is INVALID, return INVALID
///    7.      xP = pubkey_to_point(PK_i)
///    8.      Q = hash_to_point(message_i)
///    9.      C1 = C1 * pairing(Q, xP)
///    10. C2 = pairing(R, P)
///    11. If C1 == C2, return VALID, else return INVALID
/// ```
///
/// XXX: this function doesn't take DST as an argument in the spec. It should!
pub fn aggregate_verify(
    public_keys: Vec<PublicKey>,
    messages: Vec<Octets>,
    signature: &Signature,
    dst: &Octets,
) -> bool {
    // XXX: although not strictly mandated by the spec, this function
    // enforces that public_keys and messages are the same length.
    if public_keys.len() != messages.len() {
        return false;
    }

    // 1
    let r = match signature_to_point(signature) {
        Ok(r) => r,
        // 2
        Err(_) => return false,
    };

    // 3
    if !signature_subgroup_check(r) {
        return false;
    }

    // 4
    // Note: the spec correct says "1", but the API is `::zero()`.
    // Worry not: in the docstring of `ark_ec::pairing::PairingOutput::zero()` it says
    // that it's implemented as `P::TargetField::one()`.
    let mut c1 = BLS12381Pairing::zero();

    // 5
    for (public_key, message) in public_keys.iter().zip(messages.iter()) {
        // 6
        if !key_validate(public_key) {
            return false;
        }

        // 7
        let x_p = match pubkey_to_point(public_key) {
            Ok(x_p) => x_p,
            // Not explicit in the spec, but if the public key isn't valid, return "INVALID" (false)
            // This branch should never be hit because we check this already with `key_validate` above.
            Err(_) => return false,
        };

        // 8
        let q = hash_to_point(message, dst);

        // 9
        // XXX: I think the spec is wrong here? The operation we want is +, not *?
        c1.add_assign(pairing(q, x_p));
    }

    // 10
    let c2 = pairing(r, G1AffinePoint::generator());
    c1 == c2
}

/// ([spec link](https://www.ietf.org/archive/id/draft-irtf-cfrg-bls-signature-05.html#section-2.5))
/// Ensures that a public key is valid. In particular, it ensures that
/// a public key represents a valid, non-identity point that is in the correct subgroup.
///
/// Implementation:
/// ```plain
///    1. xP = pubkey_to_point(PK)
///    2. If xP is INVALID, return INVALID
///    3. If xP is the identity element, return INVALID
///    4. If pubkey_subgroup_check(xP) is INVALID, return INVALID
///    5. return VALID
/// ```
pub fn key_validate(pk: &PublicKey) -> bool {
    // 1
    let p = match pubkey_to_point(pk) {
        Ok(p) => p,
        // 2
        Err(_) => return false,
    };

    // 3
    if p.is_zero() {
        return false;
    }

    // 4
    if !pubkey_subgroup_check(p) {
        return false;
    }

    // 5
    true
}

/// ([spec link](https://www.ietf.org/archive/id/draft-irtf-cfrg-bls-signature-05.html#section-2.2))
/// Invoke the appropriate subgroup check routine (Section 1.3) depending on signature variant:
/// For minimal-pubkey-size: `pubkey_subgroup_check(P) := subgroup_check_E1(P)`.
pub fn pubkey_subgroup_check(p: G1AffinePoint) -> bool {
    subgroup_check_e1(p)
}

/// ([spec link](https://www.ietf.org/archive/id/draft-irtf-cfrg-bls-signature-05.html#section-2.2))
/// Invoke the appropriate subgroup check routine (Section 1.3) depending on signature variant:
/// For minimal-pubkey-size: `signature_subgroup_check(P) := subgroup_check_E2(P)`.
pub fn signature_subgroup_check(p: G2AffinePoint) -> bool {
    subgroup_check_e2(p)
}

/// ([spec link](https://www.ietf.org/archive/id/draft-irtf-cfrg-bls-signature-05.html#section-1.3-5.1.3.3.1))
/// Returns VALID when the point P is an element of the subgroup of order r, and INVALID otherwise.
fn subgroup_check_e1(p: G1AffinePoint) -> bool {
    // XXX: not mentioned by the spec but we added a check to avoid at-infinity points
    p.is_on_curve() && p.is_in_correct_subgroup_assuming_on_curve() && !p.is_zero()
}

/// ([spec link](https://www.ietf.org/archive/id/draft-irtf-cfrg-bls-signature-05.html#section-1.3-5.1.3.3.1))
/// Returns VALID when the point P is an element of the subgroup of order r, and INVALID otherwise.
fn subgroup_check_e2(p: G2AffinePoint) -> bool {
    // XXX: not mentioned by the spec but we added a check to avoid at-infinity points
    p.is_on_curve() && p.is_in_correct_subgroup_assuming_on_curve() && !p.is_zero()
}

#[cfg(test)]
mod test {
    use hex::ToHex;
    use hex_literal::hex;
    use num_bigint::ToBigInt;
    use rand_core::{OsRng, RngCore};
    use super::*;

    #[test]
    fn test_i2osp() {
        assert_eq!(i2osp(1, 1).unwrap(), vec![0b00000001],);
        assert_eq!(i2osp(255, 1).unwrap(), vec![0b11111111],);
        assert_eq!(i2osp(257, 1).unwrap_err().to_string(), "Integer too large: cannot fit 257 into a byte string of length 1");
        assert_eq!(i2osp(259, 2).unwrap(), vec![0b00000001, 0b00000011],);
    }

    #[test]
    fn test_os2ip() {
        assert_eq!(os2ip(&[0b00000000]), BigInt::from(0),);
        assert_eq!(os2ip(&[0b00000001]), BigInt::from(1),);
        assert_eq!(os2ip(&[0b11111111]), BigInt::from(255),);
        assert_eq!(
            os2ip(&[0b00000010, 0b11111111]),
            // 256 * 2 + 255 = 767
            BigInt::from(767),
        );
    }

    #[test]
    #[should_panic(expected = "keygen requires at least 32 bytes of entropy passed in. Got 31")]
    fn test_keygen_fails_with_short_ikm() {
        let ikm: [u8; 31] = [0u8; 31];
        keygen(&ikm.to_vec());
    }

    #[test]
    fn test_keygen() {
        let mut ikm = [0u8; 32];
        OsRng.fill_bytes(&mut ikm);
        let res = keygen(&ikm.to_vec());
        assert!(res > 0.to_bigint().unwrap());
    }

    #[test]
    fn test_pubkey_subgroup_check() {
        let g = G1AffinePoint::generator();
        assert!(pubkey_subgroup_check(g));

        // flip x and y, this should be an invalid point!
        let not_g = G1AffinePoint::new_unchecked(*g.y().unwrap(), *g.x().unwrap());
        assert!(!pubkey_subgroup_check(not_g));
    }

    #[test]
    fn test_signature_subgroup_check() {
        let g = G2AffinePoint::generator();
        assert!(signature_subgroup_check(g));

        // flip x and y, this should be an invalid point!
        let not_g = G2AffinePoint::new_unchecked(*g.y().unwrap(), *g.x().unwrap());
        assert!(!signature_subgroup_check(not_g));
    }

    #[test]
    fn test_sk_to_pk_with_one() {
        // multiplying G by one should give G
        assert_eq!(
            sk_to_pk(BigInt::from(1)),
            point_to_pubkey(G1AffinePoint::generator()),
        );
    }

    #[test]
    fn test_sk_to_pk_against_ian_coleman() {
        // Values obtained via https://iancoleman.io/eip2333/
        // This was the first derived address (index m/0) from the following seed:
        // 4c4f7f21e38afd4c586cbd1e5854450b25149ed8d9d71ca4372cb810e58a827c197cb337e0afbfedec7a0c849e405fea4e54316daf01a5b7e03a6b0a523e2fe3
        let secret = "316cb723e4bbdbf536d82384efe04b15484fd44afb5e579e04718c7e7eb83e0c";
        let public_key = sk_to_pk(BigInt::parse_bytes(secret.to_string().as_bytes(), 16).unwrap());

        assert_eq!(
            public_key,
            hex!("97d5726528eef5a2da8aa09bee99b04fbb3f3b7893a2988e42bfeb5af1163525c9d3832bed9e5237885339ff48d6c9fa")
        )
    }

    #[test]
    fn test_sk_to_pk_against_noble() {
        // Using the mini-app at the bottom of https://paulmillr.com/noble/
        let secret = b"f0c5bf519a6ede6be1ab684f6ecc1b129b0fc2ed95bd294bb2967077ae38a378";
        let public_key = sk_to_pk(BigInt::parse_bytes(secret, 16).unwrap());
        assert_eq!(
            public_key,
            hex!("855e5129c94bb05d0bcdf0ba1e56750f9fac3da8d272baec0ce3f1fec6f22a91b84b33032a99dee48844feefc37739dc"),
        )
    }

    #[test]
    fn test_sign_against_noble_with_default_private_key() {
        let signature = sign(
            // Using the mini-app at the bottom of https://paulmillr.com/noble/
            BigInt::parse_bytes(
                b"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                16,
            )
            .unwrap(),
            // "greetings from noble"
            &hex::decode("011a775441ecb14943130a16f00cdd41818a83dd04372f3259e3ca7237e3cdaa")
                .unwrap(),
            &"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_"
                .as_bytes()
                .to_vec(),
        )
        .unwrap();

        assert_eq!(
            signature.encode_hex::<String>(),
            "931178fd6248c4d8650426537afd262c6407018f2d89f5aec1cf9dff7b281ce0c16ebf88d6f49ba33bdb502f69ef03580cad279b353051a6d8f4d6941da0634afc8a0ca6fe4119b8c042c93016c5237dd06b0b455f46e25b344ebe4e3c86ce19",
        );

        // Just for fun, let's also test the individual point coordinates given by the webapp.
        let (_, x_c0) = BigInt::parse_bytes(b"1951074311397816256217129380891448215678103053074455239203290963002534607849011313647510737720424816079908725247513", 10).unwrap().to_bytes_be();
        let (_, x_c1) = BigInt::parse_bytes(b"2934872654361522962759986647459927853251267831434292165317227028576379973684083603495601412610656616034626006090584", 10).unwrap().to_bytes_be();
        let (_, y_c0) = BigInt::parse_bytes(b"1869792139333396858178251220129949242633799375694650208182172238168545074778871854467625856201949000921888099776790", 10).unwrap().to_bytes_be();
        let (_, y_c1) = BigInt::parse_bytes(b"0558076992166314972755149101271563409407496946727250694896358285926396466075836657102984448222057214785610737591242", 10).unwrap().to_bytes_be();

        // To do this we parse the coordinates as an uncompressed G2 point, then compare to the point obtained from parsing our actual signature.
        // They should be the same!
        assert_eq!(
            signature_to_point(&signature).unwrap(),
            signature_to_point(
                &hex::decode(format!(
                    "{}{}{}{}",
                    x_c1.encode_hex::<String>(),
                    x_c0.encode_hex::<String>(),
                    y_c1.encode_hex::<String>(),
                    y_c0.encode_hex::<String>(),
                ))
                .unwrap()
            )
            .unwrap(),
        );
    }

    #[test]
    fn test_sign_against_noble_with_random_private_key() {
        let signature = sign(
            // Using the mini-app at the bottom of https://paulmillr.com/noble/
            BigInt::parse_bytes(
                b"22ae2c98fe58a9bfae1b5acef4258a4e65593a21de5487dc3357184235ebd5ff",
                16,
            )
            .unwrap(),
            // Verify the hash with `echo -n 'Arnaud testing. 1. 2. Over. Kshhh.' | openssl dgst -sha256`
            &hex::decode("254958ab7082ba726466464e4118d86d5b19f24629b5ecfe539253fa2c821a79")
                .unwrap(),
            &"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_"
                .as_bytes()
                .to_vec(),
        )
        .unwrap();

        assert_eq!(
            signature.encode_hex::<String>(),
            "8c7c2fcdb503de39c0cdbb510e59685c37425a8de0345996b5b9a65ce2daf98cf3c18032d9905166815f82821ca99b0e1620a2df08b3fea5f20e27c7559a3616ffabc5f76c5277d4254d588fc8e775d1880f69925f66e2dadd25c0617a3e6c6b"
        );
    }

    #[test]
    fn test_verify() {
        let pk = sk_to_pk(
            BigInt::parse_bytes(
                b"22ae2c98fe58a9bfae1b5acef4258a4e65593a21de5487dc3357184235ebd5ff",
                16,
            )
            .unwrap(),
        );
        // Verify the hash with `echo -n 'Arnaud testing. 1. 2. Over. Kshhh.' | openssl dgst -sha256`
        let message =
            hex::decode("254958ab7082ba726466464e4118d86d5b19f24629b5ecfe539253fa2c821a79")
                .unwrap();
        let signature = hex::decode("8c7c2fcdb503de39c0cdbb510e59685c37425a8de0345996b5b9a65ce2daf98cf3c18032d9905166815f82821ca99b0e1620a2df08b3fea5f20e27c7559a3616ffabc5f76c5277d4254d588fc8e775d1880f69925f66e2dadd25c0617a3e6c6b").unwrap();
        let dst = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_"
            .as_bytes()
            .to_vec();
        assert!(verify(&pk, &message, &signature, &dst));
    }

    #[test]
    fn test_signature_aggregation() {
        let dst = &"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_"
            .as_bytes()
            .to_vec();
        let sk1 = BigInt::parse_bytes(
            b"22ae2c98fe58a9bfae1b5acef4258a4e65593a21de5487dc3357184235ebd5ff",
            16,
        )
        .unwrap();
        let sk2 = BigInt::parse_bytes(
            b"4b8e9a78f3da90c1f03160d9a904eba83f70abe4c0364ec4c1a37b9dd32cfe0d",
            16,
        )
        .unwrap();
        let sk3 = BigInt::parse_bytes(
            b"0179b2fa76e0b267c9eae3ecec1f9beb31f1c2e25a71b70cc465d20afd835876",
            16,
        )
        .unwrap();

        // Verify the digests with `echo -n 'Arnaud is testing {one,two,three}' | openssl dgst -sha256`
        let msg1 = hex::decode("0c1c81866dafbd0e9e3dc275ae3e47a82d1ce3b97696553eb3f86c4246dda0e4")
            .unwrap();
        let msg2 = hex::decode("54dc80580a7e6d8caaaef32cadd7b1b5422c59bfee9fe6f77c11c5fbe9375536")
            .unwrap();
        let msg3 = hex::decode("86fbb0b808638fe56c51b7d0946b3690928e0b2e34aed72a945ca2fb2fa095fb")
            .unwrap();

        let sig1 = sign(sk1.clone(), &msg1, &dst).unwrap();
        let sig2 = sign(sk2.clone(), &msg2, &dst).unwrap();
        let sig3 = sign(sk3.clone(), &msg3, &dst).unwrap();

        let aggregate_signature = aggregate(&[sig1, sig2, sig3]).unwrap();
        assert!(aggregate_verify(
            vec!(sk_to_pk(sk1), sk_to_pk(sk2), sk_to_pk(sk3)),
            vec!(msg1, msg2, msg3),
            &aggregate_signature,
            &dst
        ));
    }

    #[test]
    fn test_hash_to_point_with_null_bytes() {
        let dst = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_"
            .as_bytes()
            .to_vec();
        let p = hash_to_point(&vec![0], &dst);
        let q = hash_to_point(&vec![0, 0], &dst);

        assert_ne!(p, q);
    }
}
