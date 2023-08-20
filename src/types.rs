use ark_bls12_381::g1::Config as G1Config;
use ark_bls12_381::g2::Config as G2Config;
use ark_bls12_381::Fq2;
use ark_bls12_381::{Bls12_381, Fq, Fr};
use ark_ec::pairing::PairingOutput;
use ark_ec::short_weierstrass::{Affine, Projective};
use hmac::Hmac;
use num_bigint::BigInt;
use sha2::Sha256;

pub type BLSFr = Fr;
pub type BLSFq = Fq;
pub type BLSFq2 = Fq2;

// Type aliases for G1 and G2 points
pub type G1AffinePoint = Affine<G1Config>;
pub type G2AffinePoint = Affine<G2Config>;
pub type G1ProjectivePoint = Projective<G1Config>;
pub type G2ProjectivePoint = Projective<G2Config>;

/// Type representing the result of a pairing
pub type BLS12381Pairing = PairingOutput<Bls12_381>;

// The spec often talks about "octets strings". We alias Vec<u8> to have the code read closer to the spec
pub type Octets = Vec<u8>;

/// A secret key is just a BigInt
pub type SecretKey = BigInt;

/// Represents a point in G1
/// (we're using the "minimal-pubkey-size" variant of the BLS spec)
pub type PublicKey = Octets;

/// Represents a points in G2
/// (we're using the "minimal-pubkey-size" variant of the BLS spec)
pub type Signature = Octets;

/// Our hash function of choice is SHA-256
pub type BLSHmac = Hmac<Sha256>;

/// Error enum to wrap underlying failures in BLS operations, or wrapping errors
/// coming from this crate's dependencies.
#[derive(Debug, PartialEq, Eq)]
pub enum BLSError {
    /// Error coming from `I2OSP` (see RFC 8017, section 4.1)
    /// <https://datatracker.ietf.org/doc/html/rfc8017#section-4.1>
    IntegerTooLarge,
    SerializationErrorNoXCoordinate,
    SerializationErrorNoYCoordinate,
    IncorrectUncompressedSize,
    IncorrectCompressedSize,
    CompressedBitSet,
    CompressedBitNotSet,
    BadOctetLength,
    MalformedOctets,
    BadXCoordinate,
    PointNotOnCurve,
    HashToPointError,
    NotEnoughSignaturesToAggregate,
    PublicKeysAndMessagesSizeMismatch,
}
