//! Error enum to wrap underlying failures
use std::error::Error;
use std::fmt;

use ark_serialize::SerializationError;

/// Error enum to wrap underlying failures in BLS operations, or wrap errors from dependencies.
/// Inspired by the excellent https://blog.burntsushi.net/rust-error-handling
#[derive(Debug)]
pub enum BLSError {
    /// Happens when the infinity bit is set in an encoding point, but the rest of the bytes aren't correctly zero'd
    BadInfinityEncoding(usize),
    /// Error coming from `ark_serialize` upon deserialization
    DeserializationError(SerializationError),
    /// Error coming from `I2OSP` (see RFC 8017, section 4.1)
    /// <https://datatracker.ietf.org/doc/html/rfc8017#section-4.1>
    IntegerTooLarge(u64, usize),
    NoSignaturesToAggregate,
    SignatureNotInCorrectSubgroup,
    WrongSizeForSignature(usize),
    WrongSizeForPublicKey(usize),
}

impl Error for BLSError {}

impl fmt::Display for BLSError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            BLSError::BadInfinityEncoding(i) => write!(f, "Bad encoding: infinity bit set but found non-zero bits in byte at index {}", i),
            BLSError::DeserializationError(ref err) => err.fmt(f),
            BLSError::IntegerTooLarge(ref n, l) => write!(f, "Integer too large: cannot fit {} into a byte string of length {}", n, l),
            BLSError::NoSignaturesToAggregate => write!(f, "Cannot aggregate signatures: no signatures were passed in"),
            BLSError::SignatureNotInCorrectSubgroup => write!(f, "Signature point is not in the correct subgroup. Please check the passed in secret key value."),
            BLSError::WrongSizeForSignature(l) => write!(f, "Signature bytes must have length 96 or 192. Got {}", l),
            BLSError::WrongSizeForPublicKey(l) => write!(f, "Public key bytes must have length 48 or 96. Got {}", l),
        }
    }
}

impl From<SerializationError> for BLSError {
    fn from(err: SerializationError) -> BLSError {
        BLSError::DeserializationError(err)
    }
}