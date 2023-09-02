//! Helpers to call serialization and deserialization functions from arkworks
use alloc::vec::Vec;
use ark_serialize::CanonicalDeserialize;
use ark_serialize::CanonicalSerialize;

use crate::types::*;
use crate::errors::*;

/// Converts a point on E1 to bytes. These bytes represent the compressed encoding of the point.
/// The point at infinity is serialized as all zeroes, except the 2nd-most significant bit is set.
/// See [this standard](https://github.com/zkcrypto/pairing/tree/fa8103764a07bd273927447d434de18aace252d3/src/bls12_381#serialization).
pub fn point_to_octets_e1(p: G1AffinePoint) -> Octets {
    let mut bytes = Vec::new();
    // Fine to unwrap here; otherwise it means we have bad internal data/points.
    p.serialize_compressed(&mut bytes).unwrap();
    bytes
}

/// Converts a point on E1 to bytes. These bytes represent the uncompressed encoding of the point.
/// The point at infinity is serialized as all zeroes, except the 2nd-most significant bit is set.
/// See [this standard](https://github.com/zkcrypto/pairing/tree/fa8103764a07bd273927447d434de18aace252d3/src/bls12_381#serialization)
pub fn point_to_octets_uncompressed_e1(p: G1AffinePoint) -> Octets {
    let mut bytes = Vec::new();
    // Fine to unwrap here; otherwise it means we have bad internal data/points.
    p.serialize_uncompressed(&mut bytes).unwrap();
    bytes
}

/// Returns the point P corresponding
/// to the canonical representation ostr, or INVALID if ostr is not
/// a valid output of point_to_octets. This operation is also
/// known as deserialization.
///
/// This function accepts uncompressed (96 bytes) or compressed (48 bytes) representations.
/// This function accepts compressed (48 bytes) representations.
pub fn octets_to_point_e1(octets: &Octets) -> Result<G1AffinePoint, BLSError> {
    validate_infinity_flag(octets)?;
    G1AffinePoint::deserialize_compressed(&**octets).map_err(BLSError::from)
}

/// Similar to [`octets_to_point_e1`] but accepts uncompressed (96 bytes) format.
pub fn octets_to_point_e1_uncompressed(octets: &Octets) -> Result<G1AffinePoint, BLSError> {
    validate_infinity_flag(octets)?;
    G1AffinePoint::deserialize_uncompressed(&**octets).map_err(BLSError::from)
}

/// Returns the canonical
/// representation of the point P as an octet string. This
/// operation is also known as serialization.
///
/// The canonical representation is the compressed form.
pub fn point_to_octets_e2(p: G2AffinePoint) -> Octets {
    let mut bytes = Vec::new();
    // Fine to unwrap here; otherwise it means we have bad internal data/points.
    p.serialize_compressed(&mut bytes).unwrap();
    bytes
}

/// Similar to `point_to_octets_E2, but return the uncompressed representation of P.
pub fn point_to_octets_uncompressed_e2(p: G2AffinePoint) -> Octets {
    let mut bytes = Vec::new();
    p.serialize_uncompressed(&mut bytes).unwrap();
    bytes
}

/// Returns the point P corresponding
/// to the canonical representation ostr, or INVALID if ostr is not
/// a valid output of point_to_octets. This operation is also
/// known as deserialization.
///
/// This function accepts compressed (96 bytes) representations.
pub fn octets_to_point_e2(octets: &Octets) -> Result<G2AffinePoint, BLSError> {
    validate_infinity_flag(octets)?;
    G2AffinePoint::deserialize_compressed(&**octets).map_err(BLSError::from)
}
/// Similar to [`octets_to_point_e2`] but accepts uncompressed (192 bytes) representations.
pub fn octets_to_point_e2_uncompressed(octets: &Octets) -> Result<G2AffinePoint, BLSError> {
    validate_infinity_flag(octets)?;
    G2AffinePoint::deserialize_uncompressed(&**octets).map_err( BLSError::from)
}

// Currently a bug in the deserialization logic in Arkworks: if the infinity flag is set but other bits aren't 0, the deserialization still works.
// This function ensures that all bits after the initial 2 are set to zero when the infinity flag is set. Otherwise return an error.
fn validate_infinity_flag(octets: &Octets) -> Result<(), BLSError> {
    if octets.len() > 1 {
        let infinity_flag_set = octets[0] & 0b01000000 > 0;
        if infinity_flag_set {
            for (i, o) in octets.iter().enumerate() {
                let mask = match i {
                    // See https://github.com/zkcrypto/pairing/tree/fa8103764a07bd273927447d434de18aace252d3/src/bls12_381#serialization:
                    // For a correct encoding of a point at infinity:
                    // - First bit (indicating compressed/uncompressed): can be 0 or 1.
                    // - Second bit (infinity bit, already checked above): must be 1.
                    // - Third bit (helps with compressed point deserialization): MUST be 0.
                    // - All other bits MUST be 0
                    0 => 0b00111111,
                    // All other bytes MUST be 0
                    _ => 0b11111111,
                };
                if o & mask > 0 { return Err(BLSError::BadInfinityEncoding(i))}
            }
        }
    }
    Ok(())
}

/// Test cases follow [this standard](https://github.com/zkcrypto/pairing/tree/fa8103764a07bd273927447d434de18aace252d3/src/bls12_381#serialization)
/// ----
/// Original discussion for this serialization standard: <https://github.com/zcash/zcash/issues/2517>
#[cfg(test)]
mod test {
    use super::*;
    use ark_ec::AffineRepr;
    use hex_literal::hex;

    #[test]
    fn test_point_to_octets_e1() {
        assert_eq!(
            point_to_octets_e1(G1AffinePoint::generator()),
            // See https://github.com/nccgroup/pairing-bls12381/blob/617c555b2b94797528049ff9a02789cb39c0e1a9/Crypto/Pairing_bls12381.hs#L225-L226
            // Generator is:
            //     17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb
            //     08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1
            // First 4 bytes of x is 0x1, or 0001 in binary. Compression requires first byte to be set: 1001 or 0x9
            hex!("
                97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb
            ").to_vec()
        );
        assert_eq!(
            point_to_octets_e1(G1AffinePoint::identity()),
            // Identity point is all 0s, with the first and second bits set.
            // 0xc is 1100 in binary.
            hex!("
                c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
            ").to_vec()
        );
    }

    #[test]
    fn test_point_to_octets_uncompressed_e1() {
        assert_eq!(
            point_to_octets_uncompressed_e1(G1AffinePoint::generator()),
            // See https://github.com/nccgroup/pairing-bls12381/blob/617c555b2b94797528049ff9a02789cb39c0e1a9/Crypto/Pairing_bls12381.hs#L225-L226
            // for where this test vector comes from.
            hex!("
                17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb
                08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1
            ").to_vec()
        );
        assert_eq!(
            point_to_octets_uncompressed_e1(G1AffinePoint::identity()),
            // Identity point is all 0s, with the second bit set.
            // 0x4 is 0100 in binary.
            hex!("
                400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
                000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
            ").to_vec()
        );
    }

    #[test]
    fn test_point_to_octets_e2() {
        assert_eq!(
            point_to_octets_e2(G2AffinePoint::generator()),
            // See https://github.com/nccgroup/pairing-bls12381/blob/617c555b2b94797528049ff9a02789cb39c0e1a9/Crypto/Pairing_bls12381.hs#L229-L235
            // for where this test vector comes from.
            // First char was "1" (0x1, or 0001), but we're setting the first bit: 1001 -> 0x9
            hex!("
                93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e
                024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8
            ").to_vec()
        );
        assert_eq!(
            point_to_octets_e2(G2AffinePoint::identity()),
            // Identity point is all 0s, with the second bit set.
            // 0xc is 1100 in binary.
            hex!("
                c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
                000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
            ").to_vec()
        );
    }

    #[test]
    fn test_point_to_octets_uncompressed_e2() {
        assert_eq!(
            point_to_octets_uncompressed_e2(G2AffinePoint::generator()),
            // See https://github.com/nccgroup/pairing-bls12381/blob/617c555b2b94797528049ff9a02789cb39c0e1a9/Crypto/Pairing_bls12381.hs#L229-L235
            // for where this test vector comes from.
            hex!("
                13e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e
                024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8
                0606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be
                0ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801
            ").to_vec()
        );
        assert_eq!(
            point_to_octets_uncompressed_e2(G2AffinePoint::identity()),
            // Identity point is all 0s, with the second bit set.
            // 0x4 is 0100 in binary.
            hex!("
                400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
                000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
                000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
                000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
            ").to_vec()
        );
    }

    #[test]
    fn test_octets_to_point_e1() {
        const G1_COMPRESSED_POINT_AT_INFINITY: &[u8; 48] = &[
            0b11000000, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        const G1_UNCOMPRESSED_POINT_AT_INFINITY: &[u8; 96] = &[
            0b01000000, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0,
        ];

        assert_eq!(
            octets_to_point_e1_uncompressed(&G1_UNCOMPRESSED_POINT_AT_INFINITY.to_vec()).unwrap(),
            G1AffinePoint::identity()
        );
        assert_eq!(
            octets_to_point_e1(&G1_COMPRESSED_POINT_AT_INFINITY.to_vec()).unwrap(),
            G1AffinePoint::identity()
        );
        assert_eq!(
            octets_to_point_e1_uncompressed(&hex!("
            17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb
            08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1
            ").to_vec()).unwrap(),
            G1AffinePoint::generator()  
        );
        assert_eq!(
            octets_to_point_e1(&hex!("
            97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb
            ").to_vec()).unwrap(),
            G1AffinePoint::generator()
        )
    }


    #[test]
    fn test_octets_to_point_e2() {
        const G2_UNCOMPRESSED_POINT_AT_INFINITY: &[u8; 192] = &[
            0b01000000, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0,
        ];
        const G2_COMPRESSED_POINT_AT_INFINITY: &[u8; 96] = &[
            0b11000000, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0,
        ];

        assert_eq!(
            octets_to_point_e2_uncompressed(&G2_UNCOMPRESSED_POINT_AT_INFINITY.to_vec()).unwrap(),
            G2AffinePoint::identity()
        );
        assert_eq!(
            octets_to_point_e2(&G2_COMPRESSED_POINT_AT_INFINITY.to_vec()).unwrap(),
            G2AffinePoint::identity()
        );
        assert_eq!(
            octets_to_point_e2_uncompressed(&hex!("
            13e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e
            024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8
            0606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be
            0ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801
            ").to_vec()).unwrap(),
            G2AffinePoint::generator()
        );
        assert_eq!(
            octets_to_point_e2(&hex!("
            93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e
            024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8
            ").to_vec()).unwrap(),
            G2AffinePoint::generator()
        )
    }
    
    #[test]
    // If this test starts failing, we can get rid of the custom logic!
    fn test_arkworks_accepts_invalid_infinity_encoding() {
        let mut bad_infinity = vec![0u8; 96];
        bad_infinity[0] = 0b11000111;
        assert_eq!(
            G2AffinePoint::deserialize_compressed(&*bad_infinity).unwrap(),
            G2AffinePoint::identity(),
        )
    }

    #[test]
    fn test_this_library_does_not_accept_invalid_infinity_encoding() {
        let mut bad_infinity = vec![0u8; 96];
        
        // Set a bad first byte
        bad_infinity[0] = 0b11010000;
        assert_eq!(
            octets_to_point_e2(&bad_infinity).unwrap_err().to_string(),
            "Bad encoding: infinity bit set but found non-zero bits in byte at index 0"
        );

        // Now set a good first byte, but a bad byte at index 42
        bad_infinity[0] = 0b11000000;
        bad_infinity[42] = 0b01010101;
        assert_eq!(
            octets_to_point_e2(&bad_infinity).unwrap_err().to_string(),
            "Bad encoding: infinity bit set but found non-zero bits in byte at index 42"
        );
    }
}
