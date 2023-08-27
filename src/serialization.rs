//! Implements serialization and deserialization, in compressed and uncompressed formats,
//! following [this standard](https://github.com/zkcrypto/pairing/tree/fa8103764a07bd273927447d434de18aace252d3/src/bls12_381#serialization)
//! ----
//! Original discussion for this serialization standard: <https://github.com/zcash/zcash/issues/2517>
use ark_ec::AffineRepr;
use ark_ff::PrimeField;
use num_bigint::BigInt;

use crate::types::*;

const G1_COMPRESSED_POINT_SIZE: usize = 48;
const G1_UNCOMPRESSED_POINT_SIZE: usize = 96;
const G2_COMPRESSED_POINT_SIZE: usize = 96;
const G2_UNCOMPRESSED_POINT_SIZE: usize = 192;

const G1_COMPRESSED_POINT_AT_INFINITY: &[u8; G1_COMPRESSED_POINT_SIZE] = &[
    0b11000000, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];

const G1_UNCOMPRESSED_POINT_AT_INFINITY: &[u8; G1_UNCOMPRESSED_POINT_SIZE] = &[
    0b01000000, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0,
];

const G2_COMPRESSED_POINT_AT_INFINITY: &[u8; G2_COMPRESSED_POINT_SIZE] = &[
    0b11000000, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0,
];

const G2_UNCOMPRESSED_POINT_AT_INFINITY: &[u8; G2_UNCOMPRESSED_POINT_SIZE] = &[
    0b01000000, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0,
];

/// Converts a point on E1 to bytes. These bytes represent the compressed encoding of the point.
/// The point at infinity is serialized as all zeroes, except the 2nd-most significant bit is set.
/// See [this standard](https://github.com/zkcrypto/pairing/tree/fa8103764a07bd273927447d434de18aace252d3/src/bls12_381#serialization).
pub fn point_to_octets_e1(p: G1AffinePoint) -> Octets {
    if p.is_zero() {
        let mut infinity = vec![0; 48];
        infinity[0] = 0b11000000;
        return infinity;
    }

    let (x, y) = p.xy().expect("p is not at infinity, we checked above");

    // Possible y coordinates, in lexicographical order
    let (_, y2) = &G1AffinePoint::get_ys_from_x_unchecked(*x).expect("p is a G1 point, on curve");

    let mut compressed = field_element_to_bytes(x);

    // Set the first bit to indicate compressed form
    // Okay to unwrap() here, `compressed` is at least 1 bytes long.
    compressed[0] = compressed.first().map(|b| b | 0b10000000).unwrap();

    if y == y2 {
        // If the y coordinate is the second (in lexicographical order), set the 3rd most significant bit
        // Okay to unwrap() here, `compressed` is at least 1 bytes long.
        compressed[0] = compressed.first().map(|b| b | 0b00100000).unwrap();
    }
    compressed
}

/// Converts a point on E1 to bytes. These bytes represent the uncompressed encoding of the point.
/// The point at infinity is serialized as all zeroes, except the 2nd-most significant bit is set.
/// See [this standard](https://github.com/zkcrypto/pairing/tree/fa8103764a07bd273927447d434de18aace252d3/src/bls12_381#serialization)
pub fn point_to_octets_uncompressed_e1(p: G1AffinePoint) -> Octets {
    if p.is_zero() {
        return G1_UNCOMPRESSED_POINT_AT_INFINITY.to_vec();
    }
    let (x, y) = p.xy().expect("point is not at infinity -- checked above!");
    let mut res: Vec<u8> = vec![];
    res.append(&mut field_element_to_bytes(x));
    res.append(&mut field_element_to_bytes(y));
    res
}

/// Returns the point P corresponding
/// to the canonical representation ostr, or INVALID if ostr is not
/// a valid output of point_to_octets. This operation is also
/// known as deserialization.
///
/// This function accepts uncompressed (96 bytes) or compressed (48 bytes) representations.
pub fn octets_to_point_e1(octets: &Octets) -> Result<G1AffinePoint, BLSError> {
    match octets.len() {
        G1_COMPRESSED_POINT_SIZE => {
            if !is_compressed(octets) {
                return Err(BLSError::CompressedBitNotSet);
            }
            if is_at_infinity(octets) {
                if octets == G1_COMPRESSED_POINT_AT_INFINITY {
                    return Ok(G1AffinePoint::identity());
                } else {
                    return Err(BLSError::MalformedOctets);
                }
            }
            let uses_largest_y = uses_largest_y(octets);
            let x_bytes: [u8; G1_COMPRESSED_POINT_SIZE] = mask_first_3_bits(octets)
                .try_into()
                .expect("sized in surrounding match");
            let x = BLSFq::from_be_bytes_mod_order(&x_bytes);
            let (y1, y2) =
                G1AffinePoint::get_ys_from_x_unchecked(x).ok_or(BLSError::BadXCoordinate)?;

            if uses_largest_y {
                create_g1_point(x, y2)
            } else {
                create_g1_point(x, y1)
            }
        }
        G1_UNCOMPRESSED_POINT_SIZE => {
            if is_compressed(octets) {
                return Err(BLSError::CompressedBitSet);
            }
            if is_at_infinity(octets) {
                if octets == G1_UNCOMPRESSED_POINT_AT_INFINITY {
                    return Ok(G1AffinePoint::identity());
                } else {
                    return Err(BLSError::MalformedOctets);
                }
            }
            let xy_bytes: [u8; G1_UNCOMPRESSED_POINT_SIZE] = mask_first_3_bits(octets)
                .try_into()
                .expect("sized in surrounding match");
            let x = BLSFq::from_be_bytes_mod_order(&xy_bytes[..G1_UNCOMPRESSED_POINT_SIZE / 2]);
            let y = BLSFq::from_be_bytes_mod_order(&xy_bytes[G1_UNCOMPRESSED_POINT_SIZE / 2..]);
            create_g1_point(x, y)
        }
        _ => Err(BLSError::BadOctetLength),
    }
}

/// Returns the canonical
/// representation of the point P as an octet string. This
/// operation is also known as serialization.
///
/// The canonical representation is the compressed form.
pub fn point_to_octets_e2(p: G2AffinePoint) -> Octets {
    if p.is_zero() {
        let mut infinity = vec![0; 96];
        infinity[0] = 0b11000000;
        return infinity;
    }

    let (x, y) = p.xy().expect("p is not at infinity, we checked above");
    // Possible y coordinates, in lexicographical order
    let (_, y2) = &G2AffinePoint::get_ys_from_x_unchecked(*x).expect("p is a G2 point, on curve");

    let mut compressed = vec![];
    compressed.append(&mut field_element_to_bytes(&x.c1));
    compressed.append(&mut field_element_to_bytes(&x.c0));

    // Set the first bit to indicate compressed form
    // Okay to unwrap() here, `compressed` is at least 1 bytes long.
    compressed[0] = compressed.first().map(|b| b | 0b10000000).unwrap();

    if y == y2 {
        // If the y coordinate is the second (in lexicographical order), set the 3rd most significant bit
        // Okay to unwrap() here, `compressed` is at least 1 bytes long.
        compressed[0] = compressed.first().map(|b| b | 0b00100000).unwrap();
    }
    compressed
}

/// Similar to `point_to_octets_E2, but return the uncompressed representation of P.
pub fn point_to_octets_uncompressed_e2(p: G2AffinePoint) -> Octets {
    //let p_prime: types::G2ProjectivePoint = p.into();
    if let Some((x, y)) = p.xy() {
        let mut w: Vec<u8> = vec![];

        w.append(&mut field_element_to_bytes(&x.c1));
        w.append(&mut field_element_to_bytes(&x.c0));
        w.append(&mut field_element_to_bytes(&y.c1));
        w.append(&mut field_element_to_bytes(&y.c0));
        w
    } else {
        let mut infinity = vec![0; 192];
        infinity[0] = 0b01000000;
        infinity
    }
}

/// Returns the point P corresponding
/// to the canonical representation ostr, or INVALID if ostr is not
/// a valid output of point_to_octets. This operation is also
/// known as deserialization.
///
/// This function accepts uncompressed (192 bytes) or compressed (96 bytes) representations.
pub fn octets_to_point_e2(octets: &Octets) -> Result<G2AffinePoint, BLSError> {
    match octets.len() {
        G2_COMPRESSED_POINT_SIZE => {
            if !is_compressed(octets) {
                return Err(BLSError::CompressedBitNotSet);
            }
            if is_at_infinity(octets) {
                if octets == G2_COMPRESSED_POINT_AT_INFINITY {
                    return Ok(G2AffinePoint::identity());
                } else {
                    return Err(BLSError::MalformedOctets);
                }
            }
            let uses_largest_y = uses_largest_y(octets);
            let x_bytes: [u8; G2_COMPRESSED_POINT_SIZE] = mask_first_3_bits(octets)
                .try_into()
                .expect("sized in surrounding match");
            let x_c1 = BLSFq::from_be_bytes_mod_order(&x_bytes[..G2_COMPRESSED_POINT_SIZE / 2]);
            let x_c0 = BLSFq::from_be_bytes_mod_order(&x_bytes[G2_COMPRESSED_POINT_SIZE / 2..]);

            let x = BLSFq2::new(x_c0, x_c1);
            let (y1, y2) =
                G2AffinePoint::get_ys_from_x_unchecked(x).ok_or(BLSError::BadXCoordinate)?;

            if uses_largest_y {
                create_g2_point(x, y2)
            } else {
                create_g2_point(x, y1)
            }
        }
        G2_UNCOMPRESSED_POINT_SIZE => {
            if is_compressed(octets) {
                return Err(BLSError::CompressedBitSet);
            }
            if is_at_infinity(octets) {
                if octets == G2_UNCOMPRESSED_POINT_AT_INFINITY {
                    return Ok(G2AffinePoint::identity());
                } else {
                    return Err(BLSError::MalformedOctets);
                }
            }
            let xy_bytes: [u8; G2_UNCOMPRESSED_POINT_SIZE] = mask_first_3_bits(octets)
                .try_into()
                .expect("sized in surrounding match");
            let chunk_size = G2_UNCOMPRESSED_POINT_SIZE / 4;
            let x_c1 = BLSFq::from_be_bytes_mod_order(&xy_bytes[..chunk_size]);
            let x_c0 = BLSFq::from_be_bytes_mod_order(&xy_bytes[chunk_size..2 * chunk_size]);
            let y_c1 = BLSFq::from_be_bytes_mod_order(&xy_bytes[2 * chunk_size..3 * chunk_size]);
            let y_c0 = BLSFq::from_be_bytes_mod_order(&xy_bytes[3 * chunk_size..]);

            let x = BLSFq2::new(x_c0, x_c1);
            let y = BLSFq2::new(y_c0, y_c1);

            create_g2_point(x, y)
        }
        _ => Err(BLSError::BadOctetLength),
    }
}

// Function to bubble up errors when we create G2 point.
// `G2AffinePoint::new` panics :(
fn create_g1_point(x: BLSFq, y: BLSFq) -> Result<G1AffinePoint, BLSError> {
    let p = G1AffinePoint::new_unchecked(x, y);
    if !p.is_on_curve() {
        return Err(BLSError::PointNotOnCurve);
    }
    if !p.is_in_correct_subgroup_assuming_on_curve() {
        return Err(BLSError::PointInIncorrectSubgroup);
    }
    Ok(p)
}

// Function to bubble up errors when we create G2 point.
// `G2AffinePoint::new` panics by default! :(
fn create_g2_point(x: BLSFq2, y: BLSFq2) -> Result<G2AffinePoint, BLSError> {
    let p = G2AffinePoint::new_unchecked(x, y);
    if !p.is_on_curve() {
        return Err(BLSError::PointNotOnCurve);
    }
    if !p.is_in_correct_subgroup_assuming_on_curve() {
        return Err(BLSError::PointInIncorrectSubgroup);
    }
    Ok(p)
}

fn mask_first_3_bits(octets: &Octets) -> Octets {
    let mut res = octets.clone();
    res[0] = res
        .first()
        .map(|b| b & 0b00011111)
        .expect("res is at least 1 bytes long");
    res
}

/// Convenience function to check whether a octet string indicates compression
fn is_compressed(octets: &Octets) -> bool {
    octets[0] & 0b10000000 > 0
}

/// Convenience function to check whether a octet string indicates a point at infinity
fn is_at_infinity(octets: &Octets) -> bool {
    octets[0] & 0b01000000 > 0
}

/// Convenience function to check whether a octet string indicates the largest y coordinate is used
/// (only relevant when compression is used AND when the point isn't infinity)
fn uses_largest_y(octets: &Octets) -> bool {
    octets[0] & 0b00100000 > 0
}

/// Awkward helper to convert a field element into bytes
/// We use the to_string() function to get the underlying integer (as a String)
/// Then parse it again with BigInt to extract bytes out.
/// I'm _sure_ there's gotta be a better way, but a simple element.0.to_bytes_be() doesn't seem to be good enough!
fn field_element_to_bytes(element: &BLSFq) -> Vec<u8> {
    let i = BigInt::parse_bytes(element.to_string().as_bytes(), 10)
        .expect("Field Elements have valid coordinates");
    let mut res = i.to_signed_bytes_be();

    // Pad to the nearest multiple of 8
    if res.len() % 8 != 0 {
        res.insert(0, 0);
    }
    res
}

#[cfg(test)]
mod test {
    use super::*;
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
    fn test_octets_to_point_e2() {
        assert_eq!(
            octets_to_point_e2(&G2_UNCOMPRESSED_POINT_AT_INFINITY.to_vec()).unwrap(),
            G2AffinePoint::identity()
        );
        assert_eq!(
            octets_to_point_e2(&G2_COMPRESSED_POINT_AT_INFINITY.to_vec()).unwrap(),
            G2AffinePoint::identity()
        );
        assert_eq!(
            octets_to_point_e2(&hex!("
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
}
