use bls_on_arkworks as core;

mod cases;

#[test]
fn test_aggregate() {
    for c in cases::aggregate() {
        let signature = core::aggregate(&c.signatures);
        if c.expected_signature.len() > 1 {
            assert_eq!(signature.unwrap(), c.expected_signature, "{}", c.name);
        } else {
            // When the expected signature is empty, we expect an error
            // this is the case where 0 signatures are passed as input
            // The Ethereum test vector is [] -> null but IMO returning an error is more correct
            // `null` shouldn't be a valid signature / result returned from `aggregate`.
            assert_eq!(
                signature.unwrap_err().to_string(),
                "Cannot aggregate signatures: no signatures were passed in".to_string(),
            )
        }
    }
}

#[test]
fn test_aggregate_verify() {
    for c in cases::aggregate_verify() {
        let is_valid = core::aggregate_verify(
            c.public_keys,
            c.messages,
            &c.signature,
            &core::DST_ETHEREUM.as_bytes().to_vec(),
        );
        assert_eq!(is_valid, c.should_be_valid, "{}", c.name);
    }
}

#[test]
fn test_fast_aggregate_verify() {
    for c in cases::fast_aggregate_verify() {
        let is_valid = core::aggregate_verify(
            c.public_keys,
            c.messages,
            &c.signature,
            &core::DST_ETHEREUM.as_bytes().to_vec(),
        );
        assert_eq!(is_valid, c.should_be_valid, "{}", c.name);
    }
}

#[test]
fn test_batch_verify() {
    for c in cases::batch_verify() {
        // No "batch verify" in this library (for now).
        // We just iterate over each (public key, message, signature) triplet instead.
        let mut is_valid = true;
        for i in 0..c.public_keys.len() {
            is_valid = is_valid
                && core::verify(
                    &c.public_keys[i],
                    &c.messages[i],
                    &c.signatures[i],
                    &core::DST_ETHEREUM.as_bytes().to_vec(),
                );
        }
        assert_eq!(is_valid, c.should_be_valid, "{}", c.name);
    }
}

#[test]
fn test_deserialization() {
    for c in cases::deserialization_g1() {
        let res = core::pubkey_to_point(&c.octets);
        if c.should_be_valid {
            assert_eq!(true, res.is_ok(), "{}: got err: {:?}", c.name, res);
        } else {
            assert_eq!(false, res.is_ok(), "{} should not be valid", c.name);
        }
    }

    for c in cases::deserialization_g2() {
        let res = core::signature_to_point(&c.octets);
        if c.should_be_valid {
            assert_eq!(true, res.is_ok(), "{}: got err: {:?}", c.name, res);
        } else {
            assert_eq!(false, res.is_ok(), "{} should not be valid", c.name);
        }
    }
}

#[test]
fn test_hash_to_g2() {
    // See https://github.com/ethereum/bls12-381-tests/blob/v0.1.2/main.py#L102
    let dst = "QUUX-V01-CS02-with-BLS12381G2_XMD:SHA-256_SSWU_RO_"
        .as_bytes()
        .to_vec();

    for c in cases::hash_to_g2() {
        let point = core::hash_to_point(&c.message, &dst);

        let mut signature_bytes: Vec<u8> = vec![];
        signature_bytes.extend(c.expected_x_c1);
        signature_bytes.extend(c.expected_x_c0);
        signature_bytes.extend(c.expected_y_c1);
        signature_bytes.extend(c.expected_y_c0);

        let expected_point = core::signature_to_point(&signature_bytes).unwrap();

        assert_eq!(point, expected_point, "{}", c.name);
    }
}

#[test]
fn test_sign() {
    let dst = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_"
        .as_bytes()
        .to_vec();
    for c in cases::sign_cases() {
        let signature = core::sign(c.private_key, &c.message, &dst);

        if c.expected_signature.len() == 0 {
            assert_eq!(
                signature.unwrap_err().to_string(),
                "Signature point is not in the correct subgroup. Please check the passed in secret key value.",
            );
        } else {
            assert_eq!(
                signature.unwrap(),
                c.expected_signature,
                "{} (len: {})",
                c.name,
                c.message.len()
            );
        }
    }
}
