use ark_ff::BigInteger;
use bls_on_arkworks::types::{Octets, SecretKey};
use std::fs;

pub fn aggregate() -> Vec<AggregateCase> {
    let paths = fs::read_dir("tests/aggregate").unwrap();
    paths
        .map(|p| {
            let path = p.unwrap().path();
            let content = fs::read_to_string(path.clone()).unwrap();
            let parsed_content = json::parse(&content).unwrap();
            let signatures = parsed_content["input"]
                .members()
                .map(|pk| prefixed_hex_string_to_bytes(&pk.to_string()))
                .collect::<Vec<Octets>>();
            let expected_signature = if parsed_content["output"].is_null() {
                vec![]
            } else {
                prefixed_hex_string_to_bytes(&parsed_content["output"].to_string())
            };
            let name = path.to_str().unwrap().to_string();

            return AggregateCase {
                name,
                signatures,
                expected_signature,
            };
        })
        .collect()
}

pub fn batch_verify() -> Vec<BatchVerifyCase> {
    let paths = fs::read_dir("tests/batch_verify").unwrap();
    paths
        .map(|p| {
            let path = p.unwrap().path();
            let content = fs::read_to_string(path.clone()).unwrap();
            let parsed_content = json::parse(&content).unwrap();
            let pubkeys = parsed_content["input"]["pubkeys"]
                .members()
                .map(|pk| prefixed_hex_string_to_bytes(&pk.to_string()))
                .collect::<Vec<Octets>>();
            let msgs = parsed_content["input"]["messages"]
                .members()
                .map(|m| prefixed_hex_string_to_bytes(&m.to_string()))
                .collect::<Vec<Octets>>();
            let sigs = parsed_content["input"]["signatures"]
                .members()
                .map(|s| prefixed_hex_string_to_bytes(&s.to_string()))
                .collect::<Vec<Octets>>();

            return BatchVerifyCase {
                name: path.to_str().unwrap().to_string(),
                public_keys: pubkeys,
                messages: msgs,
                signatures: sigs,
                should_be_valid: parsed_content["output"].as_bool().unwrap(),
            };
        })
        .collect()
}

pub fn deserialization_g1() -> Vec<DeserializationCase> {
    let paths = fs::read_dir("tests/deserialization_G1").unwrap();
    paths
        .map(|p| {
            let path = p.unwrap().path();
            let content = fs::read_to_string(path.clone()).unwrap();
            let parsed_content = json::parse(&content).unwrap();

            return DeserializationCase {
                name: path.to_str().unwrap().to_string(),
                octets: hex::decode(parsed_content["input"]["pubkey"].to_string()).unwrap(),
                should_be_valid: parsed_content["output"].as_bool().unwrap(),
            };
        })
        .collect()
}

pub fn deserialization_g2() -> Vec<DeserializationCase> {
    let paths = fs::read_dir("tests/deserialization_G2").unwrap();
    paths
        .map(|p| {
            let path = p.unwrap().path();
            let content = fs::read_to_string(path.clone()).unwrap();
            let parsed_content = json::parse(&content).unwrap();

            return DeserializationCase {
                name: path.to_str().unwrap().to_string(),
                octets: hex::decode(parsed_content["input"]["signature"].to_string()).unwrap(),
                should_be_valid: parsed_content["output"].as_bool().unwrap(),
            };
        })
        .collect()
}

pub fn aggregate_verify() -> Vec<AggregateVerifyCase> {
    let paths = fs::read_dir("tests/aggregate_verify").unwrap();
    paths
        .map(|p| {
            let path = p.unwrap().path();
            let content = fs::read_to_string(path.clone()).unwrap();
            let parsed_content = json::parse(&content).unwrap();
            let pubkeys = parsed_content["input"]["pubkeys"]
                .members()
                .map(|pk| prefixed_hex_string_to_bytes(&pk.to_string()))
                .collect::<Vec<Octets>>();
            let messages = parsed_content["input"]["messages"]
                .members()
                .map(|pk| prefixed_hex_string_to_bytes(&pk.to_string()))
                .collect::<Vec<Octets>>();

            return AggregateVerifyCase {
                name: path.to_str().unwrap().to_string(),
                public_keys: pubkeys,
                messages: messages,
                signature: prefixed_hex_string_to_bytes(
                    &parsed_content["input"]["signature"].to_string(),
                ),
                should_be_valid: parsed_content["output"].as_bool().unwrap(),
            };
        })
        .collect()
}

pub fn fast_aggregate_verify() -> Vec<AggregateVerifyCase> {
    let paths = fs::read_dir("tests/fast_aggregate_verify").unwrap();
    paths
        .map(|p| {
            let path = p.unwrap().path();
            let content = fs::read_to_string(path.clone()).unwrap();
            let parsed_content = json::parse(&content).unwrap();
            let pubkeys = parsed_content["input"]["pubkeys"]
                .members()
                .map(|pk| prefixed_hex_string_to_bytes(&pk.to_string()))
                .collect::<Vec<Octets>>();
            let message =
                prefixed_hex_string_to_bytes(&parsed_content["input"]["message"].to_string());

            return AggregateVerifyCase {
                name: path.to_str().unwrap().to_string(),
                public_keys: pubkeys.clone(),
                messages: vec![message; pubkeys.len()],
                signature: prefixed_hex_string_to_bytes(
                    &parsed_content["input"]["signature"].to_string(),
                ),
                should_be_valid: parsed_content["output"].as_bool().unwrap(),
            };
        })
        .collect()
}

pub fn hash_to_g2() -> Vec<HashToG2Case> {
    let paths = fs::read_dir("tests/hash_to_G2").unwrap();
    paths
        .map(|p| {
            let path = p.unwrap().path();
            let content = fs::read_to_string(path.clone()).unwrap();
            let parsed_content = json::parse(&content).unwrap();

            let x = &parsed_content["output"]["x"].to_string();
            let y = &parsed_content["output"]["y"].to_string();

            let x_parts = x.split(",").collect::<Vec<&str>>();
            let (x_c0, x_c1) = (x_parts[0], x_parts[1]);
            let y_parts = y.split(",").collect::<Vec<&str>>();
            let (y_c0, y_c1) = (y_parts[0], y_parts[1]);

            return HashToG2Case {
                name: path.to_str().unwrap().to_string(),
                message: parsed_content["input"]["msg"]
                    .to_string()
                    .as_bytes()
                    .to_vec(),
                expected_x_c0: prefixed_hex_string_to_bytes(x_c0),
                expected_x_c1: prefixed_hex_string_to_bytes(x_c1),
                expected_y_c0: prefixed_hex_string_to_bytes(y_c0),
                expected_y_c1: prefixed_hex_string_to_bytes(y_c1),
            };
        })
        .collect()
}

pub fn sign_cases() -> Vec<SignCase> {
    let paths = fs::read_dir("tests/sign").unwrap();
    paths
        .map(|p| {
            let path = p.unwrap().path();
            let content = fs::read_to_string(path.clone()).unwrap();
            let parsed_content = json::parse(&content).unwrap();
            let private_key =
                prefixed_hex_string_to_secret_key(&parsed_content["input"]["privkey"].to_string());
            let message =
                prefixed_hex_string_to_bytes(&parsed_content["input"]["message"].to_string());
            let expected_signature = if parsed_content["output"].is_null() {
                vec![]
            } else {
                prefixed_hex_string_to_bytes(&parsed_content["output"].to_string())
            };

            return SignCase {
                name: path.to_str().unwrap().to_string(),
                private_key,
                message,
                expected_signature,
            };
        })
        .collect()
}

#[derive(Clone, Debug)]
pub struct AggregateCase {
    pub name: String,
    pub signatures: Vec<Octets>,
    pub expected_signature: Octets,
}

#[derive(Clone, Debug)]
pub struct BatchVerifyCase {
    pub name: String,
    pub public_keys: Vec<Octets>,
    pub messages: Vec<Octets>,
    pub signatures: Vec<Octets>,
    pub should_be_valid: bool,
}

#[derive(Clone, Debug)]
pub struct AggregateVerifyCase {
    pub name: String,
    pub public_keys: Vec<Octets>,
    pub messages: Vec<Octets>,
    pub signature: Octets,
    pub should_be_valid: bool,
}

#[derive(Clone, Debug)]
pub struct DeserializationCase {
    pub name: String,
    pub octets: Octets,
    pub should_be_valid: bool,
}

#[derive(Clone, Debug)]
pub struct HashToG2Case {
    pub name: String,
    pub message: Octets,
    pub expected_x_c0: Octets,
    pub expected_x_c1: Octets,
    pub expected_y_c0: Octets,
    pub expected_y_c1: Octets,
}

#[derive(Clone, Debug)]
pub struct SignCase {
    pub name: String,
    pub private_key: SecretKey,
    pub message: Octets,
    pub expected_signature: Octets,
}

/**
 * Below: utils to parse hex-encoded strings
 */

// 0x1234 -> [0x12, 0x34]
fn prefixed_hex_string_to_bytes(s: &str) -> Vec<u8> {
    hex::decode(s.replace("0x", "")).unwrap()
}

// 0x1234 -> 4660
fn prefixed_hex_string_to_secret_key(s: &str) -> SecretKey {
    // Remove the "0x" prefix
    let mut non_prefixed = s.to_string();
    non_prefixed.remove(0);
    non_prefixed.remove(0);

    let bytes = hex::decode(non_prefixed).unwrap();
    let mut bits = vec![false; 8*bytes.len()];
    for (i, byte) in bytes.iter().enumerate() {
        bits[8*i] = byte & 0b10000000 > 0;
        bits[8*i+1] = byte & 0b01000000 > 0;
        bits[8*i+2] = byte & 0b00100000 > 0;
        bits[8*i+3] = byte & 0b00010000 > 0;
        bits[8*i+4] = byte & 0b00001000 > 0;
        bits[8*i+5] = byte & 0b00000100 > 0;
        bits[8*i+6] = byte & 0b00000010 > 0;
        bits[8*i+7] = byte & 0b00000001 > 0;
    }

    SecretKey::from_bits_be(&bits)
}
