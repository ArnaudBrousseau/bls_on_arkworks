# BLS on Arkworks

[![MIT licensed](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE) [![crates.io](https://img.shields.io/crates/v/bls_on_arkworks.svg)](https://crates.io/crates/bls_on_arkworks) [![Documentation](https://docs.rs/bls_on_arkworks/badge.svg)](https://docs.rs/bls_on_arkworks)

This crate implements the latest IRTF draft for BLS signatures: [`draft-irtf-cfrg-bls-signature-05`](https://www.ietf.org/archive/id/draft-irtf-cfrg-bls-signature-05.html) with the [Arkworks crates](https://github.com/arkworks-rs/).

## Goals

In order of importance:
- **Correctness**: above all, this library should be correct. This is why it's tested with a strong suite of unit tests. It's also tested against the cases from [ethereum/bls12-381-tests](https://github.com/ethereum/bls12-381-tests). See [tests/lib.rs](./tests/lib.rs).
- **Spec compliance**: lots of effort went into documentation of each core function such that it's linked to the relevant specification section, and the code references the steps from the spec instructions. Types, interfaces,  function names are as close as it gets to the spec. Places which deviate from the spec are marked with `XXX`.
- **Compatibility with Ethereum**: BLS signatures produced by this crate should work with Ethereum (choice of variant explained [here](https://github.com/ethereum/consensus-specs/blob/v1.0.0/specs/phase0/beacon-chain.md#bls-signatures)).
- **Simplicity**: while the Domain-Separation-Tag isn't hardcoded (we need flexibility to test against multiple types of test vectors), we are hardcoding the choice of elliptic curve (BLS12-381), hash function (SHA-256), and variant (minimal-pubkey-size).

## Usage

### Basic Signature and Verification

```rust
use bls_on_arkworks as bls;
use rand_core::{RngCore, OsRng};

// We start with 64 bytes of good randomness from the OS.
// ikm has to be at least 32 bytes long to be secure, but can be longer.
let mut ikm = [0u8; 64];
OsRng.fill_bytes(&mut ikm);

// Build a secret key from the random bytes.
// The secret key is a field element.
let secret_key = bls::keygen(&ikm.to_vec());

// Sign a message with the Ethereum Domain Separation Tag
let message = "message to sign".as_bytes().to_vec();
let dst = bls::DST_ETHEREUM.as_bytes().to_vec();

let signature = bls::sign(secret_key, &message, &dst).unwrap();


// Derive a public key from our secret key above...
let public_key = bls::sk_to_pk(secret_key);
// ...and verify the signature we just produced.
let verified = bls::verify(&public_key, &message, &signature, &dst);
```

### Aggregates

This crate supports aggregate signatures and verification:

```rust
use bls_on_arkworks as bls;

// Load known hex bytes (instead of generating a new random secret key like in the previous example)
let sk1 = bls::os2ip(
    &vec![
        0x32, 0x83, 0x88, 0xaf, 0xf0, 0xd4, 0xa5, 0xb7,
        0xdc, 0x92, 0x05, 0xab, 0xd3, 0x74, 0xe7, 0xe9,
        0x8f, 0x3c, 0xd9, 0xf3, 0x41, 0x8e, 0xdb, 0x4e,
        0xaf, 0xda, 0x5f, 0xb1, 0x64, 0x73, 0xd2, 0x16,
    ]
);
let sk2 = bls::os2ip(
    &vec![
        0x47, 0xb8, 0x19, 0x2d, 0x77, 0xbf, 0x87, 0x1b,
        0x62, 0xe8, 0x78, 0x59, 0xd6, 0x53, 0x92, 0x27,
        0x25, 0x72, 0x4a, 0x5c, 0x03, 0x1a, 0xfe, 0xab,
        0xc6, 0x0b, 0xce, 0xf5, 0xff, 0x66, 0x51, 0x38,
    ]
);

// Sign a message with the Ethereum Domain Separation Tag
let dst = bls::DST_ETHEREUM.as_bytes().to_vec();
let message = "message to be signed by multiple parties".as_bytes().to_vec();

let first_signature = bls::sign(sk1, &message, &dst).unwrap();
let second_signature = bls::sign(sk2, &message, &dst).unwrap();

let aggregate = bls::aggregate(&vec![first_signature, second_signature]).unwrap();

// Derive a public key from our secret keys...
let pk1 = bls::sk_to_pk(sk1);
let pk2 = bls::sk_to_pk(sk2);
// ...and verify the aggregate signature we produced.
let verified = bls::aggregate_verify(
    vec![pk1, pk2],
    vec![message.clone(), message],
    &aggregate,
    &dst);
```

### Error handling

All errors are consolidated under a single `BLSError` enum. We favor `Result`-based interfaces over internal `panic`s.

## Testing

To run tests:

```sh
$ cargo test
```

The JSON test case definitions in [`tests/*`](./tests/) were taken from [ethereum/bls12-381-tests@v0.1.2](https://github.com/ethereum/bls12-381-tests/releases/tag/v0.1.2).

## Linting (Clippy)

```sh
$ cargo clippy -- -D warnings
```

## Formatting
```sh
$ cargo fmt --
```