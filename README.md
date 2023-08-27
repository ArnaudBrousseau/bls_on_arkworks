# BLS on Arkworks

This crate implements the latest IRTF draft for BLS signatures: [`draft-irtf-cfrg-bls-signature-05`](https://www.ietf.org/archive/id/draft-irtf-cfrg-bls-signature-05.html) with the [Arkworks crates](https://github.com/arkworks-rs/).

## Goals

In order of importance:
- **Correctness**: above all, this library should be correct. This is why it's tested with a strong suite of unit tests. It's also tested against the cases from [ethereum/bls12-381-tests](https://github.com/ethereum/bls12-381-tests). See [tests/lib.rs](./tests/lib.rs).
- **Spec compliance**: lots of effort went into documentation of each core function such that it's linked to the relevant specification section, and the code references the steps from the spec instructions. Types, interfaces,  function names are as close as it gets to the spec. Places which deviate from the spec are marked with `XXX`.
- **Compatibility with Ethereum**: BLS signatures produced by this crate should work with Ethereum (choice of variant explained [here](https://github.com/ethereum/consensus-specs/blob/v1.0.0/specs/phase0/beacon-chain.md#bls-signatures)).
- **Simplicity**: while the Domain-Separation-Tag isn't hardcoded (we need flexibility to test against multiple types of test vectors), we are hardcoding the choice of elliptic curve (BLS12-381), hash function (SHA-256), and variant (minimal-pubkey-size).

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