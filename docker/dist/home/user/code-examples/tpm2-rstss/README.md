# Rust TPM2 Random Number Generator

A simple Rust project that uses `tss-esapi` to generate random numbers from a TPM (Trusted Platform Module).

## Requirements

- [Rust](https://www.rust-lang.org/) (at least version 1.XX)
- TPM2-TSS libraries (installation guide [here](https://github.com/tpm2-software/tpm2-tss))
- `tss-esapi` crate (already included in the project)

## Running

To run the project and generate random numbers from the TPM, execute the following command:

```bash
cargo run
```

The program will attempt to retrieve 8 bytes of random numbers from the TPM and print them to the console.

