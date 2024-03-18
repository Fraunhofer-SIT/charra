#!/bin/bash

# end script with error message
exit_with_error() {
    echo "Error: $1"
    exit 1
}

mkdir tpm_keys
cd tpm_keys

# create endorsement key
tpm2_createek \
    --ek-context rsa_ek.ctx \
    --key-algorithm rsa \
    --public rsa_ek.pub || exit_with_error "failed to create endorsement key"

echo "created endorsement key"

# create attestation key
tpm2_createak \
    --ek-context rsa_ek.ctx \
    --ak-context rsa_ak.ctx \
    --key-algorithm rsa \
    --hash-algorithm sha256 \
    --signing-algorithm rsapss \
    --public rsa_ak.pub \
    --private rsa_ak.priv \
    --ak-name rsa_ak.name || exit_with_error "failed to create attestation key"

echo "created attestation key"

tpm2_flushcontext -t

cd ..
