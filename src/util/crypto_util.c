/* SPDX-License-Identifier: BSD-3-Clause */
/*****************************************************************************
 * Copyright 2019, Fraunhofer Institute for Secure Information Technology SIT.
 * All rights reserved.
 ****************************************************************************/

/**
 * @file crypto_util.c
 * @author Michael Eckel (michael.eckel@sit.fraunhofer.de)
 * @brief Provides IMA related crypto functions.
 * @version 0.1
 * @date 2019-12-22
 *
 * @copyright Copyright 2019, Fraunhofer Institute for Secure Information
 * Technology SIT. All rights reserved.
 *
 * @license BSD 3-Clause "New" or "Revised" License (SPDX-License-Identifier:
 * BSD-3-Clause).
 */

#include "crypto_util.h"

/* system includes */
#include <psa/crypto.h>
#include <tss2/tss2_tpm2_types.h>

#include "../common/charra_error.h"
#include "../util/charra_util.h"
#include "../util/io_util.h"
#include "../util/parser_util.h"
#include "psa_key_util.h"

/* hash algorithm strings */
#define CHARRA_SHA1_STR "sha1"
#define CHARRA_SHA256_STR "sha256"
#define CHARRA_SHA384_STR "sha384"
#define CHARRA_SHA512_STR "sha512"
#define CHARRA_RSASSA_STR "rsassa"
#define CHARRA_RSAPSS_STR "rsapss"
#define CHARRA_ECDSA_STR "ecdsa"

typedef enum {
    CHARRA_TPM_UNKNOWN_ALGORITHM = 0,
    CHARRA_TPM_HASH_ALGORITHM = 1,
    CHARRA_TPM_SIGNATURE_SCHEME = 2,
} charra_tpm_alg_type;

typedef struct {
    const char* const name;
    const TPM2_ALG_ID alg_id;
    const charra_tpm_alg_type alg_type;
} charra_tpm2_alg_t;

typedef struct {
    const char* name;
    TPM2_ALG_ID alg_id;
    charra_tpm_alg_type alg_type;
} charra_tpm2_alg_search_info_t;

static TPM2_ALG_ID charra_find_matching_alg_id(
        const charra_tpm2_alg_search_info_t* const search_information) {
    /* static initialization */
    static const charra_tpm2_alg_t tpm2_algs[] = {
            /* supported hash algorithms */
            {CHARRA_SHA1_STR, TPM2_ALG_SHA1, CHARRA_TPM_HASH_ALGORITHM},
            {CHARRA_SHA256_STR, TPM2_ALG_SHA256, CHARRA_TPM_HASH_ALGORITHM},
            {CHARRA_SHA384_STR, TPM2_ALG_SHA384, CHARRA_TPM_HASH_ALGORITHM},
            {CHARRA_SHA512_STR, TPM2_ALG_SHA512, CHARRA_TPM_HASH_ALGORITHM},
            /* supported signature schemes */
            {CHARRA_RSASSA_STR, TPM2_ALG_RSASSA, CHARRA_TPM_SIGNATURE_SCHEME},
            {CHARRA_RSAPSS_STR, TPM2_ALG_RSAPSS, CHARRA_TPM_SIGNATURE_SCHEME},
            {CHARRA_ECDSA_STR, TPM2_ALG_ECDSA, CHARRA_TPM_SIGNATURE_SCHEME},
    };
    static const size_t tpm2_algs_len =
            sizeof(tpm2_algs) / sizeof(charra_tpm2_alg_t);

    /* function start */
    if (search_information == NULL ||
            search_information->alg_type == CHARRA_TPM_UNKNOWN_ALGORITHM) {
        return TPM2_ALG_NULL;
    }
    size_t algorithm_name_len = 0;

    if (search_information->name != NULL) {
        algorithm_name_len = strlen(search_information->name);
    }

    for (size_t i = 0; i < tpm2_algs_len; i++) {
        const charra_tpm2_alg_t* const tpm2_alg = &tpm2_algs[i];
        if (search_information->alg_type != tpm2_alg->alg_type) {
            continue;  // skip if types do not match
        }
        if (search_information->name != NULL &&
                strncmp(search_information->name, tpm2_alg->name,
                        algorithm_name_len) == 0) {
            return tpm2_alg->alg_id;  // found matching algorithm
        }
        if (search_information->alg_id == tpm2_alg->alg_id) {
            return tpm2_alg->alg_id;  // found matching algorithm by ID
        }
    }

    return TPM2_ALG_NULL;
}

static TPM2_ALG_ID charra_tpm_algo_from_str(
        const char* const alg_str, charra_tpm_alg_type alg_type) {
    if (alg_str == NULL || alg_type == CHARRA_TPM_UNKNOWN_ALGORITHM) {
        return TPM2_ALG_NULL;  // handle null pointer gracefully
    }

    CHARRA_RC rc = CHARRA_RC_SUCCESS;
    uint64_t alg_id_value = 0;
    charra_tpm2_alg_search_info_t search_info = {
            .name = NULL, .alg_id = TPM2_ALG_NULL, .alg_type = alg_type};

    rc = parse_ulong(alg_str, 0, &alg_id_value);
    if (rc == CHARRA_RC_SUCCESS) {
        if (alg_id_value > UINT16_MAX) {
            /* uint16 overflow */
            return TPM2_ALG_NULL;
        }
        /* numeric value -> search by algorithm ID */
        search_info.alg_id = (TPM2_ALG_ID)alg_id_value;
    } else {
        /* no numeric value -> search by string name */
        search_info.name = alg_str;
    }
    return charra_find_matching_alg_id(&search_info);
}

charra_tpm_pcr_bank_index charra_tpm_pcr_bank_index_from_str(
        const char* const pcr_bank) {
    if (pcr_bank == NULL) {
        return CHARRA_TPM_PCR_BANK_UNKNOWN;  // handle null pointers gracefully
    }

    TPM2_ALG_ID alg_id = TPM2_ALG_NULL;

    alg_id = charra_tpm_algo_from_str(pcr_bank, CHARRA_TPM_HASH_ALGORITHM);

    switch (alg_id) {
    case TPM2_ALG_SHA1:
        return CHARRA_TPM_PCR_BANK_SHA1;
    case TPM2_ALG_SHA256:
        return CHARRA_TPM_PCR_BANK_SHA256;
    case TPM2_ALG_SHA384:
        return CHARRA_TPM_PCR_BANK_SHA384;
    case TPM2_ALG_SHA512:
        return CHARRA_TPM_PCR_BANK_SHA512;
    default:
        return CHARRA_TPM_PCR_BANK_UNKNOWN;
    }
}

TPM2_ALG_ID charra_tpm_hash_algorithm_from_str(
        const char* const hash_algorithm) {
    if (hash_algorithm == NULL) {
        return TPM2_ALG_NULL;  // handle null pointers gracefully
    }

    return charra_tpm_algo_from_str(hash_algorithm, CHARRA_TPM_HASH_ALGORITHM);
}

psa_algorithm_t charra_psa_hash_algorithm_from_tpm2_alg_id(
        TPM2_ALG_ID hash_alg_id) {
    switch (hash_alg_id) {
    case TPM2_ALG_SHA1:
        return PSA_ALG_SHA_1;
    case TPM2_ALG_SHA256:
        return PSA_ALG_SHA_256;
    case TPM2_ALG_SHA384:
        return PSA_ALG_SHA_384;
    case TPM2_ALG_SHA512:
        return PSA_ALG_SHA_512;
    default:
        return PSA_ALG_NONE;
    }
}

TPM2_ALG_ID charra_signature_scheme_from_str(
        const char* const signature_scheme) {
    if (signature_scheme == NULL) {
        return TPM2_ALG_NULL;  // handle null pointers gracefully
    }

    return charra_tpm_algo_from_str(
            signature_scheme, CHARRA_TPM_SIGNATURE_SCHEME);
}

CHARRA_RC charra_crypto_hash(psa_algorithm_t hash_algo,
        const uint8_t* const data, const size_t data_len,
        uint8_t digest[MBEDTLS_MD_MAX_SIZE]) {
    psa_status_t status = PSA_SUCCESS;
    psa_hash_operation_t operation = PSA_HASH_OPERATION_INIT;
    size_t hash_len = 0;

    status = psa_crypto_init();
    if (status != PSA_SUCCESS) {
        return CHARRA_RC_CRYPTO_ERROR;
    }

    status = psa_hash_setup(&operation, hash_algo);
    if (status != PSA_SUCCESS) {
        return CHARRA_RC_CRYPTO_ERROR;
    }

    status = psa_hash_update(&operation, data, data_len);
    if (status != PSA_SUCCESS) {
        goto error;
    }

    status =
            psa_hash_finish(&operation, digest, MBEDTLS_MD_MAX_SIZE, &hash_len);
    if (status != PSA_SUCCESS) {
        goto error;
    }

    psa_hash_abort(&operation);
    return CHARRA_RC_SUCCESS;

error:
    psa_hash_abort(&operation);
    return CHARRA_RC_CRYPTO_ERROR;
}

static CHARRA_RC charra_crypto_tpm_pub_key_to_mbedtls_rsa_pub_key(
        const TPM2B_PUBLIC* tpm_rsa_pub_key, psa_key_id_t* key_id) {
    psa_status_t status = PSA_SUCCESS;
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;

    uint8_t key[1024] = {0};
    size_t key_len = 0;

    const uint8_t* modulus = tpm_rsa_pub_key->publicArea.unique.rsa.buffer;
    size_t modulus_size = tpm_rsa_pub_key->publicArea.unique.rsa.size;
    uint32_t exponent =
            tpm_rsa_pub_key->publicArea.parameters.rsaDetail.exponent == 0
                    ? 65537
                    : tpm_rsa_pub_key->publicArea.parameters.rsaDetail.exponent;

    CHARRA_RC rc = charra_der_encode_rsa_pub_key(
            modulus, modulus_size, exponent, key, sizeof(key), &key_len);
    if (rc != CHARRA_RC_SUCCESS) {
        return CHARRA_RC_CRYPTO_ERROR;
    }

    psa_set_key_type(&attr, PSA_KEY_TYPE_RSA_PUBLIC_KEY);
    psa_set_key_lifetime(&attr, PSA_KEY_LIFETIME_VOLATILE);
    switch (tpm_rsa_pub_key->publicArea.parameters.rsaDetail.scheme.scheme) {
    case TPM2_ALG_RSASSA:
        psa_set_key_algorithm(
                &attr, PSA_ALG_RSA_PKCS1V15_SIGN(PSA_ALG_ANY_HASH));
        break;
    case TPM2_ALG_RSAPSS:
        psa_set_key_algorithm(&attr, PSA_ALG_RSA_PSS(PSA_ALG_ANY_HASH));
        break;
    default:
        return CHARRA_RC_CRYPTO_ERROR;
    }
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_VERIFY_HASH);
    psa_set_key_bits(
            &attr, tpm_rsa_pub_key->publicArea.parameters.rsaDetail.keyBits);

    status = psa_import_key(&attr, key, key_len, key_id);
    if (status != PSA_SUCCESS) {
        return CHARRA_RC_CRYPTO_ERROR;
    }

    psa_reset_key_attributes(&attr);

    return CHARRA_RC_SUCCESS;
}

static CHARRA_RC charra_crypto_tpm_pub_key_to_mbedtls_ecc_pub_key(
        const TPM2B_PUBLIC* tpm_pub, psa_key_id_t* key_id) {
    psa_status_t status = PSA_SUCCESS;
    const TPMT_PUBLIC* pub = &tpm_pub->publicArea;

    if (pub->type != TPM2_ALG_ECC) {
        return CHARRA_RC_CRYPTO_ERROR;
    }

    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;

    psa_set_key_type(
            &attr, PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_lifetime(&attr, PSA_KEY_LIFETIME_VOLATILE);
    psa_set_key_algorithm(&attr, PSA_ALG_ECDSA(PSA_ALG_ANY_HASH));
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_VERIFY_HASH);

    // Map TPM curve → PSA curve bits
    size_t bits = 0;
    switch (pub->parameters.eccDetail.curveID) {
    case TPM2_ECC_NIST_P192:
        bits = 192;
        break;
    case TPM2_ECC_NIST_P224:
        bits = 224;
        break;
    case TPM2_ECC_NIST_P256:
        bits = 256;
        break;
    case TPM2_ECC_NIST_P384:
        bits = 384;
        break;
    case TPM2_ECC_NIST_P521:
        bits = 521;
        break;
    default:
        return CHARRA_RC_CRYPTO_ERROR;
    }
    psa_set_key_bits(&attr, bits);

    uint8_t key[1 + (521 / 8 + 1) * 2];  // enough for P-521
    size_t key_len = 0;

    CHARRA_RC rc =
            charra_octet_string_encode_ecdsa_pub_key(pub->unique.ecc.x.buffer,
                    pub->unique.ecc.x.size, pub->unique.ecc.y.buffer,
                    pub->unique.ecc.y.size, key, sizeof(key), &key_len);
    if (rc != CHARRA_RC_SUCCESS) {
        return CHARRA_RC_CRYPTO_ERROR;
    }

    status = psa_import_key(&attr, key, key_len, key_id);
    if (status != PSA_SUCCESS) {
        return CHARRA_RC_CRYPTO_ERROR;
    }

    psa_reset_key_attributes(&attr);

    return CHARRA_RC_SUCCESS;
}

CHARRA_RC charra_crypto_tpm_pub_key_to_mbedtls_pub_key(
        const TPM2B_PUBLIC* tpm_pub_key, psa_key_id_t* key_id) {
    if (tpm_pub_key == NULL || key_id == NULL) {
        return CHARRA_RC_BAD_ARGUMENT;
    }

    psa_status_t status = psa_crypto_init();
    if (status != PSA_SUCCESS) {
        return CHARRA_RC_CRYPTO_ERROR;
    }

    switch (tpm_pub_key->publicArea.type) {
    case TPM2_ALG_RSA:
        return charra_crypto_tpm_pub_key_to_mbedtls_rsa_pub_key(
                tpm_pub_key, key_id);

    case TPM2_ALG_ECC:
        return charra_crypto_tpm_pub_key_to_mbedtls_ecc_pub_key(
                tpm_pub_key, key_id);

    default:
        charra_log_error("Unsupported TPM public key type: %d",
                tpm_pub_key->publicArea.type);
        return CHARRA_RC_CRYPTO_ERROR;
    }
}

static psa_status_t verify_ecdsa_signature(psa_key_id_t pub_key,
        const unsigned char* data, size_t data_len,
        const TPMT_SIGNATURE* const signature, psa_algorithm_t sig_alg) {
    uint8_t ecdsa_sig[256] = {0};
    size_t ecdsa_sig_len = 0;
    // Signature is R concatenated with S
    memcpy(ecdsa_sig, signature->signature.ecdsa.signatureR.buffer,
            signature->signature.ecdsa.signatureR.size);
    ecdsa_sig_len += signature->signature.ecdsa.signatureR.size;
    memcpy(ecdsa_sig + ecdsa_sig_len,
            signature->signature.ecdsa.signatureS.buffer,
            signature->signature.ecdsa.signatureS.size);
    ecdsa_sig_len += signature->signature.ecdsa.signatureS.size;
    return psa_verify_message(
            pub_key, sig_alg, data, data_len, ecdsa_sig, ecdsa_sig_len);
}

CHARRA_RC charra_crypto_verify_tpm_signature(psa_key_id_t pub_key,
        psa_algorithm_t hash_algo, const unsigned char* data, size_t data_len,
        const TPMT_SIGNATURE* const signature, TPM2_ALG_ID signature_scheme) {
    psa_status_t status = PSA_SUCCESS;
    psa_algorithm_t sig_alg = PSA_ALG_NONE;

    status = psa_crypto_init();
    if (status != PSA_SUCCESS) {
        return CHARRA_RC_CRYPTO_ERROR;
    }

    switch (signature_scheme) {
    case TPM2_ALG_RSASSA:
        sig_alg = PSA_ALG_RSA_PKCS1V15_SIGN(hash_algo);
        status = psa_verify_message(pub_key, sig_alg, data, data_len,
                signature->signature.rsassa.sig.buffer,
                signature->signature.rsassa.sig.size);
        break;
    case TPM2_ALG_RSAPSS:
        sig_alg = PSA_ALG_RSA_PSS(hash_algo);
        status = psa_verify_message(pub_key, sig_alg, data, data_len,
                signature->signature.rsapss.sig.buffer,
                signature->signature.rsapss.sig.size);
        break;
    case TPM2_ALG_ECDSA:
        sig_alg = PSA_ALG_ECDSA(hash_algo);
        status = verify_ecdsa_signature(
                pub_key, data, data_len, signature, sig_alg);
        break;
    default:
        return CHARRA_RC_CRYPTO_ERROR;
    }

    if (status != PSA_SUCCESS) {
        return CHARRA_RC_CRYPTO_ERROR;
    }

    return CHARRA_RC_SUCCESS;
}

CHARRA_RC compute_and_check_PCR_digest(
        const uint8_t* const pcr_values[TPM2_PCR_BANK_COUNT][TPM2_MAX_PCRS],
        const uint32_t* const pcr_values_len,
        const TPMS_ATTEST* const attest_struct,
        psa_algorithm_t hash_algorithm) {
    uint8_t pcr_composite_digest[MBEDTLS_MD_MAX_SIZE] = {0};
    uint16_t pcr_composite_digest_len =
            attest_struct->attested.quote.pcrDigest.size;
    CHARRA_RC charra_r =
            charra_compute_pcr_composite_digest_from_ptr_pcr_selection(
                    hash_algorithm, pcr_values, pcr_values_len,
                    pcr_composite_digest);
    if (charra_r != CHARRA_RC_SUCCESS) {
        return CHARRA_RC_ERROR;
    }
    bool matching = charra_verify_tpm2_quote_pcr_composite_digest(
            attest_struct, pcr_composite_digest, pcr_composite_digest_len);
    charra_print_hex(CHARRA_LOG_DEBUG, pcr_composite_digest_len,
            pcr_composite_digest,
            "                                              0x", "\n", false);
    if (matching) {
        return CHARRA_RC_SUCCESS;
    } else {
        return CHARRA_RC_NO_MATCH;
    }
}
