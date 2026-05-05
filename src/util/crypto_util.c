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
#include <mbedtls/rsa.h>
#include <mbedtls/sha1.h>
#include <mbedtls/sha256.h>
#include <mbedtls/sha512.h>
#include <tss2/tss2_tpm2_types.h>

#include "../common/charra_error.h"
#include "../util/charra_util.h"
#include "../util/io_util.h"
#include "../util/parser_util.h"

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

mbedtls_md_type_t charra_md_hash_algorithm_from_tpm2_alg_id(
        TPM2_ALG_ID hash_alg_id) {
    switch (hash_alg_id) {
    case TPM2_ALG_SHA1:
        return MBEDTLS_MD_SHA1;
    case TPM2_ALG_SHA256:
        return MBEDTLS_MD_SHA256;
    case TPM2_ALG_SHA384:
        return MBEDTLS_MD_SHA384;
    case TPM2_ALG_SHA512:
        return MBEDTLS_MD_SHA512;
    default:
        return MBEDTLS_MD_NONE;
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

/* hashing functions */

CHARRA_RC hash_sha1(const size_t data_len, const uint8_t* const data,
        uint8_t digest[TPM2_SHA1_DIGEST_SIZE]) {
    CHARRA_RC r = CHARRA_RC_SUCCESS;

    /* init */
    mbedtls_sha1_context ctx = {0};
    mbedtls_sha1_init(&ctx);

    /* hash */
    if ((mbedtls_sha1_starts(&ctx)) != 0) {
        r = CHARRA_RC_CRYPTO_ERROR;
        goto error;
    }

    if ((mbedtls_sha1_update(&ctx, data, data_len)) != 0) {
        r = CHARRA_RC_CRYPTO_ERROR;
        goto error;
    }

    if ((mbedtls_sha1_finish(&ctx, digest)) != 0) {
        r = CHARRA_RC_CRYPTO_ERROR;
        goto error;
    }

error:
    /* free */
    mbedtls_sha1_free(&ctx);

    return r;
}

CHARRA_RC hash_sha256(const size_t data_len, const uint8_t* const data,
        uint8_t digest[TPM2_SHA256_DIGEST_SIZE]) {
    CHARRA_RC r = CHARRA_RC_SUCCESS;

    /* init */
    mbedtls_sha256_context ctx = {0};
    mbedtls_sha256_init(&ctx);

    /* hash */
    if ((mbedtls_sha256_starts(&ctx, 0)) != 0) {
        r = CHARRA_RC_CRYPTO_ERROR;
        goto error;
    }

    if ((mbedtls_sha256_update(&ctx, data, data_len)) != 0) {
        r = CHARRA_RC_CRYPTO_ERROR;
        goto error;
    }

    if ((mbedtls_sha256_finish(&ctx, digest)) != 0) {
        r = CHARRA_RC_CRYPTO_ERROR;
        goto error;
    }

error:
    /* free */
    mbedtls_sha256_free(&ctx);

    return r;
}

CHARRA_RC hash_sha256_array(uint8_t* data[TPM2_SHA256_DIGEST_SIZE],
        const size_t data_len, uint8_t digest[TPM2_SHA256_DIGEST_SIZE]) {
    CHARRA_RC r = CHARRA_RC_SUCCESS;

    /* init */
    mbedtls_sha256_context ctx = {0};
    mbedtls_sha256_init(&ctx);

    /* hash */
    if ((mbedtls_sha256_starts(&ctx, 0)) != 0) {
        r = CHARRA_RC_CRYPTO_ERROR;
        goto error;
    }

    for (size_t i = 0; i < data_len; ++i) {
        if ((mbedtls_sha256_update(&ctx, data[i], TPM2_SHA256_DIGEST_SIZE)) !=
                0) {
            r = CHARRA_RC_CRYPTO_ERROR;
            goto error;
        }
    }

    if ((mbedtls_sha256_finish(&ctx, digest)) != 0) {
        r = CHARRA_RC_CRYPTO_ERROR;
        goto error;
    }

error:
    /* free */
    mbedtls_sha256_free(&ctx);

    return r;
}

CHARRA_RC hash_sha512(const size_t data_len, const uint8_t* const data,
        uint8_t digest[TPM2_SHA512_DIGEST_SIZE]) {
    CHARRA_RC r = CHARRA_RC_SUCCESS;

    /* init */
    mbedtls_sha512_context ctx = {0};
    mbedtls_sha512_init(&ctx);

    /* hash */
    if ((mbedtls_sha512_starts(&ctx, 0)) != 0) {  // 0 = SHA512
        r = CHARRA_RC_CRYPTO_ERROR;
        goto error;
    }

    if ((mbedtls_sha512_update(&ctx, data, data_len)) != 0) {
        r = CHARRA_RC_CRYPTO_ERROR;
        goto error;
    }

    if ((mbedtls_sha512_finish(&ctx, digest)) != 0) {
        r = CHARRA_RC_CRYPTO_ERROR;
        goto error;
    }

error:
    /* free */
    mbedtls_sha512_free(&ctx);

    return r;
}

CHARRA_RC charra_crypto_hash(mbedtls_md_type_t hash_algo,
        const uint8_t* const data, const size_t data_len,
        uint8_t digest[MBEDTLS_MD_MAX_SIZE]) {
    CHARRA_RC r = CHARRA_RC_SUCCESS;

    /* init and setup */
    const mbedtls_md_info_t* hash_info = mbedtls_md_info_from_type(hash_algo);
    mbedtls_md_context_t ctx = {0};
    mbedtls_md_init(&ctx);
    if ((mbedtls_md_setup(&ctx, hash_info, 0)) != 0) {  // 0 = do not use HMAC
        r = CHARRA_RC_CRYPTO_ERROR;
        goto error;
    }

    /* hash */
    if ((mbedtls_md_starts(&ctx)) != 0) {
        r = CHARRA_RC_CRYPTO_ERROR;
        goto error;
    }

    if ((mbedtls_md_update(&ctx, data, data_len)) != 0) {
        r = CHARRA_RC_CRYPTO_ERROR;
        goto error;
    }

    if ((mbedtls_md_finish(&ctx, digest)) != 0) {
        r = CHARRA_RC_CRYPTO_ERROR;
        goto error;
    }

error:
    /* free */
    mbedtls_md_free(&ctx);

    return r;
}

CHARRA_RC charra_crypto_tpm_pub_key_to_mbedtls_pub_key(
        const TPM2B_PUBLIC* tpm_pub_key, mbedtls_pk_context* mbedtls_pub_key) {
    if (tpm_pub_key == NULL || mbedtls_pub_key == NULL) {
        return CHARRA_RC_BAD_ARGUMENT;  // handle null pointers gracefully
    }

    CHARRA_RC r = CHARRA_RC_SUCCESS;

    mbedtls_pk_init(mbedtls_pub_key);
    switch (tpm_pub_key->publicArea.type) {
    case TPM2_ALG_RSA:
        if (mbedtls_pk_setup(mbedtls_pub_key,
                    mbedtls_pk_info_from_type(MBEDTLS_PK_RSA)) != 0) {
            r = CHARRA_RC_CRYPTO_ERROR;
            goto error;
        }
        r = charra_crypto_tpm_pub_key_to_mbedtls_rsa_pub_key(
                tpm_pub_key, mbedtls_pk_rsa(*mbedtls_pub_key));
        if (r != CHARRA_RC_SUCCESS) {
            goto error;
        }
        break;
    case TPM2_ALG_ECC:
        if (mbedtls_pk_setup(mbedtls_pub_key,
                    mbedtls_pk_info_from_type(MBEDTLS_PK_ECDSA)) != 0) {
            r = CHARRA_RC_CRYPTO_ERROR;
            goto error;
        }
        r = charra_crypto_tpm_pub_key_to_mbedtls_ecc_pub_key(
                tpm_pub_key, mbedtls_pk_ec(*mbedtls_pub_key));
        if (r != CHARRA_RC_SUCCESS) {
            goto error;
        }
        break;
    default:
        r = CHARRA_RC_CRYPTO_ERROR;
        charra_log_error("Unsupported TPM public key type: %d",
                tpm_pub_key->publicArea.type);
        goto error;
    }

    return r;
error:
    /* cleanup */
    mbedtls_pk_free(mbedtls_pub_key);

    return r;
}

CHARRA_RC charra_crypto_tpm_pub_key_to_mbedtls_rsa_pub_key(
        const TPM2B_PUBLIC* tpm_rsa_pub_key,
        mbedtls_rsa_context* mbedtls_rsa_pub_key) {
    CHARRA_RC r = CHARRA_RC_SUCCESS;
    int mbedtls_r = 0;

    /* construct a RSA public key from modulus and exponent */
    mbedtls_mpi n = {0}; /* modulus */
    mbedtls_mpi e = {0}; /* exponent */

    /* init mbed TLS structures */
    mbedtls_rsa_init(mbedtls_rsa_pub_key);
    if (mbedtls_rsa_set_padding(mbedtls_rsa_pub_key, MBEDTLS_RSA_PKCS_V21,
                MBEDTLS_MD_NONE) != 0) {
        r = CHARRA_RC_CRYPTO_ERROR;
        charra_log_error("mbedtls_rsa_set_padding");
        goto error;
    }
    mbedtls_mpi_init(&n);
    mbedtls_mpi_init(&e);

    /* set modulus */
    if ((mbedtls_r = mbedtls_mpi_read_binary(&n,
                 (const unsigned char*)
                         tpm_rsa_pub_key->publicArea.unique.rsa.buffer,
                 (size_t)tpm_rsa_pub_key->publicArea.unique.rsa.size)) != 0) {
        r = CHARRA_RC_CRYPTO_ERROR;
        charra_log_error("mbedtls_mpi_read_binary");
        goto error;
    }

    { /* set exponent from TPM public key (if 0 set it to 65537) */
        uint32_t exp = 65537; /* set default exponent */
        if (tpm_rsa_pub_key->publicArea.parameters.rsaDetail.exponent != 0) {
            exp = tpm_rsa_pub_key->publicArea.parameters.rsaDetail.exponent;
        }

        if ((mbedtls_r = mbedtls_mpi_lset(&e, (mbedtls_mpi_sint)exp)) != 0) {
            r = CHARRA_RC_CRYPTO_ERROR;
            charra_log_error("mbedtls_mpi_lset");
            goto error;
        }
    }

    if ((mbedtls_r = mbedtls_rsa_import(
                 mbedtls_rsa_pub_key, &n, NULL, NULL, NULL, &e)) != 0) {
        r = CHARRA_RC_CRYPTO_ERROR;
        charra_log_error("mbedtls_rsa_import");
        goto error;
    }

    if ((mbedtls_r = mbedtls_rsa_complete(mbedtls_rsa_pub_key)) != 0) {
        r = CHARRA_RC_CRYPTO_ERROR;
        charra_log_error("mbedtls_rsa_complete");
        goto error;
    }

    if ((mbedtls_r = mbedtls_rsa_check_pubkey(mbedtls_rsa_pub_key)) != 0) {
        r = CHARRA_RC_CRYPTO_ERROR;
        charra_log_error("mbedtls_rsa_check_pubkey");
        goto error;
    }

    /* cleanup */
    mbedtls_mpi_free(&n);
    mbedtls_mpi_free(&e);

    return CHARRA_RC_SUCCESS;

error:
    /* cleanup */
    mbedtls_rsa_free(mbedtls_rsa_pub_key);
    mbedtls_mpi_free(&n);
    mbedtls_mpi_free(&e);

    return r;
}

CHARRA_RC charra_crypto_tpm_pub_key_to_mbedtls_ecc_pub_key(
        const TPM2B_PUBLIC* tpm_pub, mbedtls_ecdsa_context* ecdsa) {
    CHARRA_RC rc = CHARRA_RC_SUCCESS;
    mbedtls_ecp_group_id grp_id;
    const TPMT_PUBLIC* pub = &tpm_pub->publicArea;

    // only ECC implemented
    if (pub->type != TPM2_ALG_ECC) {
        return CHARRA_RC_CRYPTO_ERROR;
    }

    switch (pub->parameters.eccDetail.curveID) {
    case TPM2_ECC_NIST_P192:
        grp_id = MBEDTLS_ECP_DP_SECP192R1;
        break;
    case TPM2_ECC_NIST_P224:
        grp_id = MBEDTLS_ECP_DP_SECP224R1;
        break;
    case TPM2_ECC_NIST_P256:
        grp_id = MBEDTLS_ECP_DP_SECP256R1;
        break;
    case TPM2_ECC_NIST_P384:
        grp_id = MBEDTLS_ECP_DP_SECP384R1;
        break;
    case TPM2_ECC_NIST_P521:
        grp_id = MBEDTLS_ECP_DP_SECP521R1;
        break;
    default:
        return CHARRA_RC_CRYPTO_ERROR;
    }

    mbedtls_ecdsa_init(ecdsa);
    if ((rc = mbedtls_ecp_group_load(&ecdsa->private_grp, grp_id)) != 0)
        return rc;

    const TPMS_ECC_POINT* pt = &pub->unique.ecc;

    rc = mbedtls_mpi_read_binary(
            &ecdsa->private_Q.private_X, pt->x.buffer, pt->x.size);
    if (rc != 0)
        return rc;

    rc = mbedtls_mpi_read_binary(
            &ecdsa->private_Q.private_Y, pt->y.buffer, pt->y.size);
    if (rc != 0)
        return rc;

    rc = mbedtls_mpi_lset(&ecdsa->private_Q.private_Z, 1);
    return rc;
}

CHARRA_RC charra_crypto_verify_tpm_signature(
        mbedtls_pk_context* mbedtls_pub_key, mbedtls_md_type_t hash_algo,
        const unsigned char* data, size_t data_len, TPMT_SIGNATURE* signature,
        TPM2_ALG_ID signature_scheme) {
    CHARRA_RC charra_r = CHARRA_RC_SUCCESS;
    mbedtls_pk_type_t pk_type = MBEDTLS_PK_NONE;

    /* hash data */
    uint8_t data_digest[MBEDTLS_MD_MAX_SIZE] = {0};
    if ((charra_r = charra_crypto_hash(hash_algo, data, data_len,
                 data_digest)) != CHARRA_RC_SUCCESS) {
        goto error;
    }

    /* verify signature */
    pk_type = mbedtls_pk_get_type(mbedtls_pub_key);
    switch (pk_type) {
    case MBEDTLS_PK_RSA:
        if ((charra_r = charra_crypto_rsa_verify_signature_hashed(
                     mbedtls_pk_rsa(*mbedtls_pub_key), hash_algo, data_digest,
                     signature->signature.rsapss.sig.buffer,
                     signature_scheme)) != CHARRA_RC_SUCCESS) {
            charra_r = CHARRA_RC_CRYPTO_ERROR;
            goto error;
        }
        break;
    case MBEDTLS_PK_ECDSA:
        if ((charra_r = charra_crypto_ecc_verify_signature_hashed(
                     mbedtls_pk_ec(*mbedtls_pub_key), hash_algo, data_digest,
                     signature, signature_scheme)) != CHARRA_RC_SUCCESS) {
            charra_r = CHARRA_RC_CRYPTO_ERROR;
            goto error;
        }
        break;
    default:
        charra_r = CHARRA_RC_CRYPTO_ERROR;
        goto error;
    }

error:
    return charra_r;
}

CHARRA_RC charra_crypto_rsa_verify_signature_hashed(
        mbedtls_rsa_context* mbedtls_rsa_pub_key, mbedtls_md_type_t hash_algo,
        const unsigned char* data_digest, const unsigned char* signature,
        TPM2_ALG_ID signature_scheme) {
    CHARRA_RC charra_r = CHARRA_RC_SUCCESS;
    int mbedtls_r = 0;

    /* get hash digest size */
    const mbedtls_md_info_t* md_info = mbedtls_md_info_from_type(hash_algo);
    if (md_info == NULL) {
        charra_r = CHARRA_RC_CRYPTO_ERROR;
        charra_log_error("mbedtls_md_info_from_type");
        goto error;
    }
    uint8_t hash_digest_size = mbedtls_md_get_size(md_info);

    /* determine signing scheme and verify function */
    switch (signature_scheme) {
    case TPM2_ALG_RSASSA:
        mbedtls_r = mbedtls_rsa_rsassa_pkcs1_v15_verify(mbedtls_rsa_pub_key,
                hash_algo, hash_digest_size, data_digest, signature);
        break;
    case TPM2_ALG_RSAPSS:
        mbedtls_r = mbedtls_rsa_rsassa_pss_verify(mbedtls_rsa_pub_key,
                hash_algo, hash_digest_size, data_digest, signature);
        break;
    default:
        charra_log_error("Unsupported signature scheme");
        charra_r = CHARRA_RC_CRYPTO_ERROR;
        goto error;
    }
    if (mbedtls_r != 0) {
        charra_r = CHARRA_RC_CRYPTO_ERROR;
        goto error;
    }

error:
    return charra_r;
}

CHARRA_RC charra_crypto_rsa_verify_signature(
        mbedtls_rsa_context* mbedtls_rsa_pub_key, mbedtls_md_type_t hash_algo,
        const unsigned char* data, size_t data_len,
        const unsigned char* signature, TPM2_ALG_ID signature_scheme) {
    CHARRA_RC charra_r = CHARRA_RC_SUCCESS;

    /* hash data */
    uint8_t data_digest[MBEDTLS_MD_MAX_SIZE] = {0};
    if ((charra_r = charra_crypto_hash(hash_algo, data, data_len,
                 data_digest)) != CHARRA_RC_SUCCESS) {
        goto error;
    }

    /* verify signature */
    if ((charra_r = charra_crypto_rsa_verify_signature_hashed(
                 mbedtls_rsa_pub_key, hash_algo, data_digest, signature,
                 signature_scheme)) != 0) {
        charra_r = CHARRA_RC_CRYPTO_ERROR;
        goto error;
    }

error:
    return charra_r;
}

CHARRA_RC charra_crypto_ecc_verify_signature_hashed(
        mbedtls_ecdsa_context* mbedtls_ecc_pub_key, mbedtls_md_type_t hash_algo,
        const unsigned char* data_digest, TPMT_SIGNATURE* signature,
        TPM2_ALG_ID signature_scheme) {
    CHARRA_RC charra_r = CHARRA_RC_SUCCESS;
    mbedtls_mpi r, s;
    int mbedtls_r = 0;

    /* get hash digest size */
    const mbedtls_md_info_t* md_info = mbedtls_md_info_from_type(hash_algo);
    if (md_info == NULL) {
        charra_r = CHARRA_RC_CRYPTO_ERROR;
        charra_log_error("mbedtls_md_info_from_type");
        goto error;
    }
    uint8_t hash_digest_size = mbedtls_md_get_size(md_info);

    /* determine signing scheme and verify function */
    switch (signature_scheme) {
    case TPM2_ALG_ECDSA:
        mbedtls_mpi_init(&r);
        mbedtls_mpi_init(&s);
        mbedtls_mpi_read_binary(&r,
                signature->signature.ecdsa.signatureR.buffer,
                signature->signature.ecdsa.signatureR.size);
        mbedtls_mpi_read_binary(&s,
                signature->signature.ecdsa.signatureS.buffer,
                signature->signature.ecdsa.signatureS.size);

        mbedtls_r = mbedtls_ecdsa_verify(&mbedtls_ecc_pub_key->private_grp,
                data_digest, hash_digest_size, &mbedtls_ecc_pub_key->private_Q,
                &r, &s);
        break;
    default:
        charra_log_error("Unsupported signature scheme");
        charra_r = CHARRA_RC_CRYPTO_ERROR;
        goto error;
    }
    if (mbedtls_r != 0) {
        charra_r = CHARRA_RC_CRYPTO_ERROR;
        goto error;
    }

error:
    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&s);
    return charra_r;
}

CHARRA_RC charra_crypto_ecc_verify_signature(
        mbedtls_ecdsa_context* mbedtls_ecc_pub_key, mbedtls_md_type_t hash_algo,
        const unsigned char* data, size_t data_len, TPMT_SIGNATURE* signature,
        TPM2_ALG_ID signature_scheme) {
    CHARRA_RC charra_r = CHARRA_RC_SUCCESS;

    /* hash data */
    uint8_t data_digest[MBEDTLS_MD_MAX_SIZE] = {0};
    if ((charra_r = charra_crypto_hash(hash_algo, data, data_len,
                 data_digest)) != CHARRA_RC_SUCCESS) {
        goto error;
    }

    /* verify signature */
    if ((charra_r = charra_crypto_ecc_verify_signature_hashed(
                 mbedtls_ecc_pub_key, hash_algo, data_digest, signature,
                 signature_scheme)) != 0) {
        charra_r = CHARRA_RC_CRYPTO_ERROR;
        goto error;
    }

error:
    return charra_r;
}

CHARRA_RC compute_and_check_PCR_digest(
        const uint8_t* const pcr_values[TPM2_PCR_BANK_COUNT][TPM2_MAX_PCRS],
        const uint32_t* const pcr_values_len,
        const TPMS_ATTEST* const attest_struct,
        mbedtls_md_type_t hash_algorithm) {
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
