/* SPDX-License-Identifier: BSD-3-Clause */
/*****************************************************************************
 * Copyright 2019-2020, Fraunhofer Institute for Secure Information Technology
 * SIT. All rights reserved.
 ****************************************************************************/

/**
 * @file crypto_util.h
 * @author Michael Eckel (michael.eckel@sit.fraunhofer.de)
 * @brief Provides related crypto functions.
 * @version 0.1
 * @date 2019-12-22
 *
 * @copyright Copyright 2019, Fraunhofer Institute for Secure Information
 * Technology SIT. All rights reserved.
 *
 * @license BSD 3-Clause "New" or "Revised" License (SPDX-License-Identifier:
 * BSD-3-Clause).
 */

#ifndef CRYPTO_UTIL_H
#define CRYPTO_UTIL_H

#include <stddef.h>
#include <stdint.h>

#include <tss2/tss2_tpm2_types.h>

#include <mbedtls/pk.h>

#include "../common/charra_error.h"

#define TPM2_PCR_BANK_COUNT 4  // sha1, sha256, sha384, sha512

typedef uint8_t charra_tpm_pcr_selection[TPM2_PCR_BANK_COUNT][TPM2_MAX_PCRS];

typedef enum {
    CHARRA_TPM_PCR_BANK_SHA1 = 0,
    CHARRA_TPM_PCR_BANK_SHA256 = 1,
    CHARRA_TPM_PCR_BANK_SHA384 = 2,
    CHARRA_TPM_PCR_BANK_SHA512 = 3,
    CHARRA_TPM_PCR_BANK_UNKNOWN = -1,
} charra_tpm_pcr_bank_index;

/**
 *  @brief parses the string as a PCR bank index.
 *
 * @param pcr_bank the string holding the PCR bank.
 * @returns the PCR bank index.
 */
charra_tpm_pcr_bank_index charra_tpm_pcr_bank_index_from_str(
        const char* const pcr_bank);

/**
 * @brief parses the string as a TPM2_ALG_ID hash algorithm.
 *
 * @param hash_algorithm the string holding the hash algorithm.
 * @returns the TPM2_ALG_ID hash algorithm.
 */
TPM2_ALG_ID charra_tpm_hash_algorithm_from_str(
        const char* const hash_algorithm);

/** * @brief parses the TPM2_ALG_ID hash algorithm to a psa_algorithm_t.
 *
 * @param hash_alg_id the TPM2_ALG_ID hash algorithm.
 * @returns the psa hash algorithm.
 */
psa_algorithm_t charra_psa_hash_algorithm_from_tpm2_alg_id(
        TPM2_ALG_ID hash_alg_id);

/**
 * @brief parses the string as a TPM2_ALG_ID signature scheme.
 *
 * @param signature_scheme the string holding the signature scheme.
 * @returns the TPM2_ALG_ID signature scheme.
 */
TPM2_ALG_ID charra_signature_scheme_from_str(
        const char* const signature_scheme);

CHARRA_RC charra_crypto_hash(psa_algorithm_t hash_algo,
        const uint8_t* const data, const size_t data_len,
        uint8_t digest[MBEDTLS_MD_MAX_SIZE]);

CHARRA_RC charra_crypto_tpm_pub_key_to_mbedtls_pub_key(
        const TPM2B_PUBLIC* tpm_pub_key, psa_key_id_t* key_id);

CHARRA_RC charra_crypto_verify_tpm_signature(psa_key_id_t pub_key,
        psa_algorithm_t hash_algo, const unsigned char* data, size_t data_len,
        const TPMT_SIGNATURE* const signature, TPM2_ALG_ID signature_scheme);

/**
 * @brief Compute PCR composite digest from PCR values and check if it matches
 * with the digest given in attest_struct.
 *
 * @param pcr_values 3D array of PCR banks containing 2D array of PCR values
 * @param pcr_values_len an array containing the count of PCR values in each
 * bank of pcr_values
 * @param attest_struct structure holding the digest to check against
 * @param hash_algorithm the hash algorithm to use for digest computation
 * @returns CHARRA_RC_SUCCESS on matching digests, CHARRA_RC_NO_MATCH
 * on non-matching digests, CHARRA_RC_ERROR on error
 */
CHARRA_RC compute_and_check_PCR_digest(
        const uint8_t* const pcr_values[TPM2_PCR_BANK_COUNT][TPM2_MAX_PCRS],
        const uint32_t* const pcr_value_len,
        const TPMS_ATTEST* const attest_struct, psa_algorithm_t hash_algorithm);

#endif /* SITIMA_CRYPTO_H */
