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

#include <mbedtls/rsa.h>

#include "../common/charra_error.h"

/* hashing functions */

CHARRA_RC hash_sha1(const size_t data_len, const uint8_t* const data,
	uint8_t digest[TPM2_SHA1_DIGEST_SIZE]);

CHARRA_RC hash_sha1_array(const size_t count, const uint8_t* const array,
	uint8_t digest[TPM2_SHA1_DIGEST_SIZE]);

CHARRA_RC hash_sha256(const size_t data_len, const uint8_t* const data,
	uint8_t digest[TPM2_SHA256_DIGEST_SIZE]);

CHARRA_RC hash_sha256_array(uint8_t* data[TPM2_SHA256_DIGEST_SIZE],
	const size_t data_len, uint8_t digest[TPM2_SHA256_DIGEST_SIZE]);

CHARRA_RC hash_sha384(const size_t data_len, const uint8_t* const data,
	uint8_t digest[TPM2_SHA384_DIGEST_SIZE]);

CHARRA_RC hash_sha384_array(const size_t count, const uint8_t* const array,
	uint8_t digest[TPM2_SHA384_DIGEST_SIZE]);

CHARRA_RC hash_sha512(const size_t data_len, const uint8_t* const data,
	uint8_t digest[TPM2_SHA512_DIGEST_SIZE]);

CHARRA_RC hash_sha512_array(const size_t count, const uint8_t* const array,
	uint8_t digest[TPM2_SHA512_DIGEST_SIZE]);

CHARRA_RC hash_sm3_256(const size_t data_len, const uint8_t* const data,
	uint8_t digest[TPM2_SM3_256_DIGEST_SIZE]);

CHARRA_RC hash_sm3_256_array(const size_t count, const uint8_t* const array,
	uint8_t digest[TPM2_SM3_256_DIGEST_SIZE]);

CHARRA_RC charra_crypto_hash(mbedtls_md_type_t hash_algo,
	const uint8_t* const data, const size_t data_len,
	uint8_t digest[MBEDTLS_MD_MAX_SIZE]);

CHARRA_RC charra_crypto_tpm_pub_key_to_mbedtls_pub_key(
	const TPM2B_PUBLIC* tpm_rsa_pub_key,
	mbedtls_rsa_context* mbedtls_rsa_pub_key);

CHARRA_RC charra_crypto_rsa_verify_signature_hashed(
	mbedtls_rsa_context* mbedtls_rsa_pub_key, mbedtls_md_type_t hash_algo,
	const unsigned char* data_digest, const unsigned char* signature);

CHARRA_RC charra_crypto_rsa_verify_signature(
	mbedtls_rsa_context* mbedtls_rsa_pub_key, mbedtls_md_type_t hash_algo,
	const unsigned char* data, size_t data_len, const unsigned char* signature);

/**
 * @brief Compute PCR composite digest from PCR values and check if it matches
 * with the digest given in attest_struct.
 *
 * @param pcr_values 2D array of pcr values
 * @param pcr_values_len number of PCR values in pcr_values
 * @param attest_struct structure holding the digest to check against
 * @returns CHARRA_RC_SUCCESS on matching digests, CHARRA_RC_NO_MATCH
 * on non-matching digests, CHARRA_RC_ERROR on error
 */
CHARRA_RC compute_and_check_PCR_digest(uint8_t** pcr_values,
	uint32_t pcr_value_len, const TPMS_ATTEST* const attest_struct);

#endif /* SITIMA_CRYPTO_H */
