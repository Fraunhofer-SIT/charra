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

#endif /* SITIMA_CRYPTO_H */
