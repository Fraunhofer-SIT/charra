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

#include <mbedtls/sha1.h>
#include <mbedtls/sha256.h>
#include <mbedtls/sha512.h>

#include <tss2/tss2_tpm2_types.h>

#include "../common/charra_error.h"
#include "../util/io_util.h"

/* hashing functions */

CHARRA_RC hash_sha1(const size_t data_len, const uint8_t* const data,
	uint8_t digest[TPM2_SHA1_DIGEST_SIZE]) {
	CHARRA_RC r = CHARRA_RC_SUCCESS;

	/* init */
	mbedtls_sha1_context ctx = {0};
	mbedtls_sha1_init(&ctx);

	/* hash */
	if ((mbedtls_sha1_starts_ret(&ctx)) != 0) {
		r = CHARRA_RC_ERROR;
		goto error;
	}

	if ((mbedtls_sha1_update_ret(&ctx, data, data_len)) != 0) {
		r = CHARRA_RC_ERROR;
		goto error;
	}

	if ((mbedtls_sha1_finish_ret(&ctx, digest)) != 0) {
		r = CHARRA_RC_ERROR;
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
	if ((mbedtls_sha256_starts_ret(&ctx, 0)) != 0) {
		r = CHARRA_RC_ERROR;
		goto error;
	}

	if ((mbedtls_sha256_update_ret(&ctx, data, data_len)) != 0) {
		r = CHARRA_RC_ERROR;
		goto error;
	}

	if ((mbedtls_sha256_finish_ret(&ctx, digest)) != 0) {
		r = CHARRA_RC_ERROR;
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
	if ((mbedtls_sha256_starts_ret(&ctx, 0)) != 0) {
		r = CHARRA_RC_ERROR;
		goto error;
	}

	for (size_t i = 0; i < data_len; ++i) {
		if ((mbedtls_sha256_update_ret(
				&ctx, data[i], TPM2_SHA256_DIGEST_SIZE)) != 0) {
			r = CHARRA_RC_ERROR;
			goto error;
		}
	}

	if ((mbedtls_sha256_finish_ret(&ctx, digest)) != 0) {
		r = CHARRA_RC_ERROR;
		goto error;
	}

error:
	/* free */
	mbedtls_sha256_free(&ctx);

	return r;
}

CHARRA_RC hash_sha512(const size_t data_len, const uint8_t* const data,
	uint8_t digest[TPM2_SM3_256_DIGEST_SIZE]) {
	CHARRA_RC r = CHARRA_RC_SUCCESS;

	/* init */
	mbedtls_sha512_context ctx = {0};
	mbedtls_sha512_init(&ctx);

	/* hash */
	if ((mbedtls_sha512_starts_ret(&ctx, 0) /* 0 = SHA512 */
			) != 0) {
		r = CHARRA_RC_ERROR;
		goto error;
	}

	if ((mbedtls_sha512_update_ret(&ctx, data, data_len)) != 0) {
		r = CHARRA_RC_ERROR;
		goto error;
	}
	if ((mbedtls_sha512_finish_ret(&ctx, digest)) != 0) {
		r = CHARRA_RC_ERROR;
		goto error;
	}

error:
	/* free */
	mbedtls_sha512_free(&ctx);

	return r;
}
