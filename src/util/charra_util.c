/* SPDX-License-Identifier: BSD-3-Clause */
/*****************************************************************************
 * Copyright 2019-2020, Fraunhofer Institute for Secure Information Technology
 * SIT. All rights reserved.
 ****************************************************************************/

/**
 * @file charra_util.c
 * @author Michael Eckel (michael.eckel@sit.fraunhofer.de)
 * @brief
 * @version 0.1
 * @date 2019-09-19
 *
 * @copyright Copyright 2019-2020, Fraunhofer Institute for Secure Information
 * Technology SIT. All rights reserved.
 *
 * @license BSD 3-Clause "New" or "Revised" License (SPDX-License-Identifier:
 * BSD-3-Clause).
 */

#include "charra_util.h"

#include <assert.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/sha1.h>
#include <mbedtls/sha256.h>
#include <mbedtls/sha512.h>

#include <tss2/tss2_esys.h>
#include <tss2/tss2_mu.h>
#include <tss2/tss2_tctildr.h>
#include <tss2/tss2_tpm2_types.h>

#include "../common/charra_error.h"
#include "../common/charra_log.h"
#include "io_util.h"
#include "tpm2_util.h"

#define CHARRA_UNUSED __attribute__((unused))

static const unsigned char mbedtls_personalization[] =
	"CHARRA_mbedtls_random_personalization";
static const unsigned char mbedtls_personalization_len =
	sizeof(mbedtls_personalization);

CHARRA_RC charra_random_bytes(const uint32_t len, uint8_t* random_bytes) {
	CHARRA_RC charra_r = CHARRA_RC_SUCCESS;
	/* initialize contexts */
	mbedtls_entropy_context entropy = {0};
	mbedtls_entropy_init(&entropy);
	mbedtls_ctr_drbg_context ctr_drbg = {0};
	mbedtls_ctr_drbg_init(&ctr_drbg);

	/* add seed */
	if (mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
			mbedtls_personalization, mbedtls_personalization_len) != 0) {
		charra_r = CHARRA_RC_CRYPTO_ERROR;
		goto error;
	}

	/* add prediction resistance */
	mbedtls_ctr_drbg_set_prediction_resistance(
		&ctr_drbg, MBEDTLS_CTR_DRBG_PR_ON);

	if (mbedtls_ctr_drbg_random(
			&ctr_drbg, (unsigned char*)random_bytes, (size_t)len) != 0) {
		charra_r = CHARRA_RC_CRYPTO_ERROR;
		goto error;
	}

error:
	/* clean up */
	mbedtls_ctr_drbg_free(&ctr_drbg);
	mbedtls_entropy_free(&entropy);

	return charra_r;
}

CHARRA_RC charra_random_bytes_from_tpm(
	const uint32_t len, uint8_t* random_bytes) {
	assert(len <= sizeof(TPMU_HA));

	TSS2_RC tss2_rc = 0;
	char* error_msg = NULL;
	ESYS_CONTEXT* ctx = NULL;

	TPM2B_DIGEST* tpm_random_bytes = NULL;

	TSS2_TCTI_CONTEXT* tcti_ctx = NULL;
	if ((tss2_rc = Tss2_TctiLdr_Initialize(getenv("CHARRA_TCTI"), &tcti_ctx)) !=
		TSS2_RC_SUCCESS) {
		error_msg = "TPM2 Tss2_TctiLdr_Initialize failed.";
		goto error;
	}
	if ((tss2_rc = Esys_Initialize(&ctx, tcti_ctx, NULL)) != TSS2_RC_SUCCESS) {
		error_msg = "TPM2 Esys_Initialize failed.";
		goto error;
	}

	if ((tss2_rc = tpm2_get_random(ctx, len, &tpm_random_bytes)) !=
		TSS2_RC_SUCCESS) {
		error_msg = "TPM2 get random failed";
		goto error;
	}

	/* set out params */
	memcpy(random_bytes, tpm_random_bytes->buffer, len);

error:
	/* print error message */
	if (error_msg != NULL) {
		charra_log_error("%s (TSS2_RC: 0x%04x)", error_msg, tss2_rc);
	}

	/* free ESAPI objects */
	if (tpm_random_bytes != NULL) {
		Esys_Free(tpm_random_bytes);
	}

	/* finalize ESAPI */
	Esys_Finalize(&ctx);
	Tss2_TctiLdr_Finalize(&tcti_ctx);

	/* transform TSS2_RC to CHARRA_RC */
	CHARRA_RC charra_rc =
		(tss2_rc == TSS2_RC_SUCCESS) ? CHARRA_RC_SUCCESS : CHARRA_RC_TPM;

	return charra_rc;
}

TSS2_RC charra_verify_tpm2_quote_signature_with_tpm(ESYS_CONTEXT* ctx,
	const ESYS_TR sig_key_handle, const TPM2_ALG_ID hash_algo_id,
	const TPM2B_ATTEST* attest_buf, TPMT_SIGNATURE* signature,
	TPMT_TK_VERIFIED** validation) {
	TSS2_RC tss2_r = TSS2_RC_SUCCESS;
	char* error_msg = NULL;

	/* prepare buffer */
	TPM2B_MAX_BUFFER data = {.size = attest_buf->size};
	memcpy(data.buffer, (const uint8_t*)&attest_buf->attestationData,
		attest_buf->size);

	/* hash relevant attestation data for verification */
	TPM2B_DIGEST* attestation_data_digest = NULL;
	TPMT_TK_HASHCHECK* hash_validation = NULL;
	if ((tss2_r = Esys_Hash(ctx, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
			 &data, hash_algo_id, TPM2_RH_OWNER, &attestation_data_digest,
			 &hash_validation)) != TSS2_RC_SUCCESS) {
		error_msg = "Esys_Hash";
		goto error;
	}

	/* verify quote signature */
	if ((tss2_r = Esys_VerifySignature(ctx, sig_key_handle, ESYS_TR_NONE,
			 ESYS_TR_NONE, ESYS_TR_NONE, attestation_data_digest, signature,
			 validation)) != TSS2_RC_SUCCESS) {
		error_msg = "Esys_VerifySignature";
		goto error;
	}

error:
	/* print error message */
	if (error_msg != NULL) {
		charra_log_error("%s (TSS2_RC: 0x%04x)", error_msg, tss2_r);
	}

	/* free ESAPI objects */
	if (hash_validation != NULL) {
		Esys_Free(hash_validation);
	}
	if (attestation_data_digest != NULL) {
		Esys_Free(attestation_data_digest);
	}

	return tss2_r;
}

CHARRA_RC charra_unmarshal_tpm2_quote(size_t attest_buf_len,
	const uint8_t* attest_buf, TPMS_ATTEST* attest_struct) {
	CHARRA_RC charra_rc = CHARRA_RC_SUCCESS;
	TSS2_RC tss2_rc = TSS2_RC_SUCCESS;
	char* error_msg = NULL;

	/* verify input parameters */
	if (attest_buf == NULL) {
		error_msg = "Bad argument. attest_buf is NULL.";
		charra_rc = CHARRA_RC_BAD_ARGUMENT;
		goto error;
	} else if (attest_struct == NULL) {
		error_msg = "Bad argument. attest_struct is NULL.";
		charra_rc = CHARRA_RC_BAD_ARGUMENT;
		goto error;
	}

	/* unmarshal TPMS_ATTEST structure */
	size_t offset = 0;
	if ((tss2_rc = Tss2_MU_TPMS_ATTEST_Unmarshal(attest_buf, attest_buf_len,
			 &offset, attest_struct)) != TSS2_RC_SUCCESS) {
		error_msg = "Unmarshal TPMS_ATTEST structure.";
		charra_rc = CHARRA_RC_MARSHALING_ERROR;
		goto error;
	}

error:
	/* print error message */
	if (error_msg != NULL) {
		charra_log_error("%s (CHARRA RC: 0x%04x, TSS2 RC: 0x%04x)", error_msg,
			charra_rc, tss2_rc);
	}

	/* transform TSS2_RC to CHARRA_RC */
	if ((charra_rc == CHARRA_RC_SUCCESS) && (tss2_rc != TSS2_RC_SUCCESS)) {
		charra_rc = CHARRA_RC_TPM;
	}

	return charra_rc;
}

bool charra_verify_tpm2_quote_qualifying_data(uint16_t qualifying_data_len,
	const uint8_t* const qualifying_data,
	const TPMS_ATTEST* const attest_struct) {

	/* verify input parameters */
	if (qualifying_data == NULL) {
		return false;
	} else if (attest_struct == NULL) {
		return false;
	}

	/* compare sizes and content */
	if (attest_struct->extraData.size != qualifying_data_len) {
		return false;
	} else if (memcmp(qualifying_data, attest_struct->extraData.buffer,
				   qualifying_data_len) != 0) {
		return false;
	}

	return true;
}

/* TODO Add specific versions of this function for all supported hash algos,
 * i.e. charra_compute_pcr_composite_digest_sha256_from_ptr_array, etc.,
 * invoking this generic funtion internally with TPM2_SHA256_DIGEST_SIZE, etc.
 */
CHARRA_RC charra_compute_pcr_composite_digest_from_ptr_array(
	uint16_t hash_algo_digest_size CHARRA_UNUSED,
	const uint8_t* expected_pcr_values[] CHARRA_UNUSED,
	size_t expected_pcr_values_len CHARRA_UNUSED,
	uint8_t* pcr_composite_digest CHARRA_UNUSED) {
	// TODO: to be implemented
	return CHARRA_RC_NOT_YET_IMPLEMENTED;
}

bool charra_verify_tpm2_quote_pcr_composite_digest(
	const TPMS_ATTEST* const attest_struct,
	const uint8_t* const pcr_composite_digest,
	const uint16_t pcr_composite_digest_len) {

	/* extract PCR digest from attestation structure */
	TPMS_QUOTE_INFO quote_info = attest_struct->attested.quote;
	const uint8_t* const pcr_digest = quote_info.pcrDigest.buffer;
	uint16_t pcr_digest_size = quote_info.pcrDigest.size;

	/* compare digests */
	if (pcr_digest_size != pcr_composite_digest_len) {
		return false;
	} else if (memcmp(pcr_digest, pcr_composite_digest, pcr_digest_size) != 0) {
		return false;
	}

	return true;
}
