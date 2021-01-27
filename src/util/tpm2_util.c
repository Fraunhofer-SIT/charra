/* SPDX-License-Identifier: BSD-3-Clause */
/*****************************************************************************
 * Copyright 2019, Fraunhofer Institute for Secure Information Technology SIT.
 * All rights reserved.
 ****************************************************************************/

/**
 * @file tpm2_util.c
 * @author Michael Eckel (michael.eckel@sit.fraunhofer.de)
 * @brief
 * @version 0.1
 * @date 2019-09-19
 *
 * @copyright Copyright 2019, Fraunhofer Institute for Secure Information
 * Technology SIT. All rights reserved.
 *
 * @license BSD 3-Clause "New" or "Revised" License (SPDX-License-Identifier:
 * BSD-3-Clause).
 */

#include "tpm2_util.h"

#include <stdio.h>
#include <string.h>
#include <tss2/tss2_esys.h>
#include <tss2/tss2_mu.h>
#include <tss2/tss2_tpm2_types.h>

#include "../common/charra_error.h"
#include "../common/charra_log.h"

TSS2_RC tpm2_create_primary_key_rsa2048(
	ESYS_CONTEXT* ctx, ESYS_TR* primary_handle, TPM2B_PUBLIC** out_public) {
	TSS2_RC r = TSS2_RC_SUCCESS;
	char* error_msg = NULL;

	/* verify input parameters */
	if (ctx == NULL) {
		error_msg = "Bad ESAPI context.";
		r = TSS2_ESYS_RC_BAD_VALUE;
		goto error;
	} else if (primary_handle == NULL) {
		error_msg = "Bad primary key handle.";
		r = TSS2_ESYS_RC_BAD_VALUE;
		goto error;
	}

	/* authenticate at user/storage hierarchy */
	TPM2B_AUTH authValueSH = {.size = 0, .buffer = {0}};
	if ((r = Esys_TR_SetAuth(ctx, ESYS_TR_RH_OWNER, &authValueSH)) !=
		TSS2_RC_SUCCESS) {
		error_msg = "Esys_TR_SetAuth.";
		goto error;
	}

	/* prepare primary key sensitive part */
	TPM2B_AUTH authValuePK = {.size = 0, .buffer = {0}};
	TPM2B_SENSITIVE_CREATE inSensitivePrimary = {.size = 0,
		.sensitive = {
			.userAuth = authValuePK,
			.data = {.size = 0, .buffer = {0}},
		}};

	/* prepare primary key public part */
	TPM2B_PUBLIC inPublic = {
		.size = 0,
		.publicArea =
			{
				.type = TPM2_ALG_RSA,
				.nameAlg = TPM2_ALG_SHA256,
				.objectAttributes =
					(TPMA_OBJECT_USERWITHAUTH | TPMA_OBJECT_RESTRICTED |
						TPMA_OBJECT_SIGN_ENCRYPT | TPMA_OBJECT_FIXEDTPM |
						TPMA_OBJECT_FIXEDPARENT |
						TPMA_OBJECT_SENSITIVEDATAORIGIN),
				.authPolicy =
					{
						.size = 0,
					},
				.parameters.rsaDetail =
					{
						.symmetric =
							{
								.algorithm = TPM2_ALG_NULL,
								.keyBits.aes = 128,
								.mode.aes = TPM2_ALG_CFB,
							},
						.scheme =
							{
								.scheme = TPM2_ALG_RSAPSS,
								.details = {.rsassa = {.hashAlg =
														   TPM2_ALG_SHA256}},

							},
						.keyBits = 2048,
						.exponent = 0,
					},
				.unique.rsa =
					{
						.size = 0,
						.buffer = {0},
					},
			},
	};

	/* declare/define all needed in and out parameters */
	TPM2B_DATA outsideInfo = {.size = 0, .buffer = {0}};
	TPML_PCR_SELECTION creationPCR = {.count = 0};

	if ((r = Esys_CreatePrimary(ctx, ESYS_TR_RH_OWNER, ESYS_TR_PASSWORD,
			 ESYS_TR_NONE, ESYS_TR_NONE, &inSensitivePrimary, &inPublic,
			 &outsideInfo, &creationPCR, primary_handle, out_public, NULL, NULL,
			 NULL)) != TSS2_RC_SUCCESS) {
		error_msg = "Esys_CreatePrimary";
		goto error;
	} else {
		charra_log_info("Primary Key created successfully.");
	}

	return TSS2_RC_SUCCESS;

error:
	if (error_msg != NULL) {
		charra_log_error("%s", error_msg);
	}

	return r;
}

TSS2_RC tpm2_store_key_in_nvram(ESYS_CONTEXT* ctx, const ESYS_TR* key_handle) {
	TSS2_RC r = TSS2_RC_SUCCESS;
	char* error_msg = NULL;

	/* verify input parameters */
	if (ctx == NULL) {
		error_msg = "Bad ESAPI context.";
		r = TSS2_ESYS_RC_BAD_VALUE;
		goto error;
	} else if (key_handle == NULL) {
		error_msg = "Bad key handle.";
		r = TSS2_ESYS_RC_BAD_VALUE;
		goto error;
	}

	/* store key persistently */
	ESYS_TR primaryPersistentHandle = ESYS_TR_NONE;
	// TPM2_HANDLE nvPersistentHandle = TPM2_PERSISTENT_FIRST;
	TPMI_DH_PERSISTENT nvPersistentHandle = TPM2_PERSISTENT_FIRST;
	if ((r = Esys_EvictControl(ctx, ESYS_TR_RH_OWNER, *key_handle,
			 ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE, nvPersistentHandle,
			 &primaryPersistentHandle)) != TSS2_RC_SUCCESS) {
		error_msg = "Esys_EvictControl";
		goto error;
	} else {
		charra_log_info("Primary Key successfully stored in NVRAM.");
	}

	return TSS2_RC_SUCCESS;

error:
	if (error_msg != NULL) {
		charra_log_error("%s", error_msg);
	}

	return r;
}

TSS2_RC tpm2_pcr_extend(ESYS_CONTEXT* ctx, const uint32_t pcr_idx,
	const TPML_DIGEST_VALUES* digests) {
	TSS2_RC r = TSS2_RC_SUCCESS;
	char* error_msg = NULL;

	/* verify input parameters */
	if (ctx == NULL) {
		error_msg = "Bad ESAPI context.";
		r = TSS2_ESYS_RC_BAD_VALUE;
		goto error;
	}

	r = Esys_PCR_Extend(
		ctx, pcr_idx, ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE, digests);

	/*ERROR CHECK*/
	if (r != TSS2_RC_SUCCESS) {
		error_msg = "Esys_PCR_Extend";
		goto error;
	}

	return TSS2_RC_SUCCESS;

error:
	if (error_msg != NULL) {
		charra_log_error("%s", error_msg);
	}

	return r;
}

TSS2_RC tpm2_get_random(
	ESYS_CONTEXT* ctx, const uint32_t len, TPM2B_DIGEST** random_bytes) {
	TSS2_RC r = TSS2_RC_SUCCESS;
	char* error_msg = NULL;

	/* verify input parameters */
	if (ctx == NULL) {
		error_msg = "Bad ESAPI context.";
		r = TSS2_ESYS_RC_BAD_VALUE;
		goto error;
	} else if (random_bytes == NULL || *random_bytes != NULL) {
		error_msg = "Bad reference to random bytes (NULL pointer).";
		r = TSS2_ESYS_RC_BAD_VALUE;
		goto error;
	}

	/* get random bytes */
	r = Esys_GetRandom(
		ctx, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, len, random_bytes);

	/*ERROR CHECK*/
	if (r != TSS2_RC_SUCCESS) {
		error_msg = "Esys_GetRandom";
		goto error;
	}

	return TSS2_RC_SUCCESS;

error:
	if (error_msg != NULL) {
		charra_log_error("%s", error_msg);
	}

	return r;
}

TSS2_RC tpm2_quote(ESYS_CONTEXT* ctx, const ESYS_TR sign_key_handle,
	const TPML_PCR_SELECTION* pcr_selection, const TPM2B_DATA* qualifying_data,
	TPM2B_ATTEST** attest_buf, TPMT_SIGNATURE** signature) {
	TSS2_RC r = TSS2_RC_SUCCESS;
	char* error_msg = NULL;

	/* verify input parameters */
	if (ctx == NULL) {
		error_msg = "Bad ESAPI context.";
		r = TSS2_ESYS_RC_BAD_VALUE;
		goto error;
	}

	/* check whether size limit is exceeded */
	if (qualifying_data->size > sizeof(TPMT_HA)) {
		error_msg = "Size of qualifying data exceeded (max = sizeof(TPMT_HA)";
		r = TSS2_ESYS_RC_BAD_VALUE;
		goto error;
	}

	/* do the TPM quote*/
	TPMT_SIG_SCHEME sig_scheme = {.scheme = TPM2_ALG_NULL};
	r = Esys_Quote(ctx, sign_key_handle, ESYS_TR_PASSWORD, ESYS_TR_NONE,
		ESYS_TR_NONE, qualifying_data, &sig_scheme, pcr_selection, attest_buf,
		signature);
	/* ERROR CHECK */
	if (r != TSS2_RC_SUCCESS) {
		error_msg = "Esys_Quote";
		goto error;
	}

	return TSS2_RC_SUCCESS;

error:
	if (error_msg != NULL) {
		charra_log_error("%s", error_msg);
	}

	return r;
}
