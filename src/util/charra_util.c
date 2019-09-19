/* SPDX-License-Identifier: BSD-3-Clause */
/*****************************************************************************
 * Copyright 2019, Fraunhofer Institute for Secure Information Technology SIT.
 * All rights reserved.
 ****************************************************************************/

/**
 * @file charra_util.c
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

#include "charra_util.h"

#include <assert.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <tss2/tss2_tpm2_types.h>

#include "../common/charra_error.h"
#include "../common/charra_log.h"
#include "tpm2_util.h"

CHARRA_RC charra_get_random_bytes(const uint32_t len, uint8_t** random_bytes) {
	assert(len <= sizeof(TPMU_HA));

	TSS2_RC r = 0;
	char* error_msg = NULL;
	ESYS_CONTEXT* ctx = NULL;

	TPM2B_DIGEST* tpm_random_bytes = NULL;

	r = Esys_Initialize(&ctx, NULL, NULL);
	if (r != TSS2_RC_SUCCESS) {
		error_msg = "TPM2 Esys_Initialize failed.";
		goto error;
	}

	r = tpm2_get_random(ctx, len, &tpm_random_bytes);
	if (r != TSS2_RC_SUCCESS) {
		error_msg = "TPM2 get random failed";
		goto error;
	}

	/* set out params */
	*random_bytes = calloc((size_t)len, sizeof(**random_bytes));
	memcpy(*random_bytes, tpm_random_bytes->buffer, len);

error:
	/* print error message */
	if (error_msg != NULL) {
		charra_log_error(error_msg);
	}

	/* free ESAPI objects */
	if (tpm_random_bytes != NULL) {
		Esys_Free(tpm_random_bytes);
	}

	/* finalize ESAPI */
	Esys_Finalize(&ctx);

	return (r == TSS2_RC_SUCCESS) ? CHARRA_RC_SUCCESS : CHARRA_RC_ERROR;
}
