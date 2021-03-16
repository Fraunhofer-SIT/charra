/* SPDX-License-Identifier: BSD-3-Clause */
/*****************************************************************************
 * Copyright 2019, Fraunhofer Institute for Secure Information Technology SIT.
 * All rights reserved.
 ****************************************************************************/

/**
 * @file charra_util.h
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

#include <inttypes.h>
#include <stdbool.h>
#include <tss2/tss2_esys.h>
#include <tss2/tss2_mu.h>
#include <tss2/tss2_tpm2_types.h>

#include "../common/charra_error.h"

#ifndef CHARRA_UTIL_H
#define CHARRA_UTIL_H

/**
 * @brief Retrieve random bytes.
 *
 * @param[in] len the requested number of random bytes.
 * @param[out] random_bytes the random bytes.
 * @return CHARRA_RC_SUCCESS on success.
 * @return CHARRA_RC_ERROR on error.
 */
CHARRA_RC charra_random_bytes(const uint32_t len, uint8_t* random_bytes);

/**
 * @brief Retrieve random bytes from a TPM.
 *
 * @param[in] len the requested number of random bytes.
 * @param[out] random_bytes the random bytes.
 * @return CHARRA_RC_SUCCESS on success.
 * @return CHARRA_RC_ERROR on error.
 */
CHARRA_RC charra_random_bytes_from_tpm(
	const uint32_t len, uint8_t* random_bytes);

/**
 * @brief Verifies a TPM 2.0 quote using the TPM.
 *
 * @param ctx[in,out] The ESAPI context.
 * @param sig_key_handle[in] The TPM2 handle of the signature key.
 * @param attest[in] The attestation data structure.
 * @param signature[in] The TPM2 signature over \a attest->attestationData.
 * @param validation[out] The validation data that holds the verification
 * result.
 * @return TSS2_RC The TSS return code.
 */
CHARRA_RC charra_verify_tpm2_quote_signature_with_tpm(ESYS_CONTEXT* ctx,
	const ESYS_TR sig_key_handle, const TPM2_ALG_ID hash_algo_id,
	const TPM2B_ATTEST* attest_buf, TPMT_SIGNATURE* signature,
	TPMT_TK_VERIFIED** validation);

CHARRA_RC charra_unmarshal_tpm2_quote(size_t attest_buf_len,
	const uint8_t* attest_buf, TPMS_ATTEST* attest_struct);

bool charra_verify_tpm2_quote_qualifying_data(uint16_t qualifying_data_len,
	const uint8_t* const qualifying_data,
	const TPMS_ATTEST* const attest_struct);

bool charra_verify_tpm2_quote_pcrs(TPM2_ALG_ID hash_algo_id,
	const uint8_t* const qualifying_data,
	const TPMS_ATTEST* const attest_struct);

bool charra_verify_tpm2_quote_pcr_composite_digest(
	const TPMS_ATTEST* const attest_struct, const uint8_t* const pcr_composite,
	const uint16_t pcr_composite_len);

#endif /* CHARRA_UTIL_H */
