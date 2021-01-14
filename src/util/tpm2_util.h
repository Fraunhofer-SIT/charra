/* SPDX-License-Identifier: BSD-3-Clause */
/*****************************************************************************
 * Copyright 2019, Fraunhofer Institute for Secure Information Technology SIT.
 * All rights reserved.
 ****************************************************************************/

/**
 * @file tpm2_util.h
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

#ifndef TPM2_UTIL_H
#define TPM2_UTIL_H

#include <stdio.h>
#include <tss2/tss2_esys.h>

#include "../common/charra_error.h"

/**
 * @brief Creates a primary key in the endorsement/user hierarchy in the TPM.
 *
 * @param[in,out] ctx The TSS ESAPI context.
 * @param[out] primary_handle The TSS key handle of the generated primary key.
 * @return TSS2_RC The TSS return code.
 */
TSS2_RC tpm2_create_primary_key_rsa2048(
	ESYS_CONTEXT* ctx, ESYS_TR* primary_handle, TPM2B_PUBLIC** out_public);

/**
 * @brief Stores a key in the TPM NVRAM under the first available NV index.
 *
 * @param ctx[in,out] The ESAPI context.
 * @param key_handle[in] The TPM key handle.
 * @return TSS2_RC The TSS return code.
 */
TSS2_RC tpm2_store_key_in_nvram(ESYS_CONTEXT* ctx, const ESYS_TR* key_handle);

/**
 * @brief Extends a TPM 2.0 PCR.
 *
 * @param ctx[in,out] The ESAPI context.
 * @param pcr_idx[in] The PCR index to be extended.
 * @param digests[in] The digests to be extended to the PCR.
 * @return TSS2_RC The TSS return code.
 */
TSS2_RC tpm2_pcr_extend(ESYS_CONTEXT* ctx, const uint32_t pcr_idx,
	const TPML_DIGEST_VALUES* digests);

/**
 * @brief Generates random bytes using the TPM 2.0.
 *
 * @param ctx[in,out] The ESAPI context.
 * @param len[in] Length of the random bytes to be generated.
 * @param random_bytes[out] The generated random bytes.
 * @return TSS2_RC The TSS return code.
 */
TSS2_RC tpm2_get_random(
	ESYS_CONTEXT* ctx, const uint32_t len, TPM2B_DIGEST** random_bytes);

/**
 * @brief Executes a TPM quote operation.
 *
 * @param ctx[in,out] The ESAPI context.
 * @param sign_key_handle[in] The TPM2 handle of the signature key.
 * @param pcr_selection[in] The PCR selection
 * @param qualifying_data[in] The qualifying data, such as a nonce for
 * freshness.
 * @param attest[out] The attestation data structure.
 * @param signature[out] The TPM2 signature over \a attest->attestationData.
 * @return TSS2_RC The TSS return code.
 */
TSS2_RC tpm2_quote(ESYS_CONTEXT* ctx, const ESYS_TR sign_key_handle,
	const TPML_PCR_SELECTION* pcr_selection, const TPM2B_DATA* qualifyingData,
	TPM2B_ATTEST** attest, TPMT_SIGNATURE** signature);

#endif /* TPM2_UTIL_H */
