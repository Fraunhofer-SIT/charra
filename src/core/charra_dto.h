/* SPDX-License-Identifier: BSD-3-Clause */
/*****************************************************************************
 * Copyright 2019, Fraunhofer Institute for Secure Information Technology SIT.
 * All rights reserved.
 ****************************************************************************/

/**
 * @file charra_dto.h
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
#include <stddef.h>
#include <tss2/tss2_tpm2_types.h>

#ifndef CHARRA_DTO_H
#define CHARRA_DTO_H

/* --- data transfer objects ---------------------------------------------- */

typedef struct {
	uint16_t tcg_hash_alg_id; // TPM2_ALG_ID
	uint32_t pcrs_len;
	uint8_t* pcrs; // max = TPM2_MAX_PCRS
} pcr_selection_dto;

/**
 * @brief Frees used memory of a \p pcr_selection_dto object.
 *
 * @param obj[in,out] The \p pcr_selection_dto object.
 */
void destroy_pcr_selection_dto(pcr_selection_dto** obj);

/**
 * @brief Allocates memory for a pcr_selection_dto object.
 *
 * @return The pcr_selection_dto object.
 */
pcr_selection_dto* create_pcr_selection_dto();

/**
 * @brief Allocates memory for an array of pcr_selection_dto objects.
 *
 * @param[in] n Number of elements to allocate.
 * @return The pcr_selection_dto array.
 */
pcr_selection_dto* create_pcr_selection_dto_array(const size_t n);

/**
 * @brief Frees used memory of a \p pcr_selection_dto object.
 *
 * @param obj[in,out] The \p pcr_selection_dto object.
 */
void destroy_pcr_selection_dto(pcr_selection_dto** obj);

/**
 * @brief Frees used memory of a \p pcr_selection_dto array.
 *
 * @param obj[in,out] The \p pcr_selection_dto object.
 * @param[in] n Number of elements to free.
 */
void destroy_pcr_selection_dto_array(pcr_selection_dto** obj, const size_t n);

typedef struct {
	uint64_t clock;
	uint32_t resetCounter;
	uint32_t restartCounter;
	bool safe;
} tpms_clock_info_dto;

typedef struct {
	uint16_t hash; // TPMI_ALG_HASH (TPM2_ALG_ID)
	uint8_t sizeofSelect;
	uint8_t* pcrSelect; // max = TPM2_PCR_SELECT_MAX
} tpms_pcr_selection_dto;

typedef struct {
	uint32_t count;
	tpms_pcr_selection_dto* pcr_selections; // max = TPM2_NUM_PCR_BANKS
} tpml_pcr_selection_dto;

typedef struct {
	uint16_t size;
	uint8_t* buffer; // max = sizeof(TPMU_HA)
} tpm2b_digest_dto;

typedef struct {
	tpml_pcr_selection_dto pcr_select; // TPML_PCR_SELECTION
	tpm2b_digest_dto pcr_digest;	   // TPM2B_DIGEST
} tpms_quote_info_dto;

typedef struct {
	uint16_t qualified_signer; // TPM2B_NAME
	tpms_clock_info_dto clock_info;
	uint64_t firmware_version;
	tpms_quote_info_dto quote;
} tpms_attest_dto;

/* --- messages ----------------------------------------------------------- */

typedef struct {
	bool hello;
	size_t sig_key_id_len;
	uint8_t* sig_key_id;
	size_t nonce_len;
	uint8_t* nonce; // max = sizeof(TPMU_HA)
	uint32_t pcr_selections_len;
	pcr_selection_dto* pcr_selections; // max = TPM2_NUM_PCR_BANKS
} msg_attestation_request_dto;

/**
 * @brief Allocates memory for a msg_attestation_request_dto object.
 *
 * @return The msg_attestation_request_dto object.
 */
msg_attestation_request_dto* create_msg_attestation_request_dto();

/**
 * @brief Allocates memory for an array of msg_attestation_request_dto objects.
 *
 * @param[in] n Number of elements to allocate.
 * @return The msg_attestation_request_dto array.
 */
msg_attestation_request_dto* create_msg_attestation_request_dto_array(
	const size_t n);

/**
 * @brief Frees used memory of a \p msg_attestation_request_dto object.
 *
 * @param obj[in,out] The \p msg_attestation_request_dto object.
 */
void destroy_msg_attestation_request_dto(msg_attestation_request_dto** obj);

typedef struct {
	// tpms_attest_dto attestation_data;
	uint32_t attestation_data_len;
	uint8_t* attestation_data; // TPM2B_ATTEST
	uint32_t tpm2_signature_len;
	uint8_t* tpm2_signature;
} msg_attestation_response_dto;

#endif /* CHARRA_DTO_H */
