/* SPDX-License-Identifier: BSD-3-Clause */
/*****************************************************************************
 * Copyright 2024, Fraunhofer Institute for Secure Information Technology SIT.
 * All rights reserved.
 ****************************************************************************/

/**
 * @file charra_tap_dto.h
 * @author Markus Horn (markus.horn@sit.fraunhofer.de)
 * @brief
 * @version 0.1
 * @date 2024-03-18
 *
 * @copyright Copyright 2024, Fraunhofer Institute for Secure Information
 * Technology SIT. All rights reserved.
 *
 * @license BSD 3-Clause "New" or "Revised" License (SPDX-License-Identifier:
 * BSD-3-Clause).
 */

#ifndef CHARRA_TAP_DTO_H
#define CHARRA_TAP_DTO_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <tss2/tss2_tpm2_types.h>

#define SIG_KEY_ID_MAXLEN 256
#define SUPPORTED_PCR_LOGS_COUNT 2
#define CHARRA_TAP_SPEC_VERSION 0x00000000020200

typedef enum {
    CHARRA_TAP_PCR_LOG_ERROR = 0,
    CHARRA_TAP_PCR_LOG_IMA = 1,
    CHARRA_TAP_PCR_LOG_TCG_BOOT = 2,
} charra_tap_pcr_logs_t;

/* TAP data transfer objects */

typedef struct {
    uint32_t pcr_log_len;
    uint8_t* pcr_log;
} charra_tap_pcr_log_values_dto;

typedef struct {
    uint32_t attestation_data_len;
    uint8_t attestation_data[sizeof(TPM2B_ATTEST)];
    uint32_t tpm2_signature_len;
    uint8_t tpm2_signature[sizeof(TPMT_SIGNATURE)];
} charra_tap_explicit_attestation_tpm2_quote_dto;

/* Charra response and request data transfer objects */

typedef struct {
    TPM2_ALG_ID tcg_hash_alg_id;  // TPM2_ALG_ID
    uint32_t pcrs_len;
    uint8_t pcrs[TPM2_MAX_PCRS];
} pcr_selection_dto;

typedef struct {
    char* identifier;
    uint64_t start;
    uint64_t count;
} pcr_log_dto;

typedef struct {
    uint64_t tap_spec_version;
    bool hello;
    /* TODO: Integration of TPM ID (if multiple are available) */
    size_t tpm_id_len;
    uint8_t* tpm_id;
    size_t sig_key_id_len;
    uint8_t sig_key_id[SIG_KEY_ID_MAXLEN];
    size_t nonce_len;
    uint8_t nonce[sizeof(TPMU_HA)];
    uint32_t pcr_selections_len;
    pcr_selection_dto pcr_selections[TPM2_NUM_PCR_BANKS];
    uint32_t pcr_log_len;
    pcr_log_dto* pcr_logs;
} charra_tap_msg_attestation_request_dto;

typedef struct {
    char* identifier;
    uint64_t start;
    uint64_t count;
    uint64_t content_len;
    uint8_t* content;
} pcr_log_response_dto;

typedef struct {
    charra_tap_explicit_attestation_tpm2_quote_dto tpm2_quote;
    uint32_t pcr_log_len;
    pcr_log_response_dto* pcr_logs;
} charra_tap_msg_attestation_response_dto;

#endif /* CHARRA_TAP_DTO_H */
