/* SPDX-License-Identifier: BSD-3-Clause */
/*****************************************************************************
 * Copyright 2019, Fraunhofer Institute for Secure Information Technology SIT.
 * All rights reserved.
 ****************************************************************************/

/**
 * @file charra_rim_mgr.c
 * @author Michael Eckel (michael.eckel@sit.fraunhofer.de)
 * @author Markus Horn (markus.horn@sit.fraunhofer.de)
 * @brief
 * @version 0.1
 * @date 2020-09-19
 *
 * @copyright Copyright 2019, Fraunhofer Institute for Secure Information
 * Technology SIT. All rights reserved.
 *
 * @license BSD 3-Clause "New" or "Revised" License (SPDX-License-Identifier:
 * BSD-3-Clause).
 */

#include "charra_rim_mgr.h"

#include <stdint.h>
#include <string.h>
#include <sys/types.h>
#include <tss2/tss2_tpm2_types.h>

#include "../common/charra_log.h"
#include "../util/crypto_util.h"
#include "../util/parser_util.h"
#include "../util/yaml_util.h"

#define BUFFER_LEN 1024
#define KEY_SHA1 "sha1"
#define KEY_SHA256 "sha256"
#define KEY_SHA384 "sha384"
#define KEY_SHA512 "sha512"

typedef struct {
    uint8_t reference_pcrs[TPM2_PCR_BANK_COUNT][TPM2_MAX_PCRS]
                          [MBEDTLS_MD_MAX_SIZE];
    bool reference_pcrs_set[TPM2_PCR_BANK_COUNT][TPM2_MAX_PCRS];
    const uint8_t (*const reference_pcr_selection)[TPM2_MAX_PCRS];
    const uint8_t* const reference_pcr_selection_len;
    const TPMS_ATTEST* const attest_struct;
    const mbedtls_md_type_t signature_hash_algorithm;
    TPM2_ALG_ID current_hash_algorithm;
    charra_tpm_pcr_bank_index current_pcr_bank_index;
    uint32_t pcr_set_index;
    bool are_pcrs_valid;
} attest_verification_t;

static bool check_if_index_is_in_selection(
        const uint8_t* const reference_pcr_selection,
        const uint8_t reference_pcr_selection_len, const uint8_t index) {
    for (uint8_t i = 0; i < reference_pcr_selection_len; i++) {
        if (reference_pcr_selection[i] == index) {
            return true;
        }
    }
    return false;
}

static bool check_if_all_reference_pcrs_are_found(
        const attest_verification_t* const attest_verification) {
    const uint8_t (*const reference_pcr_selection)[TPM2_MAX_PCRS] =
            attest_verification->reference_pcr_selection;
    const uint8_t* const reference_pcr_selection_len =
            attest_verification->reference_pcr_selection_len;
    const bool (*const reference_pcrs_set)[TPM2_MAX_PCRS] =
            attest_verification->reference_pcrs_set;
    for (uint8_t i = 0; i < TPM2_PCR_BANK_COUNT; i++) {
        for (uint8_t j = 0; j < reference_pcr_selection_len[i]; j++) {
            uint8_t pcr_index = reference_pcr_selection[i][j];
            if (!reference_pcrs_set[i][pcr_index]) {
                return false;
            }
        }
    }
    return true;
}

static void format_reference_pcrs_for_verification(
        const uint8_t (*const reference_pcr_selection)[TPM2_MAX_PCRS],
        const uint8_t* const reference_pcr_selection_len,
        const uint8_t (*const reference_pcrs)[TPM2_MAX_PCRS]
                                             [MBEDTLS_MD_MAX_SIZE],
        const uint8_t* formatted_pcrs[TPM2_PCR_BANK_COUNT][TPM2_MAX_PCRS],
        uint32_t* const formatted_pcrs_len) {
    for (uint8_t i = 0; i < TPM2_PCR_BANK_COUNT; i++) {
        formatted_pcrs_len[i] = reference_pcr_selection_len[i];
        for (uint8_t j = 0; j < reference_pcr_selection_len[i]; j++) {
            uint8_t pcr_index = reference_pcr_selection[i][j];
            formatted_pcrs[i][j] = reference_pcrs[i][pcr_index];
        }
    }
}

/**
 * @brief Check if all requested PCRs are set in the current YAML document and
 * then compute their digest which will be compared against the digest given in
 * the attest_struct. If both digests match, are_pcrs_valid is set to
 * true.
 *
 * @param parser_state The current YAML parser state. (not used in this
 * function)
 * @param data The attest_verification struct holding the
 * reference PCRs and the attest struct
 */
static CHARRA_RC handle_end_of_pcr_set(
        const charra_yaml_parser_state_t* const parser_state
        __attribute__((unused)),
        void* data) {
    attest_verification_t* attest_verification = (attest_verification_t*)data;

    if (!check_if_all_reference_pcrs_are_found(attest_verification)) {
        charra_log_warn("Not all requested PCRs are set in the reference PCR "
                        "file at index: %u. Skipping this set.",
                attest_verification->pcr_set_index);
        goto cleanup;
    }

    const uint8_t* formatted_pcrs[TPM2_PCR_BANK_COUNT][TPM2_MAX_PCRS] = {0};
    uint32_t formatted_pcrs_len[TPM2_PCR_BANK_COUNT] = {0};

    format_reference_pcrs_for_verification(
            attest_verification->reference_pcr_selection,
            attest_verification->reference_pcr_selection_len,
            (const uint8_t (*const)[TPM2_MAX_PCRS][MBEDTLS_MD_MAX_SIZE])
                    attest_verification->reference_pcrs,
            formatted_pcrs, formatted_pcrs_len);

    charra_log_debug("Checking PCR composite digest at PCR set index %d:",
            attest_verification->pcr_set_index);

    CHARRA_RC rc = compute_and_check_PCR_digest(
            (const uint8_t* const(*)[TPM2_MAX_PCRS])formatted_pcrs,
            formatted_pcrs_len, attest_verification->attest_struct,
            attest_verification->signature_hash_algorithm);
    if (rc == CHARRA_RC_ERROR) {
        charra_log_error("Unexpected error while computing PCR digest at index "
                         "%d of the PCR sets",
                attest_verification->pcr_set_index);
    } else if (rc == CHARRA_RC_SUCCESS) {
        charra_log_info("Found matching PCR composite digest at index %d of "
                        "the PCR sets.",
                attest_verification->pcr_set_index);
        attest_verification->are_pcrs_valid = true;
    }

cleanup:
    // resetting reference PCRs for the next set of PCRs
    memset(attest_verification->reference_pcrs, 0,
            sizeof(attest_verification->reference_pcrs));
    memset(attest_verification->reference_pcrs_set, 0,
            sizeof(attest_verification->reference_pcrs_set));
    attest_verification->pcr_set_index++;

    return CHARRA_RC_SUCCESS;
}

static CHARRA_RC hash_field_handler(charra_yaml_parser_state_t* parser_state,
        const char* const key, void* data) {
    CHARRA_RC charra_rc = CHARRA_RC_SUCCESS;
    attest_verification_t* attest_verification = (attest_verification_t*)data;

    char string_value[BUFFER_LEN] = {0};
    uint8_t pcr_index = 0;

    charra_rc = parse_pcr_index(key, &pcr_index);
    if (charra_rc != CHARRA_RC_SUCCESS) {
        CHARRA_YAML_PARSER_ERROR_LOG(
                parser_state->parser, "invalid index value");
        return charra_rc;
    }
    charra_rc = parse_yaml_string_value(parser_state, string_value, BUFFER_LEN);
    if (charra_rc != CHARRA_RC_SUCCESS) {
        return charra_rc;
    }

    if (!check_if_index_is_in_selection(
                attest_verification->reference_pcr_selection[attest_verification
                                ->current_pcr_bank_index],
                attest_verification->reference_pcr_selection_len
                        [attest_verification->current_pcr_bank_index],
                pcr_index)) {
        return charra_rc;
    }
    charra_rc = parse_pcr_value(string_value, strlen(string_value),
            attest_verification->reference_pcrs[attest_verification
                            ->current_pcr_bank_index][pcr_index],
            attest_verification->current_hash_algorithm);
    if (charra_rc != CHARRA_RC_SUCCESS) {
        CHARRA_YAML_PARSER_ERROR_LOG_F(
                parser_state->parser, "invalid pcr value '%s'", string_value);
        return charra_rc;
    }
    attest_verification->reference_pcrs_set[attest_verification
                    ->current_pcr_bank_index][pcr_index] = true;
    return charra_rc;
}

static CHARRA_RC reference_pcr_file_field_handler(
        charra_yaml_parser_state_t* parser_state, const char* const key,
        void* data) {
    CHARRA_RC charra_rc = CHARRA_RC_SUCCESS;
    attest_verification_t* attest_verification = (attest_verification_t*)data;

    if (strncmp(key, KEY_SHA1, sizeof(KEY_SHA1)) == 0) {
        attest_verification->current_hash_algorithm = TPM2_ALG_SHA1;
        attest_verification->current_pcr_bank_index = CHARRA_TPM_PCR_BANK_SHA1;
    } else if (strncmp(key, KEY_SHA256, sizeof(KEY_SHA256)) == 0) {
        attest_verification->current_hash_algorithm = TPM2_ALG_SHA256;
        attest_verification->current_pcr_bank_index =
                CHARRA_TPM_PCR_BANK_SHA256;
    } else if (strncmp(key, KEY_SHA384, sizeof(KEY_SHA384)) == 0) {
        attest_verification->current_hash_algorithm = TPM2_ALG_SHA384;
        attest_verification->current_pcr_bank_index =
                CHARRA_TPM_PCR_BANK_SHA384;
    } else if (strncmp(key, KEY_SHA512, sizeof(KEY_SHA512)) == 0) {
        attest_verification->current_hash_algorithm = TPM2_ALG_SHA512;
        attest_verification->current_pcr_bank_index =
                CHARRA_TPM_PCR_BANK_SHA512;
    } else {
        charra_rc = CHARRA_RC_ERROR;
        CHARRA_YAML_PARSER_ERROR_LOG_F(
                parser_state->parser, "unknown field '%s'", key);
        return charra_rc;
    }

    charra_rc = parse_yaml_mapping(
            parser_state, hash_field_handler, attest_verification);
    if (charra_rc != CHARRA_RC_SUCCESS) {
        return charra_rc;
    }

    return charra_rc;
}

CHARRA_RC charra_check_pcr_digest_against_reference(const char* const filename,
        const uint8_t (*const reference_pcr_selection)[TPM2_MAX_PCRS],
        const uint8_t* const reference_pcr_selection_len,
        const TPMS_ATTEST* const attest_struct,
        mbedtls_md_type_t signature_hash_algorithm) {
    CHARRA_RC charra_rc = CHARRA_RC_ERROR;

    attest_verification_t attest_verification = {
            .reference_pcr_selection = reference_pcr_selection,
            .reference_pcr_selection_len = reference_pcr_selection_len,
            .attest_struct = attest_struct,
            .signature_hash_algorithm = signature_hash_algorithm,
            .current_hash_algorithm = TPM2_ALG_NULL,
            .current_pcr_bank_index = CHARRA_TPM_PCR_BANK_UNKNOWN,
            .pcr_set_index = 0,
            .are_pcrs_valid = false,
    };
    memset(attest_verification.reference_pcrs, 0,
            sizeof(attest_verification.reference_pcrs));
    memset(attest_verification.reference_pcrs_set, 0,
            sizeof(attest_verification.reference_pcrs_set));
    memset(attest_verification.reference_pcrs, 0,
            sizeof(attest_verification.reference_pcrs));

    charra_rc = parse_yaml_file(filename, reference_pcr_file_field_handler,
            handle_end_of_pcr_set, &attest_verification);

    if (attest_verification.are_pcrs_valid) {
        /* ignore parsing errors in the reference file if the PCR values are
         * already verified */
        charra_rc = CHARRA_RC_SUCCESS;
    } else if (charra_rc != CHARRA_RC_ERROR) {
        charra_rc = CHARRA_RC_VERIFICATION_FAILED;
    }

    return charra_rc;
}
