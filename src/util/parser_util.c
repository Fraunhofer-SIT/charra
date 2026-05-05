/* SPDX-License-Identifier: BSD-3-Clause */
/*****************************************************************************
 * Copyright 2021, Fraunhofer Institute for Secure Information Technology SIT.
 * All rights reserved.
 ****************************************************************************/

/**
 * @file parser_util.c
 * @author Dominik Lorych (dominik.lorych@sit.fraunhofer.de)
 * @author Markus Horn (markus.horn@sit.fraunhofer.de)
 * @brief
 * @version 0.1
 * @date 2021-03-23
 *
 * @copyright Copyright 2021, Fraunhofer Institute for Secure Information
 * Technology SIT. All rights reserved.
 *
 * @license BSD 3-Clause "New" or "Revised" License (SPDX-License-Identifier:
 * BSD-3-Clause).
 */

#include "parser_util.h"

#include <errno.h>
#include <stdint.h>
#include <string.h>

#include <tss2/tss2_tpm2_types.h>

#include "../common/charra_error.h"
#include "../common/charra_log.h"
#include "../common/charra_macro.h"
#include "../util/io_util.h"

/* a byte is represented as 2 characters in a hex string + 2 bytes for the
 * characters "0x" */
#define DIGEST_TO_HEX_STR_SIZE(DIGEST_SIZE) ((DIGEST_SIZE) * 2 + 2)

CHARRA_RC parse_pcr_value(char* start, size_t length, uint8_t* pcr_value,
        TPM2_ALG_ID hash_algorithm) {
    uint32_t digest_size = 0;
    switch (hash_algorithm) {
    case TPM2_ALG_SHA1:
        digest_size = TPM2_SHA1_DIGEST_SIZE;
        break;
    case TPM2_ALG_SHA256:
        digest_size = TPM2_SHA256_DIGEST_SIZE;
        break;
    case TPM2_ALG_SHA384:
        digest_size = TPM2_SHA384_DIGEST_SIZE;
        break;
    case TPM2_ALG_SHA512:
        digest_size = TPM2_SHA512_DIGEST_SIZE;
        break;
    default:
        return CHARRA_RC_ERROR;
    }

    if (length != DIGEST_TO_HEX_STR_SIZE(digest_size)) {
        return CHARRA_RC_ERROR;
    }

    /* string should start with 0x */
    if (*start != '0' || *(start + 1) != 'x') {
        return CHARRA_RC_ERROR;
    }
    char* hex_start = start + 2;

    // iterate over all bytes of the digest
    for (uint32_t digest_index = 0; digest_index < digest_size;
            digest_index++) {
        // hex_index is the byte in string representation at the
        // current digest_index
        char* hex_index = hex_start + (digest_index * 2);

        // convert byte in string representation to byte as uint8_t
        char byte_as_string[3] = {0};
        // copy substring into other string because otherwise strtoul
        // would read more than one byte
        memcpy(byte_as_string, hex_index, 2);
        byte_as_string[2] = '\0';
        uint64_t hex_value = 0;
        if (parse_ulong(byte_as_string, 16, &hex_value) != CHARRA_RC_SUCCESS) {
            return CHARRA_RC_ERROR;
        }
        pcr_value[digest_index] = (uint8_t)hex_value;
    }
    return CHARRA_RC_SUCCESS;
}

CHARRA_RC parse_pcr_index(const char* const index_start, uint8_t* const index) {
    CHARRA_RC charra_rc = CHARRA_RC_SUCCESS;
    uint64_t long_value = 0;

    charra_rc = parse_ulong(index_start, 10, &long_value);
    if (charra_rc != CHARRA_RC_SUCCESS) {
        return charra_rc;
    }
    if (long_value >= TPM2_MAX_PCRS) {
        return CHARRA_RC_ERROR;
    }
    *index = (uint8_t)long_value;
    return charra_rc;
}

static charra_tap_pcr_logs_t parse_pcr_log_identifier(
        const char* const identifier) {
    if (strncmp(CHARRA_TAP_PCR_LOG_IMA_STR, identifier,
                sizeof(CHARRA_TAP_PCR_LOG_IMA_STR)) == 0) {
        return CHARRA_TAP_PCR_LOG_IMA;
    } else if (strncmp(CHARRA_TAP_PCR_LOG_TCG_BOOT_STR, identifier,
                       sizeof(CHARRA_TAP_PCR_LOG_TCG_BOOT_STR)) == 0) {
        return CHARRA_TAP_PCR_LOG_TCG_BOOT;
    } else {
        return CHARRA_TAP_PCR_LOG_ERROR;
    }
}

static CHARRA_RC parse_pcr_ima_log(const char* const log_name,
        const char* const ima_log_path, const pcr_log_dto* const request,
        pcr_log_response_dto* response) {
    size_t ima_log_len = 0;
    uint8_t* ima_log = NULL;
    if (request->start == 0 || ima_log_path == NULL ||
            charra_io_file_exists(ima_log_path) == CHARRA_RC_ERROR) {
        response->start = 1;
        response->count = 0;
        response->content_len = 0;
        response->content = NULL;
        charra_log_info("[%s] Sending empty ima log.", log_name);
        return CHARRA_RC_SUCCESS;
    }
    // TODO: implement the actual parsing
    charra_log_info("[%s] Reading IMA log.", log_name);
    CHARRA_RC rc =
            charra_io_read_file(ima_log_path, (char**)&ima_log, &ima_log_len);
    if (rc != CHARRA_RC_SUCCESS) {
        charra_log_error("[%s] Error while reading IMA log. "
                         "Sending empty log!",
                log_name);
        response->start = 1;
        response->count = 0;
        response->content_len = ima_log_len;
        response->content = ima_log;
    } else {
        charra_log_info(
                "[%s] IMA log has a size of %d bytes.", log_name, ima_log_len);
        response->start = 1;
        response->count = 0;
        response->content_len = ima_log_len;
        response->content = ima_log;
    }
    return rc;
}

static CHARRA_RC parse_pcr_tcg_boot_log(const char* const log_name,
        const char* const tcg_boot_log_path, const pcr_log_dto* const request,
        pcr_log_response_dto* response) {
    size_t tcg_boot_log_len = 0;
    uint8_t* tcg_boot_log = NULL;
    if (request->start == 0 || tcg_boot_log_path == NULL ||
            charra_io_file_exists(tcg_boot_log_path) == CHARRA_RC_ERROR) {
        response->start = 1;
        response->count = 0;
        response->content_len = 0;
        response->content = NULL;
        charra_log_info("[%s] Sending empty tcg-boot log.", log_name);
        return CHARRA_RC_SUCCESS;
    }
    // TODO: implement the actual parsing

    charra_log_info("[%s] Reading tcg-boot log.", log_name);
    CHARRA_RC rc = charra_io_read_file(
            tcg_boot_log_path, (char**)&tcg_boot_log, &tcg_boot_log_len);
    if (rc != CHARRA_RC_SUCCESS) {
        charra_log_error("[%s] Error while reading tcg-boot log. Sending "
                         "empty log!",
                log_name);
        response->start = 1;
        response->count = 0;
        response->content_len = 0;
        response->content = NULL;
    } else {
        charra_log_info("[%s] tcg-boot log has a size of %d bytes.", log_name,
                tcg_boot_log_len);
        response->start = 1;
        response->count = 0;
        response->content_len = tcg_boot_log_len;
        response->content = tcg_boot_log;
    }
    return rc;
}

CHARRA_RC parse_pcr_log_request(const char* const log_name,
        const char* const ima_log_path, const char* const tcg_boot_log_path,
        const pcr_log_dto* const request, pcr_log_response_dto* response) {
    /* TODO: handle memory allocations */
    memcpy(response->identifier, request->identifier,
            CHARRA_TAP_PCR_LOG_IDENTIFIER_MAXLEN);
    switch (parse_pcr_log_identifier(request->identifier)) {
    case CHARRA_TAP_PCR_LOG_IMA:
        return parse_pcr_ima_log(log_name, ima_log_path, request, response);
    case CHARRA_TAP_PCR_LOG_TCG_BOOT:
        return parse_pcr_tcg_boot_log(
                log_name, tcg_boot_log_path, request, response);
    case CHARRA_TAP_PCR_LOG_ERROR:
        charra_log_info("[%s] Received unknown log identifier request: %s",
                log_name, request->identifier);
        response->start = 0;
        response->count = 0;
        response->content_len = 0;
        response->content = NULL;
        break;
    }
    return CHARRA_RC_SUCCESS;
}

CHARRA_RC parse_long(const char* const string, int base, int64_t* const value) {
    if (string == NULL || value == NULL) {
        return CHARRA_RC_BAD_ARGUMENT;
    }

    errno = 0;
    const char* value_start_index = string;
    int64_t tmp_value = 0;
    char* end = NULL;

    /* skip leading spaces */
    while (*value_start_index == ' ') {
        value_start_index++;
    }

    tmp_value = strtoll(value_start_index, &end, base);
    if (end == value_start_index || *end != '\0' || errno != 0) {
        return CHARRA_RC_ERROR;
    }

    *value = tmp_value;
    return CHARRA_RC_SUCCESS;
}

CHARRA_RC parse_ulong(
        const char* const string, int base, uint64_t* const value) {
    if (string == NULL || value == NULL) {
        return CHARRA_RC_BAD_ARGUMENT;
    }

    errno = 0;
    const char* value_start_index = string;
    uint64_t tmp_value = 0;
    char* end = NULL;

    /* skip leading spaces */
    while (*value_start_index == ' ') {
        value_start_index++;
    }

    tmp_value = strtoull(value_start_index, &end, base);
    if (end == value_start_index || *end != '\0' || errno != 0 ||
            *value_start_index == '-') {
        return CHARRA_RC_ERROR;
    }

    *value = tmp_value;
    return CHARRA_RC_SUCCESS;
}
