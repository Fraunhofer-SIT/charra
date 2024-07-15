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

#include <errno.h>

#include "../common/charra_error.h"
#include "../common/charra_log.h"
#include "../common/charra_macro.h"
#include "../util/io_util.h"
#include "parser_util.h"

#include <string.h>
#include <tss2/tss2_tpm2_types.h>

/* a byte is represented as 2 characters in a hex string + 2 bytes for the
 * characters "0x" */
#define SHA256_HEX_STR_SIZE (TPM2_SHA256_DIGEST_SIZE * 2 + 2)

CHARRA_RC parse_pcr_value(char* start, size_t length, uint8_t* pcr_value) {
    if (length != SHA256_HEX_STR_SIZE) {
        return CHARRA_RC_ERROR;
    }
    /* string should start with 0x */
    if (*start != '0' || *(start + 1) != 'x') {
        return CHARRA_RC_ERROR;
    }
    char* hex_start = start + 2;

    // iterate over all bytes of the digest
    for (uint32_t digest_index = 0; digest_index < TPM2_SHA256_DIGEST_SIZE;
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
        errno = 0;
        char* eol = NULL;
        uint32_t hex_value = strtoul(byte_as_string, &eol, 16);
        if (eol == byte_as_string || errno != 0 || hex_value > 255) {
            return CHARRA_RC_ERROR;
        }
        pcr_value[digest_index] = (uint8_t)hex_value;
    }
    return CHARRA_RC_SUCCESS;
}

int parse_pcr_index(char* index_start) {
    errno = 0;
    char* end = NULL;
    int pcr_index = strtoul(index_start, &end, 10);  // parse digits as index
    if (end == index_start || *end != '\0' || errno != 0 ||
            pcr_index >= TPM2_MAX_PCRS) {
        return -1;
    }
    return pcr_index;
}

static charra_tap_pcr_logs_t parse_pcr_log_identifier(
        const char* const identifier) {
    if (strcmp("ima", identifier) == 0) {
        return CHARRA_TAP_PCR_LOG_IMA;
    } else if (strcmp("tcg-boot", identifier) == 0) {
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
    response->identifier = request->identifier;
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
