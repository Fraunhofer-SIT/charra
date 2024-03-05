/* SPDX-License-Identifier: BSD-3-Clause */
/*****************************************************************************
 * Copyright 2021, Fraunhofer Institute for Secure Information Technology SIT.
 * All rights reserved.
 ****************************************************************************/

/**
 * @file parser_util.c
 * @author Dominik Lorych (dominik.lorych@sit.fraunhofer.de)
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
#include <tss2/tss2_tpm2_types.h>

/* a byte is represented as 2 characters in a hex string + 2 bytes for the characters "0x" */
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

char* find_end_of_line(char* start, char* end) {
    for (char* c = start; c < end; c++) {
        if (*c == '\n') {
            return c;
        }
    }  // loop ends when end of file or end of line is reached
    return end;
}

int parse_pcr_index(char* index_start) {
    errno = 0;
    char* end = NULL;
    int pcr_index = strtoul(index_start, &end, 10);  // parse digits as index
    if (end == index_start || errno != 0 || pcr_index >= TPM2_MAX_PCRS) {
        return -1;
    }
    return pcr_index;
}
