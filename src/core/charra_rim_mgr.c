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

#include <yaml.h>

#include "../common/charra_error.h"
#include "../common/charra_log.h"
#include "../common/charra_macro.h"
#include "../util/crypto_util.h"
#include "../util/io_util.h"
#include "../util/parser_util.h"

#define SKIP_BLOCK_MAPPING_START_TOKEN(token_type)                             \
    ((token_type) == YAML_BLOCK_MAPPING_START_TOKEN)

static uint32_t pcr_selection_index = 0;
static uint32_t pcr_set_index = 0;
static uint32_t pcr_set_ending_line = 0;

static void free_reference_pcrs(
        uint8_t** reference_pcrs, uint32_t reference_pcr_selection_len) {
    for (uint32_t i = 0; i < reference_pcr_selection_len; i++) {
        free(reference_pcrs[i]);
    }
    free(reference_pcrs);
}

/**
 * @brief Check that the last reference PCR set was complete and then compute
 * its digest and compare it against the digest given in the attest_struct.
 *
 * @param reference_pcrs the 2D array holding all PCR values needed for the
 * PCR composite digest
 * @param reference_pcr_selection the array holding the PCR indexes used for
 * to compute the digest. Only used for logging purposes.
 * @param reference_pcr_selection_len the number of PCR indexes used for the
 * computation of the digest, also the length of both arrays
 * @param attest_struct The struct holding the attestation data from the
 * attester, including the PCR digest.
 * @returns CHARRA_RC_SUCCESS on success, CHARRA_RC_NO_MATCH when the digests
 * did not match, CHARRA_RC_ERROR on errors.
 */
static CHARRA_RC handle_end_of_pcr_set(uint8_t** reference_pcrs,
        const uint8_t* reference_pcr_selection,
        const uint32_t reference_pcr_selection_len,
        const TPMS_ATTEST* const attest_struct) {
    if (pcr_selection_index < reference_pcr_selection_len) {
        // we found an empty newline, but the previous set of PCRs was not
        // complete.
        charra_log_error(
                "Error while parsing reference PCRs: "
                "PCR set ending in line %d does not hold selected PCR %d.",
                pcr_set_ending_line,
                reference_pcr_selection[pcr_selection_index]);
        return CHARRA_RC_ERROR;
    }

    charra_log_debug("Checking PCR composite digest at PCR set index %d:",
            pcr_set_index);
    CHARRA_RC rc = compute_and_check_PCR_digest(
            reference_pcrs, reference_pcr_selection_len, attest_struct);
    if (rc == CHARRA_RC_ERROR) {
        charra_log_error("Unexpected error while computing PCR digest at index "
                         "%d of the PCR sets",
                pcr_set_index);
    } else if (rc == CHARRA_RC_SUCCESS) {
        charra_log_info("Found matching PCR composite digest at index %d of "
                        "the PCR sets.",
                pcr_set_index);
    }
    return rc;
}

/**
 * @brief Parses a YAML token from the input file.
 *
 * @param parser a pointer to the parser
 * @param token a pointer to the YAML token
 * @returns CHARRA_RC_SUCCESS on success, CHARRA_RC_ERROR on errors.
 */
static CHARRA_RC parse_token(yaml_parser_t* parser, yaml_token_t* token) {
    if (yaml_parser_scan(parser, token) == 0) {
        if (parser->problem_mark.line || parser->problem_mark.column) {
            charra_log_error("Parse error: %s [Line: %lu, Column: %lu]",
                    parser->problem, parser->problem_mark.line + 1,
                    parser->problem_mark.column + 1);
        } else {
            charra_log_error("Parse error: %s", parser->problem);
        }
        return CHARRA_RC_ERROR;
    }
    return CHARRA_RC_SUCCESS;
}

/**
 * @brief Parses a YAML mapping containing a PCR list. All PCR values whose
 * indexes are included in `reference_pcr_selection` will be parsed and stored
 * in `reference_pcrs`. This function should only be called if the parser has
 * previously parsed a `YAML_BLOCK_MAPPING_START_TOKEN`.
 *
 * @param parser a pointer to the parser
 * @param reference_pcrs the 2D array holding all PCR values needed for the
 * PCR composite digest
 * @param reference_pcr_selection the array holding the PCR indexes used for
 * to compute the digest.
 * @param reference_pcr_selection_len the number of PCR indexes used for the
 * computation of the digest, also the length of both arrays
 * @returns CHARRA_RC_SUCCESS on success, CHARRA_RC_ERROR on errors.
 */
static CHARRA_RC parse_pcr_mapping(yaml_parser_t* parser,
        uint8_t** reference_pcrs, const uint8_t* reference_pcr_selection,
        const uint32_t reference_pcr_selection_len) {
    CHARRA_RC charra_rc = CHARRA_RC_ERROR;
    yaml_token_t token = {0};
    bool mapping_end = false;
    bool is_key_scalar = false;
    int file_pcr_index = 0;

    do {
        charra_rc = parse_token(parser, &token);
        if (charra_rc != CHARRA_RC_SUCCESS) {
            goto mapping_error;
        }
        switch (token.type) {
        case YAML_KEY_TOKEN:
            is_key_scalar = true;
            break;
        case YAML_VALUE_TOKEN:
            is_key_scalar = false;
            break;
        case YAML_SCALAR_TOKEN:
            if (pcr_selection_index >= reference_pcr_selection_len) {
                // only parse the line if we actually need another PCR for our
                // digest, otherwise just skip it
                break;
            }
            if (is_key_scalar) {
                file_pcr_index =
                        parse_pcr_index((char*)token.data.scalar.value);
                if (file_pcr_index < 0 ||
                        token.data.scalar.style != YAML_PLAIN_SCALAR_STYLE) {
                    charra_log_error("Error while parsing line %d from "
                                     "reference PCR file: "
                                     "Unparseable PCR Index.",
                            token.start_mark.line + 1);
                    charra_rc = CHARRA_RC_ERROR;
                    goto mapping_error;
                }
            } else if (file_pcr_index ==
                       reference_pcr_selection[pcr_selection_index]) {
                // PCR in current line is part of the PCR selection
                charra_rc = parse_pcr_value((char*)token.data.scalar.value,
                        token.data.scalar.length,
                        reference_pcrs[pcr_selection_index]);
                if (token.data.scalar.style != YAML_PLAIN_SCALAR_STYLE) {
                    charra_rc = CHARRA_RC_ERROR;
                }
                if (charra_rc != CHARRA_RC_SUCCESS) {
                    charra_log_error("Error while parsing PCR value in "
                                     "line %d from reference PCR file.",
                            token.start_mark.line + 1);
                    goto mapping_error;
                }

                // current selected PCR parsed, increase index
                pcr_selection_index++;
            }
            break;
        case YAML_BLOCK_END_TOKEN:
            mapping_end = true;
            pcr_set_ending_line = token.end_mark.line + 1;
            break;
        /* all other tokens should not be parsed in this stage */
        default:
            goto mapping_parse_error;
        }
        yaml_token_delete(&token);
    } while (!mapping_end);

    return charra_rc;

mapping_parse_error:
    charra_rc = CHARRA_RC_ERROR;
    charra_log_error("Parser error: invalid representation [Line: %lu, "
                     "Column: %lu]",
            token.start_mark.line + 1, token.start_mark.column + 1);
mapping_error:
    yaml_token_delete(&token);
    return charra_rc;
}

/**
 * @brief Parses a YAML document containing a mapping with a mapping as value
 * containing a PCR list. This function should only be called if the parser has
 * previously parsed a `YAML_DOCUMENT_START_TOKEN`.
 *
 * @param parser a pointer to the parser
 * @param skip_block_mapping_start_token this function should skip the first
 * `YAML_BLOCK_MAPPING_START_TOKEN` if set to `true`
 * @param reference_pcrs the 2D array holding all PCR values needed for the
 * PCR composite digest
 * @param reference_pcr_selection the array holding the PCR indexes used for
 * to compute the digest.
 * @param reference_pcr_selection_len the number of PCR indexes used for the
 * computation of the digest, also the length of both arrays
 * @returns CHARRA_RC_SUCCESS on success, CHARRA_RC_ERROR on errors.
 */
static CHARRA_RC parse_document(yaml_parser_t* parser,
        bool skip_block_mapping_start_token, uint8_t** reference_pcrs,
        const uint8_t* reference_pcr_selection,
        const uint32_t reference_pcr_selection_len) {
    CHARRA_RC charra_rc = CHARRA_RC_ERROR;
    yaml_token_t token = {0};
    bool document_end = false;
    bool mapping_started = false;
    yaml_token_type_t expected_token = YAML_BLOCK_MAPPING_START_TOKEN;
    /* YAML_BLOCK_MAPPING_START_TOKEN is already parsed */
    if (skip_block_mapping_start_token) {
        expected_token = YAML_KEY_TOKEN;
        mapping_started = true;
    }

    /* the parser should parse:
     * - YAML_BLOCK_MAPPING_START_TOKEN (depending on
     * skip_block_mapping_start_token)
     * - YAML_KEY_TOKEN
     * - YAML_SCALAR_TOKEN: ("sha256")
     * - YAML_VALUE_TOKEN
     * - YAML_BLOCK_MAPPING_START_TOKEN: (pcr list)
     * - ...
     * - YAML_BLOCK_END_TOKEN (end of root mapping) */
    do {
        charra_rc = parse_token(parser, &token);
        if (charra_rc != CHARRA_RC_SUCCESS) {
            goto document_error;
        }
        if (token.type != expected_token) {
            goto document_parse_error;
        }
        switch (token.type) {
        case YAML_BLOCK_MAPPING_START_TOKEN:
            if (mapping_started) {
                charra_rc = parse_pcr_mapping(parser, reference_pcrs,
                        reference_pcr_selection, reference_pcr_selection_len);
                if (charra_rc != CHARRA_RC_SUCCESS) {
                    goto document_error;
                }
                expected_token = YAML_BLOCK_END_TOKEN;
            } else {
                expected_token = YAML_KEY_TOKEN;
                mapping_started = true;
            }
            break;
        case YAML_KEY_TOKEN:
            expected_token = YAML_SCALAR_TOKEN;
            break;
        case YAML_SCALAR_TOKEN:
            // TODO(any): Allow other hashing algorithms
            /* root mapping key should be the pcr digest algorithm */
            if (strncmp((const char*)token.data.scalar.value, "sha256",
                        token.data.scalar.length) != 0) {
                goto document_parse_error;
            }
            expected_token = YAML_VALUE_TOKEN;
            break;
        case YAML_VALUE_TOKEN:
            expected_token = YAML_BLOCK_MAPPING_START_TOKEN;
            break;
        case YAML_BLOCK_END_TOKEN:
            document_end = true;
            break;
        /* all other tokens should not be parsed in this stage */
        default:
            goto document_parse_error;
        }
        yaml_token_delete(&token);
    } while (!document_end);

    return charra_rc;

document_parse_error:
    charra_rc = CHARRA_RC_ERROR;
    charra_log_error("Parser error: invalid representation [Line: %lu, "
                     "Column: %lu]",
            token.start_mark.line + 1, token.start_mark.column + 1);
document_error:
    yaml_token_delete(&token);
    return charra_rc;
}

CHARRA_RC charra_check_pcr_digest_against_reference(const char* filename,
        const uint8_t* reference_pcr_selection,
        const uint32_t reference_pcr_selection_len,
        const TPMS_ATTEST* const attest_struct) {
    /* sanity check */
    if (reference_pcr_selection_len >= TPM2_MAX_PCRS) {
        charra_log_error(
                "Bad PCR selection length: %d.", reference_pcr_selection_len);
        return CHARRA_RC_BAD_ARGUMENT;
    }

    // allocate memory for the pcr values read from the file
    uint8_t** reference_pcrs =
            malloc(reference_pcr_selection_len * sizeof(uint8_t*));
    for (uint32_t i = 0; i < reference_pcr_selection_len; i++) {
        reference_pcrs[i] = malloc(TPM2_SHA256_DIGEST_SIZE * sizeof(uint8_t));
    }

    CHARRA_RC charra_rc = CHARRA_RC_ERROR;

    yaml_parser_t parser = {0};
    yaml_token_t token = {0};
    FILE* yaml_file = NULL;
    bool no_digest_match = true;

    if (filename != NULL) {
        /* open YAML file*/
        if ((yaml_file = fopen(filename, "rb")) == NULL) {
            charra_log_error("Cannot open file '%s'.", filename);
            charra_rc = CHARRA_RC_ERROR;
            goto returns;
        }

        /* initialize YAML parser with file */
        if (yaml_parser_initialize(&parser) == 0) {
            charra_log_error("Could not initialize YAML parser");
            charra_rc = CHARRA_RC_ERROR;
            goto returns;
        }
        yaml_parser_set_input_file(&parser, yaml_file);

        /* parse YAML file*/
        bool stream_end = false;
        do {
            charra_rc = parse_token(&parser, &token);
            if (charra_rc != CHARRA_RC_SUCCESS) {
                goto returns;
            }
            switch (token.type) {
            case YAML_STREAM_START_TOKEN:
                break;
            case YAML_DOCUMENT_START_TOKEN:  // optional token
            case YAML_BLOCK_MAPPING_START_TOKEN:
                charra_rc = parse_document(&parser,
                        SKIP_BLOCK_MAPPING_START_TOKEN(token.type),
                        reference_pcrs, reference_pcr_selection,
                        reference_pcr_selection_len);
                if (charra_rc != CHARRA_RC_SUCCESS) {
                    goto returns;
                }
                /* check if digests match */
                charra_rc = handle_end_of_pcr_set(reference_pcrs,
                        reference_pcr_selection, reference_pcr_selection_len,
                        attest_struct);
                // do not return when digests don't match, we have more PCR sets
                // to try out
                if (charra_rc != CHARRA_RC_NO_MATCH) {
                    no_digest_match = false;
                    goto returns;
                }
                pcr_selection_index = 0;
                pcr_set_index++;
                break;
            case YAML_DOCUMENT_END_TOKEN:  // optional token
                break;
            case YAML_STREAM_END_TOKEN:
                stream_end = true;
                break;
            /* all other tokens should not be parsed in this stage */
            default:
                charra_rc = CHARRA_RC_ERROR;
                goto returns;
            }
            yaml_token_delete(&token);
        } while (!stream_end);
    } else {
        /* filename is NULL */
        charra_log_error("No reference PCR file specified");
        charra_rc = CHARRA_RC_ERROR;
        goto returns;
    }

returns:
    if (charra_rc != CHARRA_RC_ERROR && no_digest_match) {
        // no match until end of reference PCR file, verification failed.
        charra_rc = CHARRA_RC_VERIFICATION_FAILED;
    }
    yaml_token_delete(&token);
    yaml_parser_delete(&parser);
    if (yaml_file != NULL) {
        fclose(yaml_file);
    }
    free_reference_pcrs(reference_pcrs, reference_pcr_selection_len);
    return charra_rc;
}
