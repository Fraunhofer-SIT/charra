/* SPDX-License-Identifier: BSD-3-Clause */
/*****************************************************************************
 * Copyright 2025, Fraunhofer Institute for Secure Information Technology SIT.
 * All rights reserved.
 ****************************************************************************/

/**
 * @file yaml_util.c
 * @author Markus Horn (markus.horn@sit.fraunhofer.de)
 * @brief Provides yaml parsing functions.
 * @version 0.1
 * @date 2025-05-11
 *
 * @copyright Copyright 2024, Fraunhofer Institute for Secure Information
 * Technology SIT. All rights reserved.
 *
 * @license BSD 3-Clause "New" or "Revised" License (SPDX-License-Identifier:
 * BSD-3-Clause).
 */

#include "yaml_util.h"

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include <yaml.h>

#include "../common/charra_log.h"
#include "../util/parser_util.h"

#define MAX_KEY_LEN 128

CHARRA_RC parse_yaml_token(
        charra_yaml_parser_state_t* parser_state, yaml_token_t* const token) {
    if (yaml_parser_scan(&parser_state->parser, token) == 0) {
        if (parser_state->parser.problem_mark.line ||
                parser_state->parser.problem_mark.column) {
            charra_log_error("Parse error: %s [Line: %lu, Column: %lu]",
                    parser_state->parser.problem,
                    parser_state->parser.problem_mark.line + 1,
                    parser_state->parser.problem_mark.column + 1);
        } else {
            charra_log_error("Parse error: %s", parser_state->parser.problem);
        }
        return CHARRA_RC_ERROR;
    }
    return CHARRA_RC_SUCCESS;
}

CHARRA_RC parse_yaml_ulong_value(
        charra_yaml_parser_state_t* parser_state, uint64_t* const value) {
    CHARRA_RC charra_rc = CHARRA_RC_ERROR;
    yaml_token_t token = {0};
    uint64_t parsed_value = 0;

    charra_rc = parse_yaml_token(parser_state, &token);
    if (charra_rc != CHARRA_RC_SUCCESS) {
        return charra_rc;
    }
    if (token.type != YAML_SCALAR_TOKEN) {
        charra_rc = CHARRA_RC_ERROR;
        goto cleanup;
    }
    if (token.data.scalar.style != YAML_PLAIN_SCALAR_STYLE) {
        CHARRA_YAML_TOKEN_ERROR_LOG(token, "invalid number representation");
        charra_rc = CHARRA_RC_ERROR;
        goto cleanup;
    }

    const char* const token_value = (char*)token.data.scalar.value;
    charra_rc = parse_ulong(token_value, 0, &parsed_value);
    if (charra_rc != CHARRA_RC_SUCCESS) {
        CHARRA_YAML_TOKEN_ERROR_LOG(token, "invalid unsigned long value");
        charra_rc = CHARRA_RC_ERROR;
    }
    *value = parsed_value;

cleanup:
    yaml_token_delete(&token);
    return charra_rc;
}

CHARRA_RC parse_yaml_bool_value(
        charra_yaml_parser_state_t* parser_state, bool* const value) {
    CHARRA_RC charra_rc = CHARRA_RC_ERROR;
    yaml_token_t token = {0};

    charra_rc = parse_yaml_token(parser_state, &token);
    if (charra_rc != CHARRA_RC_SUCCESS) {
        return charra_rc;
    }
    if (token.type != YAML_SCALAR_TOKEN) {
        charra_rc = CHARRA_RC_ERROR;
        goto cleanup;
    }
    if (token.data.scalar.style != YAML_PLAIN_SCALAR_STYLE) {
        CHARRA_YAML_TOKEN_ERROR_LOG(token, "invalid boolean representation");
        charra_rc = CHARRA_RC_ERROR;
        goto cleanup;
    }

    const char* const token_value = (char*)token.data.scalar.value;
    if (strncmp(token_value, "true", token.data.scalar.length) == 0) {
        *value = true;
    } else if (strncmp(token_value, "false", token.data.scalar.length) == 0) {
        *value = false;
    } else {
        CHARRA_YAML_TOKEN_ERROR_LOG(token, "invalid boolean value");
        charra_rc = CHARRA_RC_ERROR;
    }

cleanup:
    yaml_token_delete(&token);
    return charra_rc;
}

CHARRA_RC parse_yaml_string_value(charra_yaml_parser_state_t* parser_state,
        char* const value, size_t buffer_size) {
    CHARRA_RC charra_rc = CHARRA_RC_ERROR;
    yaml_token_t token = {0};

    charra_rc = parse_yaml_token(parser_state, &token);
    if (charra_rc != CHARRA_RC_SUCCESS) {
        return charra_rc;
    }
    if (token.type != YAML_SCALAR_TOKEN) {
        charra_rc = CHARRA_RC_ERROR;
        CHARRA_YAML_TOKEN_ERROR_LOG(token, "invalid representation");
        goto cleanup;
    }

    const char* const token_value = (char*)token.data.scalar.value;
    const size_t token_len = token.data.scalar.length;
    if (token_len >= buffer_size) {
        charra_rc = CHARRA_RC_ERROR;
        CHARRA_YAML_TOKEN_ERROR_LOG(token, "string value too long");
        goto cleanup;
    }
    memcpy(value, token_value, token_len);
    value[token_len] = '\0';  // null-terminate the string

cleanup:
    yaml_token_delete(&token);
    return charra_rc;
}

static inline bool check_is_not_expected_sequence_token(
        const yaml_token_t* const token, yaml_token_type_t expected_token,
        bool is_flow_entry_token_allowed, bool is_block_entry_token_allowed,
        bool is_item_token_allowed) {
    if (token->type == expected_token) {
        return false;
    }
    if (token->type == YAML_BLOCK_ENTRY_TOKEN && is_block_entry_token_allowed) {
        return false;
    }
    if (token->type == YAML_FLOW_ENTRY_TOKEN && is_flow_entry_token_allowed) {
        return false;
    }
    if (is_item_token_allowed) {
        switch (token->type) {
            /* possible tokens which start new item */
        case YAML_FLOW_SEQUENCE_START_TOKEN:
        case YAML_FLOW_MAPPING_START_TOKEN:
        case YAML_BLOCK_SEQUENCE_START_TOKEN:
        case YAML_BLOCK_MAPPING_START_TOKEN:
        case YAML_SCALAR_TOKEN:
        case YAML_KEY_TOKEN:
        /* it is possible that two BLOCK_ENTRY_TOKENS are parsed in row (empty
         * item) */
        case YAML_BLOCK_ENTRY_TOKEN:
            return false;
        default:
            return true;
        }
    }

    return true;
}

static CHARRA_RC parse_yaml_inner_sequence(
        charra_yaml_parser_state_t* parser_state,
        yaml_item_handler item_handler, bool is_block_sequence, void* data,
        size_t data_len, size_t* items_read) {

    bool reset_is_inside_flow = false;

    if (parser_state->is_inside_flow && is_block_sequence) {
        charra_log_error(
                "Invalid YAML representation: block sequence inside flow");
        return CHARRA_RC_ERROR;
    }

    if (!parser_state->is_inside_flow && !is_block_sequence) {
        reset_is_inside_flow = true;
        parser_state->is_inside_flow = true;
    }

    CHARRA_RC charra_rc = CHARRA_RC_ERROR;
    yaml_token_t token = {0};
    bool sequence_end = false;
    yaml_token_type_t expected_token = YAML_BLOCK_ENTRY_TOKEN;
    bool is_flow_entry_token_allowed = false;
    bool is_block_entry_token_allowed = false;
    bool is_item_token_allowed = false;

    if (!is_block_sequence) {
        expected_token = YAML_FLOW_SEQUENCE_END_TOKEN;
        is_item_token_allowed = true;
    }

    do {
        charra_rc = parse_yaml_token(parser_state, &token);
        if (charra_rc != CHARRA_RC_SUCCESS) {
            goto sequence_error;
        }
        if (check_is_not_expected_sequence_token(&token, expected_token,
                    is_flow_entry_token_allowed, is_block_entry_token_allowed,
                    is_item_token_allowed)) {
            goto sequence_parse_error;
        }
        switch (token.type) {
        case YAML_BLOCK_ENTRY_TOKEN:
            if (is_item_token_allowed) {
                /* previous token was an BLOCK_ENTRY_TOKEN -> empty item */
                charra_rc = item_handler(
                        parser_state, NULL, *items_read, data, data_len);
                (*items_read)++;
                if (charra_rc != CHARRA_RC_SUCCESS) {
                    goto sequence_error;
                }
            }
            is_block_entry_token_allowed = false;
            expected_token = YAML_BLOCK_END_TOKEN;
            is_item_token_allowed = true;
            break;
        case YAML_FLOW_ENTRY_TOKEN:
            is_flow_entry_token_allowed = false;
            expected_token = YAML_FLOW_SEQUENCE_END_TOKEN;
            is_item_token_allowed = true;
            break;
        case YAML_BLOCK_END_TOKEN:
            sequence_end = true;
            if (is_item_token_allowed) {
                /* previous token was an BLOCK_ENTRY_TOKEN -> empty item */
                charra_rc = item_handler(
                        parser_state, &token, *items_read, data, data_len);
                (*items_read)++;
                if (charra_rc != CHARRA_RC_SUCCESS) {
                    goto sequence_error;
                }
            }
            break;
        case YAML_FLOW_SEQUENCE_END_TOKEN:
            sequence_end = true;
            break;
        /* all other tokens should be parsed by the item_handler */
        default:
            is_item_token_allowed = false;
            charra_rc = item_handler(
                    parser_state, &token, *items_read, data, data_len);
            (*items_read)++;
            if (charra_rc != CHARRA_RC_SUCCESS) {
                goto sequence_error;
            }
            if (is_block_sequence) {
                expected_token = YAML_BLOCK_END_TOKEN;
                is_block_entry_token_allowed = true;
            } else {
                expected_token = YAML_FLOW_SEQUENCE_END_TOKEN;
                is_flow_entry_token_allowed = true;
            }
            break;
        }
        yaml_token_delete(&token);
    } while (!sequence_end);

    if (reset_is_inside_flow) {
        parser_state->is_inside_flow = false;
    }

    return charra_rc;

sequence_parse_error:
    CHARRA_YAML_TOKEN_ERROR_LOG(token, "invalid YAML syntax");

sequence_error:
    charra_rc = CHARRA_RC_ERROR;
    yaml_token_delete(&token);
    return charra_rc;
}

CHARRA_RC parse_yaml_sequence(charra_yaml_parser_state_t* parser_state,
        yaml_item_handler item_handler, void* data, size_t data_len,
        size_t* items_read) {
    CHARRA_RC charra_rc = CHARRA_RC_ERROR;
    yaml_token_t token = {0};
    *items_read = 0;

    charra_rc = parse_yaml_token(parser_state, &token);
    if (charra_rc != CHARRA_RC_SUCCESS) {
        return charra_rc;
    }
    switch (token.type) {
    case YAML_BLOCK_SEQUENCE_START_TOKEN:
        charra_rc = parse_yaml_inner_sequence(
                parser_state, item_handler, true, data, data_len, items_read);
        break;
    case YAML_FLOW_SEQUENCE_START_TOKEN:
        charra_rc = parse_yaml_inner_sequence(
                parser_state, item_handler, false, data, data_len, items_read);
        break;
    default:
        charra_rc = CHARRA_RC_ERROR;
        CHARRA_YAML_TOKEN_ERROR_LOG(token, "invalid representation");
    }

    yaml_token_delete(&token);
    return charra_rc;
}

static inline bool check_is_not_expected_mapping_token(
        const yaml_token_t* const token, yaml_token_type_t expected_token,
        bool is_key_token_allowed, bool is_flow_entry_token_allowed) {
    if (token->type == expected_token) {
        return false;
    }
    if (token->type == YAML_KEY_TOKEN && is_key_token_allowed) {
        return false;
    }
    if (token->type == YAML_FLOW_ENTRY_TOKEN && is_flow_entry_token_allowed) {
        return false;
    }
    return true;
}

static CHARRA_RC parse_yaml_inner_mapping(
        charra_yaml_parser_state_t* parser_state,
        yaml_field_handler field_handler, bool is_block_mapping, void* data) {

    bool reset_is_inside_flow = false;

    if (parser_state->is_inside_flow && is_block_mapping) {
        charra_log_error("Invalid YAML representation: block mapping inside "
                         "flow");
        return CHARRA_RC_ERROR;
    }

    if (!parser_state->is_inside_flow && !is_block_mapping) {
        reset_is_inside_flow = true;
        parser_state->is_inside_flow = true;
    }

    CHARRA_RC charra_rc = CHARRA_RC_ERROR;
    yaml_token_t token = {0};
    bool mapping_end = false;
    yaml_token_type_t expected_token = YAML_KEY_TOKEN;
    char key_name[MAX_KEY_LEN] = {0};
    // this variables are used to decide if it is allowed to use another
    // token e.g. after a value is it possible to end the mapping or start
    // with another key
    bool is_key_token_allowed = false;
    bool is_flow_entry_token_allowed = false;

    /* the parser should parse:
     * - YAML_BLOCK_MAPPING_START_TOKEN / YAML_FLOW_MAPPING_START_TOKEN
     * (handled by caller)
     * - LOOP START
     * - YAML_KEY_TOKEN
     * - YAML_SCALAR_TOKEN: (key name)
     * - YAML_VALUE_TOKEN: (call field handler)
     * - YAML_FLOW_ENTRY_TOKEN (used in flow mapping, for last entry
     * optional)
     * - LOOP END
     * - YAML_BLOCK_END_TOKEN / YAML_FLOW_MAPPING_END_TOKEN (end of mapping)
     */
    do {
        charra_rc = parse_yaml_token(parser_state, &token);
        if (charra_rc != CHARRA_RC_SUCCESS) {
            goto mapping_error;
        }
        if (check_is_not_expected_mapping_token(&token, expected_token,
                    is_key_token_allowed, is_flow_entry_token_allowed)) {
            goto mapping_parse_error;
        }
        switch (token.type) {
        case YAML_KEY_TOKEN:
            is_key_token_allowed = false;
            expected_token = YAML_SCALAR_TOKEN;
            break;
        case YAML_SCALAR_TOKEN: {
            const char* token_value = (const char*)token.data.scalar.value;
            const size_t token_len = token.data.scalar.length;
            if (token_len >= sizeof(key_name)) {
                CHARRA_YAML_TOKEN_ERROR_LOG(token, "key name too long");
                goto mapping_error;
            }
            memcpy(key_name, token_value, token_len);
            key_name[token_len] = '\0';  // null-terminate the string
            expected_token = YAML_VALUE_TOKEN;
            break;
        }
        case YAML_VALUE_TOKEN:
            /* this handler should consume all tokens corresponding to this
             * value token */
            charra_rc = field_handler(parser_state, key_name, data);
            if (charra_rc != CHARRA_RC_SUCCESS) {
                goto mapping_error;
            }
            if (is_block_mapping) {
                /* at this point an key or an end token is expected */
                expected_token = YAML_BLOCK_END_TOKEN;
                is_key_token_allowed = true;
            } else {
                /* at this point an flow entry or an end token is expected
                 */
                expected_token = YAML_FLOW_MAPPING_END_TOKEN;
                is_flow_entry_token_allowed = true;
            }
            break;
        case YAML_FLOW_ENTRY_TOKEN:
            is_flow_entry_token_allowed = false;
            /* at this point an key or an end token is expected */
            is_key_token_allowed = true;
            expected_token = YAML_FLOW_MAPPING_END_TOKEN;
            break;
        case YAML_BLOCK_END_TOKEN:
        case YAML_FLOW_MAPPING_END_TOKEN:
            mapping_end = true;
            break;
        /* all other tokens should not be parsed in this stage */
        default:
            goto mapping_parse_error;
        }
        yaml_token_delete(&token);
    } while (!mapping_end);

    if (reset_is_inside_flow) {
        parser_state->is_inside_flow = false;
    }
    return charra_rc;

mapping_parse_error:
    CHARRA_YAML_TOKEN_ERROR_LOG(token, "invalid YAML syntax");

mapping_error:
    charra_rc = CHARRA_RC_ERROR;
    yaml_token_delete(&token);
    return charra_rc;
}

CHARRA_RC parse_yaml_mapping(charra_yaml_parser_state_t* parser_state,
        yaml_field_handler field_handler, void* data) {
    CHARRA_RC charra_rc = CHARRA_RC_ERROR;
    yaml_token_t token = {0};

    charra_rc = parse_yaml_token(parser_state, &token);
    if (charra_rc != CHARRA_RC_SUCCESS) {
        return charra_rc;
    }
    switch (token.type) {
    case YAML_BLOCK_MAPPING_START_TOKEN:
        charra_rc = parse_yaml_inner_mapping(
                parser_state, field_handler, true, data);
        break;
    case YAML_FLOW_MAPPING_START_TOKEN:
        charra_rc = parse_yaml_inner_mapping(
                parser_state, field_handler, false, data);
        break;
    default:
        charra_rc = CHARRA_RC_ERROR;
        CHARRA_YAML_TOKEN_ERROR_LOG(token, "invalid representation");
        break;
    }

    yaml_token_delete(&token);
    return charra_rc;
}

CHARRA_RC parse_yaml_file(
        const char* const path, yaml_field_handler field_handler, void* data) {
    CHARRA_RC charra_rc = CHARRA_RC_ERROR;

    charra_yaml_parser_state_t parser_state = {0};
    yaml_token_t token = {0};
    FILE* yaml_file = NULL;

    if (path == NULL) {
        charra_log_error("No config file specified");
        charra_rc = CHARRA_RC_ERROR;
        goto cleanup;
    }

    /* open YAML file*/
    if ((yaml_file = fopen(path, "rb")) == NULL) {
        charra_log_error("Cannot open file '%s'.", path);
        charra_rc = CHARRA_RC_ERROR;
        goto cleanup;
    }

    /* initialize YAML parser with file */
    if (yaml_parser_initialize(&parser_state.parser) == 0) {
        charra_log_error("Could not initialize YAML parser");
        charra_rc = CHARRA_RC_ERROR;
        goto cleanup;
    }
    yaml_parser_set_input_file(&parser_state.parser, yaml_file);

    /* parse YAML file*/
    bool stream_end = false;
    do {
        charra_rc = parse_yaml_token(&parser_state, &token);
        if (charra_rc != CHARRA_RC_SUCCESS) {
            goto cleanup;
        }
        switch (token.type) {
        case YAML_STREAM_START_TOKEN:
        case YAML_DOCUMENT_START_TOKEN:  // optional token
        case YAML_DOCUMENT_END_TOKEN:    // optional token
            break;
        case YAML_BLOCK_MAPPING_START_TOKEN:
            charra_rc = parse_yaml_inner_mapping(
                    &parser_state, field_handler, true, data);
            if (charra_rc != CHARRA_RC_SUCCESS) {
                goto cleanup;
            }
            break;
        case YAML_FLOW_MAPPING_START_TOKEN:
            charra_rc = parse_yaml_inner_mapping(
                    &parser_state, field_handler, false, data);
            if (charra_rc != CHARRA_RC_SUCCESS) {
                goto cleanup;
            }
            break;
        case YAML_STREAM_END_TOKEN:
            stream_end = true;
            break;
        /* all other tokens should not be parsed in this stage */
        default:
            charra_rc = CHARRA_RC_ERROR;
            goto cleanup;
        }
        yaml_token_delete(&token);
    } while (!stream_end);

cleanup:
    yaml_token_delete(&token);
    yaml_parser_delete(&parser_state.parser);
    if (yaml_file != NULL) {
        fclose(yaml_file);
    }
    return charra_rc;
}
