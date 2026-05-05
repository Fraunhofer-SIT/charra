/* SPDX-License-Identifier: BSD-3-Clause */
/*****************************************************************************
 * Copyright 2025, Fraunhofer Institute for Secure Information Technology SIT.
 * All rights reserved.
 ****************************************************************************/

/**
 * @file yaml_util.h
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

#ifndef YAML_UTIL_H
#define YAML_UTIL_H

#include <stdbool.h>
#include <stdint.h>

#include <yaml.h>

#include "../common/charra_error.h"

typedef struct {
    yaml_parser_t parser;
    bool is_inside_flow;
} charra_yaml_parser_state_t;

/**
 * @brief A function pointer type for handling the end of a YAML document. If
 * the return value is not CHARRA_RC_SUCCESS, the parser will stop parsing.
 *
 * @param parser_state a pointer to the parser state
 * @param data a pointer to the data structure
 * @returns CHARRA_RC_SUCCESS if the parser should continue parsing
 */
typedef CHARRA_RC (*yaml_document_end_handler_t)(
        const charra_yaml_parser_state_t* const parser_state, void* data);

/**
 * @brief A function pointer type for handling YAML fields. This function has to
 * parse all fields of a mapping, otherwise the parser may fail.
 *
 * @param parser_state a pointer to the parser state
 * @param key the key of the current field
 * @param data a pointer to the data structure
 * @returns CHARRA_RC_SUCCESS on success, CHARRA_RC_ERROR on errors.
 */
typedef CHARRA_RC (*yaml_field_handler)(
        charra_yaml_parser_state_t* parser_state, const char* const key,
        void* data);

/**
 * @brief A function pointer type for handling YAML items. This function has to
 * parse all items of a sequence, otherwise the parser may fail.
 *
 * @param parser_state a pointer to the parser state
 * @param token the current token
 * @param index the index of the current sequence item
 * @param data a pointer to the data structure
 * @param data_len the size of the data structure
 * @returns CHARRA_RC_SUCCESS on success, CHARRA_RC_ERROR on errors.
 */
typedef CHARRA_RC (*yaml_item_handler)(charra_yaml_parser_state_t* parser_state,
        const yaml_token_t* const token, size_t index, void* data,
        size_t data_len);

#define CHARRA_YAML_PARSER_ERROR_LOG(parser, reason)                           \
    charra_log_error("Parser error: " reason " [Line: %lu, Column: %lu]",      \
            (parser).mark.line + 1, (parser).mark.column + 1);

#define CHARRA_YAML_PARSER_ERROR_LOG_F(parser, reason, ...)                    \
    charra_log_error("Parser error: " reason " [Line: %lu, Column: %lu]",      \
            __VA_ARGS__, (parser).mark.line + 1, (parser).mark.column + 1);

#define CHARRA_YAML_TOKEN_ERROR_LOG(token, reason)                             \
    charra_log_error("Parser error: " reason " [Line: %lu, Column: %lu]",      \
            (token).start_mark.line + 1, (token).start_mark.column + 1);

#define CHARRA_YAML_TOKEN_ERROR_LOG_F(token, reason, ...)                      \
    charra_log_error("Parser error: " reason " [Line: %lu, Column: %lu]",      \
            __VA_ARGS__, (token).start_mark.line + 1,                          \
            (token).start_mark.column + 1);

/**
 * @brief Parses a YAML token from the input file.
 *
 * @param parser_state a pointer to the parser state
 * @param token the read token
 * @returns CHARRA_RC_SUCCESS on success, CHARRA_RC_ERROR on errors.
 */
CHARRA_RC parse_yaml_token(
        charra_yaml_parser_state_t* parser_state, yaml_token_t* const token);

/**
 * @brief Parses a YAML unsigned long value from the input file.
 *
 * @param parser_state a pointer to the parser state
 * @param value the parsed value
 * @returns CHARRA_RC_SUCCESS on success, CHARRA_RC_ERROR on errors.
 */
CHARRA_RC parse_yaml_ulong_value(
        charra_yaml_parser_state_t* parser_state, uint64_t* const value);

/**
 * @brief Parses a YAML boolean value from the input file.
 *
 * @param parser_state a pointer to the parser state
 * @param value the parsed value
 * @returns CHARRA_RC_SUCCESS on success, CHARRA_RC_ERROR on errors.
 */
CHARRA_RC parse_yaml_bool_value(
        charra_yaml_parser_state_t* parser_state, bool* const value);

/**
 * @brief Parses a YAML string value from the input file.
 *
 * @param parser_state a pointer to the parser state
 * @param value the parsed value
 * @param buffer_size the buffer size of value
 * @returns CHARRA_RC_SUCCESS on success, CHARRA_RC_ERROR on errors.
 */
CHARRA_RC parse_yaml_string_value(charra_yaml_parser_state_t* parser_state,
        char* const value, size_t buffer_size);

/**
 * @brief Parses a YAML sequence from the input file.
 *
 * @param parser_state a pointer to the parser state
 * @param item_handler the item handler function (has to parse each item
 * completely)
 * @param data a pointer to the data structure
 * @param data_len the size of the data structure
 * @param items_read the number of items read
 * @returns CHARRA_RC_SUCCESS on success, CHARRA_RC_ERROR on errors.
 */
CHARRA_RC parse_yaml_sequence(charra_yaml_parser_state_t* parser_state,
        yaml_item_handler item_handler, void* data, size_t data_len,
        size_t* items_read);

/**
 * @brief Parses a YAML mapping from the input file.
 *
 * @param parser_state a pointer to the parser state
 * @param field_handler the field handler function (has to parse each field
 * completely)
 * @param data a pointer to the data structure
 * @returns CHARRA_RC_SUCCESS on success, CHARRA_RC_ERROR on errors.
 */
CHARRA_RC parse_yaml_mapping(charra_yaml_parser_state_t* parser_state,
        yaml_field_handler field_handler, void* data);

/**
 * @brief Parses a YAML file.
 *
 * @param path the path to the YAML file
 * @param field_handler the field handler function (has to parse each field
 * completely or else will lead to undefined behavior)
 * @param document_end_handler the document end handler function called after
 * the end of each YAML document in this file (can be NULL)
 * @param data a pointer to the data structure
 * @returns CHARRA_RC_SUCCESS on success, CHARRA_RC_ERROR on errors.
 */
CHARRA_RC parse_yaml_file(const char* const path,
        yaml_field_handler field_handler,
        yaml_document_end_handler_t document_end_handler, void* data);

#endif  // YAML_UTIL_H
