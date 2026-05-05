/* SPDX-License-Identifier: BSD-3-Clause */
/*****************************************************************************
 * Copyright 2021, Fraunhofer Institute for Secure Information Technology SIT.
 * All rights reserved.
 ****************************************************************************/

/**
 * @file parser_util.h
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

#include "../common/charra_error.h"
#include "../core/charra_tap/charra_tap_dto.h"

/**
 * @brief Parses PCR value from a string. Expects the PCR value to
 * start with the characters '0x'.
 *
 * @param start pointer to the start of the string
 * @param length length of the string
 * @param pcr_value pointer to an array in which the PCR value will be written.
 * @param hash_algorithm the hash algorithm used for the PCR value.
 * @returns CHARRA_RC_SUCCESS on success, otherwise CHARRA_RC_ERROR
 */
CHARRA_RC parse_pcr_value(char* start, size_t length, uint8_t* pcr_value,
        TPM2_ALG_ID hash_algorithm);

/**
 * @brief parse PCR index at the position given by index_start.
 *
 * @param index_start pointer to the string to be parsed
 * @param index pointer to the index which holds the parsed value
 * @returns CHARRA_RC_SUCCESS on success, otherwise CHARRA_RC_ERROR
 */
CHARRA_RC parse_pcr_index(const char* const index_start, uint8_t* const index);

/**
 * @brief Parses a request for a PCR log into a response.
 *
 * @param[in] log_name application name for the logger
 * @param[in] ima_log_path path to the ima log file
 * @param[in] tcg_boot_log_path path to the tcg-boot log file
 * @param[in] request pointer to the request
 * @param[out] response pointer to the response
 */
CHARRA_RC parse_pcr_log_request(const char* const log_name,
        const char* const ima_log_path, const char* const tcg_boot_log_path,
        const pcr_log_dto* const request, pcr_log_response_dto* response);

/**
 * @brief Parses a string into a long value.
 *
 * @param string pointer to the string to be parsed
 * @param base base of the number system (e.g. 10 for decimal, 16 for hex)
 * @param value pointer to the long value to be written
 * @returns CHARRA_RC_SUCCESS on success, otherwise CHARRA_RC_ERROR
 */
CHARRA_RC parse_long(const char* const string, int base, int64_t* const value);

/**
 * @brief Parses a string into an unsigned long value.
 *
 * @param string pointer to the string to be parsed
 * @param base base of the number system (e.g. 10 for decimal, 16 for hex)
 * @param value pointer to the unsigned long value to be written
 * @returns CHARRA_RC_SUCCESS on success, otherwise CHARRA_RC_ERROR
 */
CHARRA_RC parse_ulong(
        const char* const string, int base, uint64_t* const value);
