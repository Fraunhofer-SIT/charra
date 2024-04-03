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

/**
 * @brief Parses PCR value from a string. Expects the PCR value to
 * start with the characters '0x'.
 *
 * @param start pointer to the start of the string
 * @param length length of the string
 * @param pcr_value pointer to an array in which the PCR value will be written.
 * Is expected to be able to hold TPM2_SHA256_DIGEST_SIZE values.
 * @returns CHARRA_RC_SUCCESS on success, otherwise CHARRA_RC_ERROR
 */
CHARRA_RC parse_pcr_value(char* start, size_t length, uint8_t* pcr_value);

/**
 * @brief parse PCR index at the position given by index_start. Returns a
 * negative number in case of an error, including if the parsed index is too
 * big for a PCR index.
 */
int parse_pcr_index(char* index_start);
