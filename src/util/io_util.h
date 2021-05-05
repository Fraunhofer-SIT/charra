/* SPDX-License-Identifier: BSD-3-Clause */
/*****************************************************************************
 * Copyright 2019, Fraunhofer Institute for Secure Information Technology SIT.
 * All rights reserved.
 ****************************************************************************/

/**
 * @file io_util.h
 * @author Michael Eckel (michael.eckel@sit.fraunhofer.de)
 * @brief Provides I/O functions, including print.
 * @version 0.1
 * @date 2019-12-22
 *
 * @copyright Copyright 2019, Fraunhofer Institute for Secure Information
 * Technology SIT. All rights reserved.
 *
 * @license BSD 3-Clause "New" or "Revised" License (SPDX-License-Identifier:
 * BSD-3-Clause).
 */

#ifndef IO_UTIL_H
#define IO_UTIL_H

#include "../common/charra_error.h"
#include "../common/charra_log.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <tss2/tss2_tpm2_types.h>

#define CHARRA_BYTE_TO_BINARY_PATTERN "%c%c%c%c%c%c%c%c"
#define CHARRA_BYTE_TO_BINARY(byte)                                            \
	(byte & 0x80 ? '1' : '0'), (byte & 0x40 ? '1' : '0'),                      \
		(byte & 0x20 ? '1' : '0'), (byte & 0x10 ? '1' : '0'),                  \
		(byte & 0x08 ? '1' : '0'), (byte & 0x04 ? '1' : '0'),                  \
		(byte & 0x02 ? '1' : '0'), (byte & 0x01 ? '1' : '0')

/**
 * @brief
 *
 * @param level the log level to print at
 * @param buf_len Length of the buffer to be printed.
 * @param buf The buffer to be printed.
 * @param prefix A prefix to the output, e.g. "0x", or leave it empty ("").
 * @param postfix  A postfix to the output, e.g. "\n", or leave it empty ("").
 * @param upper_case true: print in uppercase (e.g. "012..ABCDEF"); false: print
 * in lowercase (e.g. "012..abcdef").
 */
void charra_print_hex(const charra_log_t level, const size_t buf_len,
	const uint8_t* const buf, const char* prefix, const char* postfix,
	const bool upper_case);

/**
 * @brief
 *
 * @param level the log level to print at
 * @param buf_len Length of the buffer to be printed.
 * @param buf The buffer to be printed.
 * @param prefix A prefix to the output, e.g. an indentation ("  "), or leave it
 * empty ("").
 * @param postfix  A postfix to the output, e.g. "\n", or leave it empty ("").
 */
void charra_print_str(const charra_log_t level, const size_t buf_len,
	const uint8_t* const buf, const char* prefix, const char* postfix);

/**
 * @brief Print PCR content of selected PCRs.
 *
 * @param level the log level to print at
 * @param pcr_selection the indexes of selected PCRs
 * @param pcr_selection_len the number of PCRs to print
 * @param pcrs the content of the PCRs
 */
void charra_print_pcr_content(const charra_log_t level,
	const uint8_t* pcr_selection, const uint32_t pcr_selection_len,
	uint8_t** pcrs);

/**
 * @brief Checks if file is existing.
 *
 * @param filename the path of the file
 */
CHARRA_RC check_file_existence(const char* filename);

/**
 * @brief read file into a buffer. The buffer will be initialized in this
 * function.
 *
 * @param[in] filename the path of the file to read
 * @param[out] file_content A pointer to the buffer, assumed to be uninitialized
 * upon calling.
 * @param[out] file_content_len The actual length of the file (aka the size of
 * file_content).
 * @return CHARRA_RC CHARRA_RC_SUCCESS on success, otherwise CHARRA_RC_ERROR
 */
CHARRA_RC charra_io_read_file(
	const char* filename, char** file_content, size_t* file_content_len);

/**
 * @brief free buffer holding the file content. Alternatively
 * free(*file_content) can be called directly.
 *
 * @param[in] file_content A pointer to the buffer.
 */
void charra_free_file_buffer(char** file_content);

/**
 * @brief read binary file of unknown length into a cvector. Used for IMA event
 * log reading, which is a char device. The cvector will be initialized inside
 * this function.
 *
 * @param[in] filename the path of the file to be read
 * @param[out] file_content A pointer to the cvector, assumed to be
 * uninitialized upon calling.
 * @param[out] file_content_len The actual length of the file (aka the size of
 * file_content).
 * @return CHARRA_RC CHARRA_RC_SUCCESS on success, otherwise CHARRA_RC_ERROR
 */
CHARRA_RC charra_io_read_continuous_binary_file(
	const char* filename, uint8_t** file_content, size_t* file_content_len);

/**
 * @brief free cvector holding the file content.
 *
 * @param[in] file_content A pointer to the cvector.
 */
void charra_free_continous_file_buffer(uint8_t** file_content);

#endif /* IO_UTIL_H */
