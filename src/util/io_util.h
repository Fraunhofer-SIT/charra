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

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define CHARRA_BYTE_TO_BINARY_PATTERN "%c%c%c%c%c%c%c%c"
#define CHARRA_BYTE_TO_BINARY(byte)                                            \
	(byte & 0x80 ? '1' : '0'), (byte & 0x40 ? '1' : '0'),                      \
		(byte & 0x20 ? '1' : '0'), (byte & 0x10 ? '1' : '0'),                  \
		(byte & 0x08 ? '1' : '0'), (byte & 0x04 ? '1' : '0'),                  \
		(byte & 0x02 ? '1' : '0'), (byte & 0x01 ? '1' : '0')

/**
 * @brief
 *
 * @param buf_len Length of the buffer to be printed.
 * @param buf The buffer to be printed.
 * @param prefix A prefix to the output, e.g. "0x", or leave it empty ("").
 * @param postfix  A postfix to the output, e.g. "\n", or leave it empty ("").
 * @param upper_case true: print in uppercase (e.g. "012..ABCDEF"); false: print
 * in lowercase (e.g. "012..abcdef").
 */
void charra_print_hex(const size_t buf_len, const uint8_t* const buf,
	const char* prefix, const char* postfix, const bool upper_case);

/**
 * @brief
 *
 * @param buf_len Length of the buffer to be printed.
 * @param buf The buffer to be printed.
 * @param prefix A prefix to the output, e.g. an indentation ("  "), or leave it
 * empty ("").
 * @param postfix  A postfix to the output, e.g. "\n", or leave it empty ("").
 */
void charra_print_str(const size_t buf_len, const uint8_t* const buf,
	const char* prefix, const char* postfix);

#endif /* IO_UTIL_H */
