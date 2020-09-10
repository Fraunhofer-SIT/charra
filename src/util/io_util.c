/* SPDX-License-Identifier: BSD-3-Clause */
/*****************************************************************************
 * Copyright 2019, Fraunhofer Institute for Secure Information Technology SIT.
 * All rights reserved.
 ****************************************************************************/

/**
 * @file io_util.c
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

#include "io_util.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

void charra_print_hex(const size_t buf_len, const uint8_t* const buf,
	const char* prefix, const char* postfix, const bool upper_case) {
	const char* const hex_case = upper_case ? "%02X" : "%02x";

	printf("%s", prefix);
	/* print upper case */
	for (size_t i = 0; i < buf_len; ++i) {
		printf(hex_case, buf[i]);
	}
	printf("%s", postfix);
}

void charra_print_str(const size_t buf_len, const uint8_t* const buf,
	const char* prefix, const char* postfix) {

	printf("%s", prefix);
	/* print upper case */
	for (size_t i = 0; i < buf_len; ++i) {
		printf("%c", buf[i]);
	}
	printf("%s", postfix);
}
