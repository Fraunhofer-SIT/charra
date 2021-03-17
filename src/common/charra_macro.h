/* SPDX-License-Identifier: BSD-3-Clause */
/*****************************************************************************
 * Copyright 2021, Fraunhofer Institute for Secure Information Technology SIT.
 * All rights reserved.
 ****************************************************************************/

/**
 * @file charra_macro.h
 * @author Michael Eckel (michael.eckel@sit.fraunhofer.de)
 * @brief General macros.
 * @version 0.1
 * @date 2021-03-17
 *
 * @copyright Copyright 2019, Fraunhofer Institute for Secure Information
 * Technology SIT. All rights reserved.
 *
 * @license BSD 3-Clause "New" or "Revised" License (SPDX-License-Identifier:
 * BSD-3-Clause).
 */

#ifndef CHARRA_MACRO_H
#define CHARRA_MACRO_H

#include <stdlib.h>

#define charra_free_and_null_ex(var, func_name)                                \
	{                                                                          \
		func_name(var);                                                        \
		var = NULL;                                                            \
	}

#define charra_free_and_null(var)                                              \
	{ charra_free_and_null_ex(var, free); }

#define charra_free_if_not_null_ex(var, func_name)                             \
	{                                                                          \
		if (var != NULL) {                                                     \
			charra_free_and_null_ex(var, func_name);                           \
		}                                                                      \
	}

#define charra_free_if_not_null(var)                                           \
	{ charra_free_if_not_null_ex(var, free); }

#endif /* CHARRA_MACRO_H */
