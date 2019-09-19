/* SPDX-License-Identifier: BSD-3-Clause */
/*****************************************************************************
 * Copyright 2019, Fraunhofer Institute for Secure Information Technology SIT.
 * All rights reserved.
 ****************************************************************************/

/**
 * @file charra_util.h
 * @author Michael Eckel (michael.eckel@sit.fraunhofer.de)
 * @brief
 * @version 0.1
 * @date 2019-09-19
 *
 * @copyright Copyright 2019, Fraunhofer Institute for Secure Information
 * Technology SIT. All rights reserved.
 *
 * @license BSD 3-Clause "New" or "Revised" License (SPDX-License-Identifier:
 * BSD-3-Clause).
 */

#include <inttypes.h>

#include "../common/charra_error.h"

#ifndef CHARRA_UTIL_H
#define CHARRA_UTIL_H

/**
 * @brief Get random bytes.
 *
 * @param[in] len the requested number of random bytes.
 * @param[out] random_bytes the random bytes.
 * @return CHARRA_RC_SUCCESS on success.
 * @return CHARRA_RC_ERROR on error.
 */
CHARRA_RC charra_get_random_bytes(const uint32_t len, uint8_t** random_bytes);

#endif /* CHARRA_UTIL_H */
