/* SPDX-License-Identifier: BSD-3-Clause */
/*****************************************************************************
 * Copyright 2026, Fraunhofer Institute for Secure Information Technology
 * SIT. All rights reserved.
 ****************************************************************************/

/**
 * @file psa_key_util.h
 * @author Markus Horn (markus.horn@sit.fraunhofer.de)
 * @brief Provides PSA key utilities.
 * @version 0.1
 * @date 2026-06-01
 *
 * @copyright Copyright 2026, Fraunhofer Institute for Secure Information
 * Technology SIT. All rights reserved.
 *
 * @license BSD 3-Clause "New" or "Revised" License (SPDX-License-Identifier:
 * BSD-3-Clause).
 */

#ifndef PSA_KEY_UTIL_H
#define PSA_KEY_UTIL_H

#include <stddef.h>
#include <stdint.h>

#include "../common/charra_error.h"

CHARRA_RC charra_der_encode_rsa_pub_key(const uint8_t* modulus,
        size_t modulus_size, uint32_t exponent, uint8_t* key,
        size_t key_buffer_size, size_t* key_len);

CHARRA_RC charra_octet_string_encode_ecdsa_pub_key(const uint8_t* qx,
        size_t qx_size, const uint8_t* qy, size_t qy_size, uint8_t* key,
        size_t key_buffer_size, size_t* key_len);

#endif /* PSA_KEY_UTIL_H */
