/* SPDX-License-Identifier: BSD-3-Clause */
/*****************************************************************************
 * Copyright 2019, Fraunhofer Institute for Secure Information Technology SIT.
 * All rights reserved.
 ****************************************************************************/

/**
 * @file charra_error.h
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

#ifndef CHARRA_ERROR_H
#define CHARRA_ERROR_H

#include <inttypes.h>

typedef uint32_t CHARRA_RC;
#define CHARRA_RC_SUCCESS ((CHARRA_RC)0x00000000)
#define CHARRA_RC_ERROR ((CHARRA_RC)0x00000001)
#define CHARRA_RC_CRYPTO_ERROR ((CHARRA_RC)0x0001ffff)
#define CHARRA_RC_NOT_YET_IMPLEMENTED ((CHARRA_RC)0xeeeeee)
#define CHARRA_RC_BAD_ARGUMENT ((CHARRA_RC)0x0000ffff)
#define CHARRA_RC_MARSHALING_ERROR ((CHARRA_RC)0x0000fffe)
#define CHARRA_RC_TPM ((CHARRA_RC)0x0002ffff)
#define CHARRA_RC_VERIFICATION_FAILED ((CHARRA_RC)0x000000ff)
#define CHARRA_RC_NO_MATCH ((CHARRA_RC)0x01010101)
#define CHARRA_RC_CLI_ERROR ((CHARRA_RC)0x0000aaaa)
#define CHARRA_RC_COAP_ERROR ((CHARRA_RC)0x0000C0AF)
#define CHARRA_RC_TIMEOUT ((CHARRA_RC)0x0000000f)

#endif /* CHARRA_ERROR_H */
