/* SPDX-License-Identifier: BSD-3-Clause */
/*****************************************************************************
 * Copyright 2019, Fraunhofer Institute for Secure Information Technology SIT.
 * All rights reserved.
 ****************************************************************************/

/**
 * @file cbor_util.h
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

#ifndef CBOR_UTIL_H
#define CBOR_UTIL_H

#include <stdlib.h>
#include <qcbor.h>

#include "../common/charra_error.h"


/**
 * @brief Returns a human-readable presentation of a CBOR type.
 *
 * @param type[in] The CBOR type.
 * @return The human-readable CBOR type.
 */
const char* cbor_type_string(const uint8_t type);

#define CHARRA_CBOR_TYPE_BOOLEAN QCBOR_TYPE_OPTTAG-1
CHARRA_RC charra_cbor_getnext(QCBORDecodeContext *pCtx, QCBORItem *pDecodedItem, uint8_t expected_type);

bool charra_cbor_getbool_val(QCBORItem *item);

const char *charra_cbor_err_str(QCBORError err);

#endif /* CBOR_UTIL_H */
