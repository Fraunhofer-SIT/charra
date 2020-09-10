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

#include <qcbor/qcbor.h>
#include <stdlib.h>

#include "../common/charra_error.h"

#define CHARRA_CBOR_TYPE_BOOLEAN QCBOR_TYPE_OPTTAG - 1

/**
 * @brief Returns a human-readable presentation of a CBOR type.
 *
 * @param type[in] The CBOR type.
 * @return The human-readable CBOR type.
 */
const char* cbor_type_string(const uint8_t type);

/**
 * @brief Retrieves the next CBOR item.
 *
 * @param ctx
 * @param decoded_item
 * @param expected_type the expected CBOR element type
 * @return CHARRA_RC_SUCCESS in case of success
 * @return CHARRA_RC_MARSHALING_ERROR in case an error occurred
 */
CHARRA_RC charra_cbor_get_next(
	QCBORDecodeContext* ctx, QCBORItem* decoded_item, uint8_t expected_type);

/**
 * @brief Reads a boolean value from a CBOR item.
 *
 * @param item the CBOR item
 * @return true if the boolean value of the CBOR item is \c true
 * @return false if the boolean value of the CBOR item is \c false
 */
bool charra_cbor_get_bool_val(QCBORItem* item);

/**
 * @brief Returns a human-readable presentation of a CBOR error.
 *
 * @param err the CBOR error
 * @return const char* the string representation of the CBOR error
 */
const char* charra_cbor_err_str(QCBORError err);

#endif /* CBOR_UTIL_H */
