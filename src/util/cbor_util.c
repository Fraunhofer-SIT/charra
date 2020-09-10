/* SPDX-License-Identifier: BSD-3-Clause */
/*****************************************************************************
 * Copyright 2019, Fraunhofer Institute for Secure Information Technology SIT.
 * All rights reserved.
 ****************************************************************************/

/**
 * @file cbor_util.c
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

// #include "cbor_util.h"

#include "cbor_util.h"

#include <qcbor/qcbor.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#include "../common/charra_log.h"

const char* cbor_type_string(const uint8_t type) {
	switch (type) {
	case QCBOR_TYPE_NONE:
		return "CborInvalidType";
	case QCBOR_TYPE_INT64:
		return "CborIntegerType";
	case QCBOR_TYPE_UINT64:
		return "CborUnsignedIntegerType";
	case QCBOR_TYPE_ARRAY:
		return "CborArrayType";
	case QCBOR_TYPE_MAP:
		return "CborMapType";
	case QCBOR_TYPE_BYTE_STRING:
		return "CborByteStringType";
	case QCBOR_TYPE_TEXT_STRING:
		return "CborTextStringType";
	case QCBOR_TYPE_POSBIGNUM:
		return "CborPositiveBigIntegerType";
	case QCBOR_TYPE_NEGBIGNUM:
		return "CborNegativeBigIntegerType";
	case QCBOR_TYPE_DATE_STRING:
		return "CborDateStringType";
	case QCBOR_TYPE_DATE_EPOCH:
		return "CborDateEpochType";
	case QCBOR_TYPE_UKNOWN_SIMPLE:
		return "CborUnknownSimpleType";
	case QCBOR_TYPE_DECIMAL_FRACTION:
		return "CborDecimalFractionType";
	case QCBOR_TYPE_DECIMAL_FRACTION_POS_BIGNUM:
		return "CborPostivieDecimalFractionType";
	case QCBOR_TYPE_DECIMAL_FRACTION_NEG_BIGNUM:
		return "CborNegativeDecimalFractionType";
	case QCBOR_TYPE_BIGFLOAT:
		return "CborBigfloatType";
	case QCBOR_TYPE_BIGFLOAT_POS_BIGNUM:
		return "CborPositiveBigfloatType";
	case QCBOR_TYPE_BIGFLOAT_NEG_BIGNUM:
		return "CborNegativeBigfloatType";
	case QCBOR_TYPE_FALSE:
		return "CborFalseType";
	case QCBOR_TYPE_TRUE:
		return "CborFalseType";
	case QCBOR_TYPE_NULL:
		return "CborNullType";
	case QCBOR_TYPE_UNDEF:
		return "CborUndefType";
	case QCBOR_TYPE_FLOAT:
		return "CborFloatType";
	case QCBOR_TYPE_DOUBLE:
		return "CborDoubleType";
	case QCBOR_TYPE_MAP_AS_ARRAY:
		return "CborMapAsArrayType";
	case CHARRA_CBOR_TYPE_BOOLEAN:
		return "CharraCborBooleanType";
	default:
		return "UNKNOWN";
	}
}

CHARRA_RC charra_cbor_get_next(
	QCBORDecodeContext* ctx, QCBORItem* decoded_item, uint8_t expected_type) {
	uint8_t type = 0;
	bool is_expected_type = false;

	if (QCBORDecode_GetNext(ctx, decoded_item)) {
		charra_log_error("CBOR Parser: Error getting next item");
		return CHARRA_RC_MARSHALING_ERROR;
	}

	if (expected_type != QCBOR_TYPE_NONE) {
		/* expect particular CBOR type */
		type = decoded_item->uDataType;
		is_expected_type = type == expected_type;
		if (expected_type == CHARRA_CBOR_TYPE_BOOLEAN) {
			is_expected_type =
				type == QCBOR_TYPE_FALSE || type == QCBOR_TYPE_TRUE;
		}
		if (!is_expected_type) {
			charra_log_error("CBOR parser: expected type %s, found type %s.",
				cbor_type_string(expected_type), cbor_type_string(type));
			return CHARRA_RC_MARSHALING_ERROR;
		}
		charra_log_debug("CBOR parser: found type %s.", cbor_type_string(type));
	}

	/* return positive result */
	return CHARRA_RC_SUCCESS;
}

bool charra_cbor_get_bool_val(QCBORItem* item) {
	if (item->uDataType == QCBOR_TYPE_TRUE) {
		return true;
	}

	return false;
}
