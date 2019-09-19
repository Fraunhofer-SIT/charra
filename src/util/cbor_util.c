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

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <tinycbor/cbor.h>

#include "../common/charra_log.h"

const char* cbor_type_string(const CborType type) {
	switch (type) {
	case CborIntegerType:
		return "CborIntegerType";
	case CborByteStringType:
		return "CborByteStringType";
	case CborTextStringType:
		return "CborTextStringType";
	case CborArrayType:
		return "CborArrayType";
	case CborMapType:
		return "CborMapType";
	case CborTagType:
		return "CborTagType";
	case CborSimpleType:
		return "CborSimpleType";
	case CborBooleanType:
		return "CborBooleanType";
	case CborNullType:
		return "CborNullType";
	case CborUndefinedType:
		return "CborUndefinedType";
	case CborHalfFloatType:
		return "CborHalfFloatType";
	case CborFloatType:
		return "CborFloatType";
	case CborDoubleType:
		return "CborDoubleType";
	case CborInvalidType:
		return "CborInvalidType";
	default:
		return "UNKNOWN";
	}
}

void cbor_indent(int nesting_level) {
	while (nesting_level--) {
		printf("  ");
	}
}

void cbor_dumpbytes(const uint8_t* buf, size_t len) {
	while (len--) {
		printf("%02X ", *buf++);
	}
}

CborError cbor_dumprecursive(CborValue* it, int nesting_level) {
	while (!cbor_value_at_end(it)) {
		CborError err;
		CborType type = cbor_value_get_type(it);

		cbor_indent(nesting_level);
		switch (type) {
		case CborArrayType:
		case CborMapType: {
			// recursive type
			CborValue recursed;
			assert(cbor_value_is_container(it));
			puts(type == CborArrayType ? "Array[" : "Map[");
			err = cbor_value_enter_container(it, &recursed);
			if (err)
				return err; // parse error
			err = cbor_dumprecursive(&recursed, nesting_level + 1);
			if (err)
				return err; // parse error
			err = cbor_value_leave_container(it, &recursed);
			if (err)
				return err; // parse error
			cbor_indent(nesting_level);
			puts("]");
			continue;
		}

		case CborIntegerType: {
			int64_t val;
			cbor_value_get_int64(it, &val); // can't fail
			printf("%lld\n", (long long)val);
			break;
		}

		case CborByteStringType: {
			uint8_t* buf;
			size_t n;
			err = cbor_value_dup_byte_string(it, &buf, &n, it);
			if (err)
				return err; // parse error
			cbor_dumpbytes(buf, n);
			puts("");
			free(buf);
			continue;
		}

		case CborTextStringType: {
			char* buf;
			size_t n;
			err = cbor_value_dup_text_string(it, &buf, &n, it);
			if (err)
				return err; // parse error
			puts(buf);
			free(buf);
			continue;
		}

		case CborTagType: {
			CborTag tag;
			cbor_value_get_tag(it, &tag); // can't fail
			printf("Tag(%lld)\n", (long long)tag);
			break;
		}

		case CborSimpleType: {
			uint8_t type;
			cbor_value_get_simple_type(it, &type); // can't fail
			printf("simple(%u)\n", type);
			break;
		}

		case CborNullType:
			puts("null");
			break;

		case CborUndefinedType:
			puts("undefined");
			break;

		case CborBooleanType: {
			bool val;
			cbor_value_get_boolean(it, &val); // can't fail
			puts(val ? "true" : "false");
			break;
		}

		case CborDoubleType: {
			double val;
			if (false) {
				float f;
			case CborFloatType:
				cbor_value_get_float(it, &f);
				val = f;
			} else {
				cbor_value_get_double(it, &val);
			}
			printf("%g\n", val);
			break;
		}
		case CborHalfFloatType: {
			uint16_t val;
			cbor_value_get_half_float(it, &val);
			printf("__f16(%04x)\n", val);
			break;
		}

		case CborInvalidType:
			assert(false); // can't happen
			break;
		}

		err = cbor_value_advance_fixed(it);
		if (err)
			return err;
	}
	return CborNoError;
}

CborError charra_cbor_parse_boolean(CborValue* it, bool* value) {
	CborError err = CborNoError;
	CborType type = CborInvalidType;

	/* expect particular CBOR type */
	const CborType expected_type = CborBooleanType;
	if ((type = cbor_value_get_type(it)) != expected_type) {
		charra_log_error("CBOR parser: expected type %s, found type %s.",
			cbor_type_string(expected_type), cbor_type_string(type));
		return CborErrorIllegalType;
	}
	charra_log_debug("CBOR parser: found type %s.", cbor_type_string(type));

	/* parse CBOR value */
	bool result = false;
	if ((err = cbor_value_get_boolean(it, &result))) {
		charra_log_error("CBOR parser: %s.", cbor_error_string(err));
		return err;
	}
	charra_log_debug("CBOR parser: parsed %s => %s.", cbor_type_string(type),
		result ? "true" : "false");

	/* set out param(s) */
	*value = result;

	/* return positive result */
	return CborNoError;
}

CborError charra_cbor_parse_uint8(CborValue* it, uint8_t* value) {
	/* parse CBOR value */
	uint64_t result = 0;
	CborError err = charra_cbor_parse_uint64(it, &result);

	/* set out param(s) */
	*value = (uint8_t)result;

	/* return result */
	return err;
}

CborError charra_cbor_parse_uint16(CborValue* it, uint16_t* value) {
	/* parse CBOR value */
	uint64_t result = 0;
	CborError err = charra_cbor_parse_uint64(it, &result);

	/* set out param(s) */
	*value = (uint16_t)result;

	/* return result */
	return err;
}

CborError charra_cbor_parse_uint32(CborValue* it, uint32_t* value) {
	/* parse CBOR value */
	uint64_t result = 0;
	CborError err = charra_cbor_parse_uint64(it, &result);

	/* set out param(s) */
	*value = (uint32_t)result;

	/* return result */
	return err;
}

CborError charra_cbor_parse_uint64(CborValue* it, uint64_t* value) {
	CborError err = CborNoError;
	CborType type = CborInvalidType;

	/* expect particular CBOR type */
	const CborType expected_type = CborIntegerType;
	if ((type = cbor_value_get_type(it)) != expected_type) {
		charra_log_error("CBOR parser: expected type %s, found type %s.",
			cbor_type_string(expected_type), cbor_type_string(type));
		return CborErrorIllegalType;
	}
	charra_log_debug("CBOR parser: found type %s.", cbor_type_string(type));

	/* parse CBOR value */
	uint64_t result = 0;
	if ((err = cbor_value_get_uint64(it, &result))) {
		charra_log_error("CBOR parser: %s.", cbor_error_string(err));
		return err;
	}
	charra_log_debug(
		"CBOR parser: parsed %s => %d.", cbor_type_string(type), result);

	/* set out param(s) */
	*value = result;

	/* return positive result */
	return CborNoError;
}

CborError charra_cbor_parse_byte_string(
	CborValue* it, size_t* value_len, uint8_t** value) {
	const CborType expected_type = CborByteStringType;

	CborError err = CborNoError;
	CborType type = CborInvalidType;

	/* expect particular CBOR type */
	if ((type = cbor_value_get_type(it)) != expected_type) {
		charra_log_error("CBOR parser: expected type %s, found type %s.",
			cbor_type_string(expected_type), cbor_type_string(type));
		return CborErrorIllegalType;
	}
	charra_log_debug("CBOR parser: found type %s.", cbor_type_string(type));

	/* parse CBOR value */
	size_t result_len = 0;
	uint8_t* result = NULL;
	if ((err = cbor_value_dup_byte_string(it, &result, &result_len, it))) {
		charra_log_error("CBOR parser: %s.", cbor_error_string(err));
		return err;
	}
	charra_log_debug("CBOR parser: parsed %s of length %d.",
		cbor_type_string(type), result_len);

	/* set out param(s) */
	*value_len = result_len;
	*value = result;

	/* return positive result */
	return CborNoError;
}

CborError charra_cbor_parse_enter_array(CborValue* it, CborValue* array) {
	const CborType expected_type = CborArrayType;

	CborType type = CborInvalidType;
	CborError err = CborNoError;

	/* expect particular CBOR type */
	if ((type = cbor_value_get_type(it)) != expected_type) {
		charra_log_error("CBOR parser: expected type %s, found type %s.",
			cbor_type_string(expected_type), cbor_type_string(type));
		return CborErrorIllegalType;
	}
	charra_log_debug("CBOR parser: found type %s.", cbor_type_string(type));

	/* enter CBOR array */
	if ((err = cbor_value_enter_container(it, array))) {
		charra_log_error("CBOR parser: %s.", cbor_error_string(err));
		return err;
	}
	charra_log_debug(
		"CBOR parser: entering array with %d elements.", array->remaining);

	/* return positive result */
	return CborNoError;
}
