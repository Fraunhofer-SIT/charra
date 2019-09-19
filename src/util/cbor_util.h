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

#include <tinycbor/cbor.h>

/**
 * @brief Returns a human-readable presentation of a CBOR type.
 *
 * @param type[in] The CBOR type.
 * @return The human-readable CBOR type.
 */
const char* cbor_type_string(const CborType type);

/**
 * @brief Indents a CBOR dump.
 * @see https://github.com/intel/tinycbor/blob/master/examples/simplereader.c
 */
void cbor_indent(int nesting_level);

/**
 * @brief Dumps bytes.
 * @see https://github.com/intel/tinycbor/blob/master/examples/simplereader.c
 */
void cbor_dumpbytes(const uint8_t* buf, size_t len);

/**
 * @brief Dumps a CBOR object recursively.
 * @see https://github.com/intel/tinycbor/blob/master/examples/simplereader.c
 */
CborError cbor_dumprecursive(CborValue* it, int nesting_level);

/**
 * @brief Parses a CBOR boolean.
 *
 * @param it[in,out] The CBOR value iterator.
 * @param value[out] The parsed value.
 * @return CborError The CBOR error that occurred during parsing.
 */
CborError charra_cbor_parse_boolean(CborValue* it, bool* value);

/**
 * @brief Parses a CBOR 8-bit unsigned integer.
 *
 * @param it[in,out] The CBOR value iterator.
 * @param value[out] The parsed value.
 * @return CborError The CBOR error that occurred during parsing.
 */
CborError charra_cbor_parse_uint8(CborValue* it, uint8_t* value);

/**
 * @brief Parses a CBOR 16-bit unsigned integer.
 *
 * @param it[in,out] The CBOR value iterator.
 * @param value[out] The parsed value.
 * @return CborError The CBOR error that occurred during parsing.
 */
CborError charra_cbor_parse_uint16(CborValue* it, uint16_t* value);

/**
 * @brief Parses a CBOR 32-bit unsigned integer.
 *
 * @param it[in,out] The CBOR value iterator.
 * @param value[out] The parsed value.
 * @return CborError The CBOR error that occurred during parsing.
 */
CborError charra_cbor_parse_uint32(CborValue* it, uint32_t* value);

/**
 * @brief Parses a CBOR 64-bit unsigned integer.
 *
 * @param it[in,out] The CBOR value iterator.
 * @param value[out] The parsed value.
 * @return CborError The CBOR error that occurred during parsing.
 */
CborError charra_cbor_parse_uint64(CborValue* it, uint64_t* value);

/**
 * @brief Parses a CBOR byte string.
 *
 * @param it The CBOR value iterator.
 * @param value_len[out] The length of the parsed value.
 * @param value[out] The parsed value.
 * @return CborError The CBOR error that occurred during parsing.
 */
CborError charra_cbor_parse_byte_string(
	CborValue* it, size_t* value_len, uint8_t** value);

/**
 * @brief
 *
 * @param it
 * @param array
 * @return CborError
 */
CborError charra_cbor_parse_enter_array(CborValue* it, CborValue* array);

#endif /* CBOR_UTIL_H */
