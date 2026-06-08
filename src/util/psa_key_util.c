/* SPDX-License-Identifier: BSD-3-Clause */
/*****************************************************************************
 * Copyright 2026, Fraunhofer Institute for Secure Information Technology
 * SIT. All rights reserved.
 ****************************************************************************/

/**
 * @file psa_key_util.c
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

#include "psa_key_util.h"

#include <string.h>

#define INT24_MAX 0x7FFFFF

#define INTEGER_TAG 0x02
#define SEQUENCE_TAG 0x30

#define UNCOMPRESSED_POINT 0x04

static size_t get_der_tag_length_len(size_t value_length) {
    // short form tag length
    if (value_length <= INT8_MAX) {
        return 1;
    }
    // long form tag length
    size_t tag_length = 1;
    size_t remaining_length = value_length;
    while (remaining_length > 0) {
        tag_length++;
        remaining_length >>= 8;
    }
    return tag_length;
}

static size_t encode_der_tag_length(size_t value_length, uint8_t* buffer) {
    if (value_length <= INT8_MAX) {
        *buffer = (uint8_t)value_length;
        return 1;
    }
    uint8_t remaining_tag_bytes = 0;
    size_t remaining_length = value_length;
    // get remaining tag bytes
    while (remaining_length > 0) {
        remaining_tag_bytes++;
        remaining_length >>= 8;
    }
    // write long form tag length
    *buffer = 0x80U | remaining_tag_bytes;
    // write length bytes in big-endian order
    uint8_t* iterator = buffer + remaining_tag_bytes;
    remaining_length = value_length;
    while (iterator > buffer) {
        *iterator-- = (uint8_t)(remaining_length & 0xFF);
        remaining_length >>= 8;
    }
    return 1 + remaining_tag_bytes;
}

static size_t get_der_biginteger_length(
        const uint8_t* buffer, size_t buffer_size) {
    if (buffer_size == 0) {
        return 0;
    }

    if ((buffer[0] & 0x80U) != 0U) {
        return buffer_size + 1;
    } else {
        return buffer_size;
    }
}

static size_t get_der_biginteger_full_length(
        const uint8_t* buffer, size_t buffer_size) {
    size_t length = get_der_biginteger_length(buffer, buffer_size);
    length += get_der_tag_length_len(length);
    return length + 1;  // add 1 byte for ASN.1 INTEGER tag
}

static size_t encode_der_biginteger(
        const uint8_t* buffer, size_t buffer_size, uint8_t* output) {
    size_t offset = 0;

    size_t value_length = get_der_biginteger_length(buffer, buffer_size);
    output[offset++] = INTEGER_TAG;
    offset += encode_der_tag_length(value_length, output + offset);
    // encode biginteger value
    if ((buffer[0] & 0x80U) != 0U) {
        output[offset++] = 0x00;  // prepend zero byte for positive integer
    }
    memcpy(output + offset, buffer, buffer_size);

    offset += buffer_size;
    return offset;
}

static size_t get_der_integer_length(uint32_t value) {
    if (value <= INT8_MAX) {
        return 1;
    } else if (value <= INT16_MAX) {
        return 2;
    } else if (value <= INT24_MAX) {
        return 3;
    } else if (value <= INT32_MAX) {
        return 4;
    } else {
        return 5;
    }
}

static size_t get_der_integer_full_length(uint32_t value) {
    size_t length = get_der_integer_length(value);
    // add 2 bytes for ASN.1 INTEGER tag and short-form tag-length-value
    return length + 2;
}

static size_t encode_der_integer(uint32_t value, uint8_t* output) {
    size_t offset = 0;

    size_t value_length = get_der_integer_length(value);
    output[offset++] = INTEGER_TAG;
    offset += encode_der_tag_length(value_length, output + offset);
    for (size_t i = 0; i < value_length; i++) {
        output[offset + value_length - 1 - i] = (uint8_t)(value & 0xFF);
        value >>= 8;
    }
    offset += value_length;
    return offset;
}

static size_t get_der_rsa_pub_key_length(
        const uint8_t* modulus, size_t modulus_size, uint32_t exponent) {
    size_t modulus_integer_length =
            get_der_biginteger_full_length(modulus, modulus_size);
    size_t exponent_integer_length = get_der_integer_full_length(exponent);
    return modulus_integer_length + exponent_integer_length;
}

static size_t get_der_rsa_pub_key_full_length(
        const uint8_t* modulus, size_t modulus_size, uint32_t exponent) {
    size_t value_length =
            get_der_rsa_pub_key_length(modulus, modulus_size, exponent);
    size_t tag_length_len = get_der_tag_length_len(value_length);
    return value_length + tag_length_len +
           1;  // add 1 byte for ASN.1 SEQUENCE tag
}

CHARRA_RC charra_der_encode_rsa_pub_key(const uint8_t* modulus,
        size_t modulus_size, uint32_t exponent, uint8_t* key,
        size_t key_buffer_size, size_t* key_len) {
    if (modulus == NULL || key == NULL || key_len == NULL) {
        return CHARRA_RC_BAD_ARGUMENT;
    }

    // calculate full DER-encoded RSA public key length and check if output
    // buffer is sufficient
    size_t offset = 0;
    size_t full_length =
            get_der_rsa_pub_key_full_length(modulus, modulus_size, exponent);
    if (key_buffer_size < full_length) {
        *key_len = 0;
        return CHARRA_RC_MARSHALING_ERROR;
    }
    *key_len = full_length;

    // RSAPublicKey ::= SEQUENCE {
    //  modulus            INTEGER,    -- n
    //  publicExponent     INTEGER  }  -- e

    key[offset++] = SEQUENCE_TAG;
    size_t value_length =
            get_der_rsa_pub_key_length(modulus, modulus_size, exponent);
    offset += encode_der_tag_length(value_length, key + offset);
    // modulus
    offset += encode_der_biginteger(modulus, modulus_size, key + offset);
    // exponent
    encode_der_integer(exponent, key + offset);

    return CHARRA_RC_SUCCESS;
}

CHARRA_RC charra_octet_string_encode_ecdsa_pub_key(const uint8_t* qx,
        size_t qx_size, const uint8_t* qy, size_t qy_size, uint8_t* key,
        size_t key_buffer_size, size_t* key_len) {
    if (qx == NULL || qy == NULL || key == NULL || key_len == NULL) {
        return CHARRA_RC_BAD_ARGUMENT;
    }

    size_t full_length = 1 + qx_size + qy_size;  // uncompressed point format
    if (key_buffer_size < full_length) {
        return CHARRA_RC_MARSHALING_ERROR;
    }

    *key_len = full_length;

    //  PSA ECC public key format:
    //  Uncompressed point: 0x04 || X || Y

    key[0] = UNCOMPRESSED_POINT;

    memcpy(key + 1, qx, qx_size);
    memcpy(key + 1 + qx_size, qy, qy_size);

    return CHARRA_RC_SUCCESS;
}
