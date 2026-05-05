
/* SPDX-License-Identifier: BSD-3-Clause */
/*****************************************************************************
 * Copyright 2025, Fraunhofer Institute for Secure Information Technology SIT.
 * All rights reserved.
 ****************************************************************************/

/**
 * @file config_attester_file_util.c
 * @author Markus Horn (markus.horn@sit.fraunhofer.de)
 * @brief Provides parsing for attester config files.
 * @version 0.1
 * @date 2025-05-11
 *
 * @copyright Copyright 2024, Fraunhofer Institute for Secure Information
 * Technology SIT. All rights reserved.
 *
 * @license BSD 3-Clause "New" or "Revised" License (SPDX-License-Identifier:
 * BSD-3-Clause).
 */

#include "config_attester_file_util.h"

#include <stdint.h>
#include <string.h>
#include <tss2/tss2_tpm2_types.h>

#include "../../coap_util.h"
#include "../../crypto_util.h"
#include "../../parser_util.h"
#include "../../yaml_util.h"
#include "../config_attester_util.h"

#define CONFIG_KEY "charra-attester"
#define BUFFER_LEN 1024

#define KEY_ENABLE "enable"
#define KEY_HINT "hint"
#define KEY_KEY "key"
#define KEY_PRIVATE_KEY_PATH "private-key-path"
#define KEY_PUBLIC_KEY_PATH "public-key-path"
#define KEY_VERIFY_PEER_PUBLIC_KEY "verify-peer-public-key"
#define KEY_PEER_PUBLIC_KEY_PATH "peer-public-key-path"
#define KEY_DTLS_PSK "dtls-psk"
#define KEY_DTLS_RPK "dtls-rpk"
#define KEY_LOG_LEVEL "log-level"
#define KEY_UDP "udp"
#define KEY_FORMAT "format"
#define KEY_PATH "path"
#define KEY_IMA "ima"
#define KEY_TCG_BOOT "tcg-boot"
#define KEY_PCR_LOG "pcr-log"
#define KEY_SIGNATURE_SCHEME "tpm-quote-signature-scheme"
#define KEY_HASH_ALGORITHM "tpm-quote-signature-hash-algorithm"
#define KEY_LOCK_CONFIG "lock-config"
#define KEY_LISTEN_IP "listen-ip"
#define KEY_LISTEN_PORT "listen-port"
#define KEY_COAP "coap"
#define KEY_ATTESTATION "attestation"

static CHARRA_RC attester_dtls_psk_field_handler(
        charra_yaml_parser_state_t* parser_state, const char* const key,
        void* data) {
    CHARRA_RC charra_rc = CHARRA_RC_SUCCESS;
    config_attester* config = (config_attester*)data;

    if (strncmp(key, KEY_ENABLE, sizeof(KEY_ENABLE)) == 0) {
        charra_rc = parse_yaml_bool_value(parser_state, &config->use_dtls_psk);
        if (charra_rc != CHARRA_RC_SUCCESS) {
            return charra_rc;
        }
    } else if (strncmp(key, KEY_HINT, sizeof(KEY_HINT)) == 0) {
        charra_rc = parse_yaml_string_value(parser_state, config->dtls_psk_hint,
                sizeof(config->dtls_psk_hint));
        if (charra_rc != CHARRA_RC_SUCCESS) {
            return charra_rc;
        }
    } else if (strncmp(key, KEY_KEY, sizeof(KEY_KEY)) == 0) {
        charra_rc = parse_yaml_string_value(parser_state, config->dtls_psk_key,
                sizeof(config->dtls_psk_key));
        if (charra_rc != CHARRA_RC_SUCCESS) {
            return charra_rc;
        }
    } else {
        charra_rc = CHARRA_RC_ERROR;
        CHARRA_YAML_PARSER_ERROR_LOG_F(
                parser_state->parser, "unknown field '%s'", key);
    }
    return charra_rc;
}

static CHARRA_RC attester_dtls_rpk_field_handler(
        charra_yaml_parser_state_t* parser_state, const char* const key,
        void* data) {
    CHARRA_RC charra_rc = CHARRA_RC_SUCCESS;
    config_attester* config = (config_attester*)data;

    if (strncmp(key, KEY_ENABLE, sizeof(KEY_ENABLE)) == 0) {
        charra_rc = parse_yaml_bool_value(parser_state, &config->use_dtls_rpk);
        if (charra_rc != CHARRA_RC_SUCCESS) {
            return charra_rc;
        }
    } else if (strncmp(key, KEY_PRIVATE_KEY_PATH,
                       sizeof(KEY_PRIVATE_KEY_PATH)) == 0) {
        charra_rc = parse_yaml_string_value(parser_state,
                config->dtls_rpk_private_key_path,
                sizeof(config->dtls_rpk_private_key_path));
        if (charra_rc != CHARRA_RC_SUCCESS) {
            return charra_rc;
        }
    } else if (strncmp(key, KEY_PUBLIC_KEY_PATH, sizeof(KEY_PUBLIC_KEY_PATH)) ==
               0) {
        charra_rc = parse_yaml_string_value(parser_state,
                config->dtls_rpk_public_key_path,
                sizeof(config->dtls_rpk_public_key_path));
        if (charra_rc != CHARRA_RC_SUCCESS) {
            return charra_rc;
        }
    } else if (strncmp(key, KEY_VERIFY_PEER_PUBLIC_KEY,
                       sizeof(KEY_VERIFY_PEER_PUBLIC_KEY)) == 0) {
        charra_rc = parse_yaml_bool_value(
                parser_state, &config->dtls_rpk_verify_peer_public_key);
        if (charra_rc != CHARRA_RC_SUCCESS) {
            return charra_rc;
        }
    } else if (strncmp(key, KEY_PEER_PUBLIC_KEY_PATH,
                       sizeof(KEY_PEER_PUBLIC_KEY_PATH)) == 0) {
        charra_rc = parse_yaml_string_value(parser_state,
                config->dtls_rpk_peer_public_key_path,
                sizeof(config->dtls_rpk_peer_public_key_path));
        if (charra_rc != CHARRA_RC_SUCCESS) {
            return charra_rc;
        }
    } else {
        charra_rc = CHARRA_RC_ERROR;
        CHARRA_YAML_PARSER_ERROR_LOG_F(
                parser_state->parser, "unknown field '%s'", key);
    }
    return charra_rc;
}

static CHARRA_RC attester_udp_field_handler(
        charra_yaml_parser_state_t* parser_state, const char* const key,
        void* data) {
    CHARRA_RC charra_rc = CHARRA_RC_SUCCESS;
    if (strncmp(key, KEY_DTLS_PSK, sizeof(KEY_DTLS_PSK)) == 0) {
        charra_rc = parse_yaml_mapping(
                parser_state, attester_dtls_psk_field_handler, data);
    } else if (strncmp(key, KEY_DTLS_RPK, sizeof(KEY_DTLS_RPK)) == 0) {
        charra_rc = parse_yaml_mapping(
                parser_state, attester_dtls_rpk_field_handler, data);
    } else {
        charra_rc = CHARRA_RC_ERROR;
        CHARRA_YAML_PARSER_ERROR_LOG_F(
                parser_state->parser, "unknown field '%s'", key);
    }
    return charra_rc;
}

static CHARRA_RC attester_coap_field_handler(
        charra_yaml_parser_state_t* parser_state, const char* const key,
        void* data) {
    CHARRA_RC charra_rc = CHARRA_RC_SUCCESS;
    config_attester* config = (config_attester*)data;
    char string_value[BUFFER_LEN] = {0};

    if (strncmp(key, KEY_LOG_LEVEL, sizeof(KEY_LOG_LEVEL)) == 0) {
        charra_rc =
                parse_yaml_string_value(parser_state, string_value, BUFFER_LEN);
        if (charra_rc != CHARRA_RC_SUCCESS) {
            return charra_rc;
        }
        int rc = charra_coap_log_level_from_str(
                string_value, &config->coap_log_level);
        if (rc != 0) {
            CHARRA_YAML_PARSER_ERROR_LOG_F(parser_state->parser,
                    "unknown " KEY_LOG_LEVEL " '%s'", string_value);
            return CHARRA_RC_ERROR;
        }
    } else if (strncmp(key, KEY_UDP, sizeof(KEY_UDP)) == 0) {
        charra_rc = parse_yaml_mapping(
                parser_state, attester_udp_field_handler, data);
    } else {
        charra_rc = CHARRA_RC_ERROR;
        CHARRA_YAML_PARSER_ERROR_LOG_F(
                parser_state->parser, "unknown field '%s'", key);
    }
    return charra_rc;
}

static CHARRA_RC attester_attestation_key_field_handler(
        charra_yaml_parser_state_t* parser_state, const char* const key,
        void* data) {
    CHARRA_RC charra_rc = CHARRA_RC_SUCCESS;
    config_attester* config = (config_attester*)data;

    if (strncmp(key, KEY_FORMAT, sizeof(KEY_FORMAT)) == 0) {
        char string_value[BUFFER_LEN] = {0};
        charra_rc =
                parse_yaml_string_value(parser_state, string_value, BUFFER_LEN);
        if (charra_rc != CHARRA_RC_SUCCESS) {
            return charra_rc;
        }
        charra_config_attester_attestation_key_format_from_str(
                string_value, &config->attestation_key_format);
        if (config->attestation_key_format ==
                ATTESTER_ATTESTATION_KEY_FORMAT_UNKNOWN) {
            charra_rc = CHARRA_RC_ERROR;
            CHARRA_YAML_PARSER_ERROR_LOG_F(parser_state->parser,
                    "unknown attestation key format '%s'", string_value);
            return charra_rc;
        }
    } else if (strncmp(key, KEY_PATH, sizeof(KEY_PATH)) == 0) {
        /* as the format is not yet known, the value is initially saved as
         * ctx_path */
        charra_rc = parse_yaml_string_value(parser_state,
                config->attestation_key.ctx_path,
                sizeof(config->attestation_key.ctx_path));
        if (charra_rc != CHARRA_RC_SUCCESS) {
            return charra_rc;
        }
    } else {
        charra_rc = CHARRA_RC_ERROR;
        CHARRA_YAML_PARSER_ERROR_LOG_F(
                parser_state->parser, "unknown field '%s'", key);
    }
    return charra_rc;
}

static CHARRA_RC attester_pcr_log_field_handler(
        charra_yaml_parser_state_t* parser_state, const char* const key,
        void* data) {
    CHARRA_RC charra_rc = CHARRA_RC_SUCCESS;
    config_attester* config = (config_attester*)data;

    if (strncmp(key, KEY_IMA, sizeof(KEY_IMA)) == 0) {
        charra_rc = parse_yaml_string_value(parser_state, config->ima_log_path,
                sizeof(config->ima_log_path));
        if (charra_rc != CHARRA_RC_SUCCESS) {
            return charra_rc;
        }
    } else if (strncmp(key, KEY_TCG_BOOT, sizeof(KEY_TCG_BOOT)) == 0) {
        charra_rc = parse_yaml_string_value(parser_state,
                config->tcg_boot_log_path, sizeof(config->tcg_boot_log_path));
        if (charra_rc != CHARRA_RC_SUCCESS) {
            return charra_rc;
        }
    } else {
        charra_rc = CHARRA_RC_ERROR;
        CHARRA_YAML_PARSER_ERROR_LOG_F(
                parser_state->parser, "unknown field '%s'", key);
    }
    return charra_rc;
}

static CHARRA_RC attester_attestation_field_handler(
        charra_yaml_parser_state_t* parser_state, const char* const key,
        void* data) {
    CHARRA_RC charra_rc = CHARRA_RC_SUCCESS;
    config_attester* config = (config_attester*)data;
    char string_value[BUFFER_LEN] = {0};

    if (strncmp(key, KEY_KEY, sizeof(KEY_KEY)) == 0) {
        charra_rc = parse_yaml_mapping(
                parser_state, attester_attestation_key_field_handler, data);
    } else if (strncmp(key, KEY_PCR_LOG, sizeof(KEY_PCR_LOG)) == 0) {
        charra_rc = parse_yaml_mapping(
                parser_state, attester_pcr_log_field_handler, data);
    } else if (strncmp(key, KEY_SIGNATURE_SCHEME,
                       sizeof(KEY_SIGNATURE_SCHEME)) == 0) {
        charra_rc =
                parse_yaml_string_value(parser_state, string_value, BUFFER_LEN);
        if (charra_rc != CHARRA_RC_SUCCESS) {
            return charra_rc;
        }
        config->signature_scheme =
                charra_signature_scheme_from_str(string_value);
        if (config->signature_scheme == TPM2_ALG_NULL) {
            charra_rc = CHARRA_RC_ERROR;
            CHARRA_YAML_PARSER_ERROR_LOG_F(parser_state->parser,
                    "unsupported signature scheme '%s'", string_value);
            return charra_rc;
        }
    } else if (strncmp(key, KEY_HASH_ALGORITHM, sizeof(KEY_HASH_ALGORITHM)) ==
               0) {
        charra_rc =
                parse_yaml_string_value(parser_state, string_value, BUFFER_LEN);
        if (charra_rc != CHARRA_RC_SUCCESS) {
            return charra_rc;
        }
        config->hash_algorithm =
                charra_tpm_hash_algorithm_from_str(string_value);
        if (config->hash_algorithm == TPM2_ALG_NULL) {
            charra_rc = CHARRA_RC_ERROR;
            CHARRA_YAML_PARSER_ERROR_LOG_F(parser_state->parser,
                    "unsupported hash algorithm '%s'", string_value);
            return charra_rc;
        }
    } else {
        charra_rc = CHARRA_RC_ERROR;
        CHARRA_YAML_PARSER_ERROR_LOG_F(
                parser_state->parser, "unknown field '%s'", key);
    }
    return charra_rc;
}

static CHARRA_RC attester_inner_field_handler(
        charra_yaml_parser_state_t* parser_state, const char* const key,
        void* data) {
    CHARRA_RC charra_rc = CHARRA_RC_SUCCESS;
    config_attester* config = (config_attester*)data;

    char string_value[BUFFER_LEN] = {0};
    uint64_t long_value = 0;

    if (strncmp(key, KEY_LOCK_CONFIG, sizeof(KEY_LOCK_CONFIG)) == 0) {
        charra_rc = parse_yaml_bool_value(parser_state, &config->lock_config);
        if (charra_rc != CHARRA_RC_SUCCESS) {
            return charra_rc;
        }
    } else if (strncmp(key, KEY_LISTEN_IP, sizeof(KEY_LISTEN_IP)) == 0) {
        charra_rc = parse_yaml_string_value(
                parser_state, config->listen_ip, sizeof(config->listen_ip));
        if (charra_rc != CHARRA_RC_SUCCESS) {
            return charra_rc;
        }
    } else if (strncmp(key, KEY_LISTEN_PORT, sizeof(KEY_LISTEN_PORT)) == 0) {
        charra_rc = parse_yaml_ulong_value(parser_state, &long_value);
        if (charra_rc != CHARRA_RC_SUCCESS) {
            return charra_rc;
        }
        if (long_value > UINT16_MAX) {
            charra_rc = CHARRA_RC_ERROR;
            CHARRA_YAML_PARSER_ERROR_LOG_F(parser_state->parser,
                    KEY_LISTEN_PORT " value %lu is too large", long_value);
        }
        config->port = (uint16_t)long_value;
    } else if (strncmp(key, KEY_LOG_LEVEL, sizeof(KEY_LOG_LEVEL)) == 0) {
        charra_rc =
                parse_yaml_string_value(parser_state, string_value, BUFFER_LEN);
        if (charra_rc != CHARRA_RC_SUCCESS) {
            return charra_rc;
        }
        int rc = charra_log_level_from_str(
                string_value, &config->charra_log_level);
        if (rc != 0) {
            CHARRA_YAML_PARSER_ERROR_LOG_F(parser_state->parser,
                    "unknown " KEY_LOG_LEVEL " '%s'", string_value);
            return CHARRA_RC_ERROR;
        }
    } else if (strncmp(key, KEY_COAP, sizeof(KEY_COAP)) == 0) {
        charra_rc = parse_yaml_mapping(
                parser_state, attester_coap_field_handler, data);
    } else if (strncmp(key, KEY_ATTESTATION, sizeof(KEY_ATTESTATION)) == 0) {
        charra_rc = parse_yaml_mapping(
                parser_state, attester_attestation_field_handler, data);
    } else {
        charra_rc = CHARRA_RC_ERROR;
        CHARRA_YAML_PARSER_ERROR_LOG_F(
                parser_state->parser, "unknown field '%s'", key);
    }

    return charra_rc;
}

static CHARRA_RC attester_field_handler(
        charra_yaml_parser_state_t* parser_state, const char* const key,
        void* data) {
    CHARRA_RC charra_rc = CHARRA_RC_SUCCESS;
    if (strncmp(key, CONFIG_KEY, sizeof(CONFIG_KEY)) == 0) {
        charra_rc = parse_yaml_mapping(
                parser_state, attester_inner_field_handler, data);
    } else {
        charra_rc = CHARRA_RC_ERROR;
        CHARRA_YAML_PARSER_ERROR_LOG_F(
                parser_state->parser, "unknown field '%s'", key);
    }
    return charra_rc;
}

CHARRA_RC load_attester_yaml_config_file(
        const char* const path, config_attester* const config) {
    CHARRA_RC charra_rc = CHARRA_RC_SUCCESS;
    uint64_t long_value = 0;

    charra_rc = parse_yaml_file(path, attester_field_handler, NULL, config);
    if (charra_rc != CHARRA_RC_SUCCESS) {
        return charra_rc;
    }
    /* translate the attestation key to its format */
    switch (config->attestation_key_format) {
    case ATTESTER_ATTESTATION_KEY_FORMAT_FILE:
        /* value is already a file path */
        break;
    case ATTESTER_ATTESTATION_KEY_FORMAT_HANDLE:
        /* translate the ctx_path to a handle */
        charra_rc =
                parse_ulong(config->attestation_key.ctx_path, 16, &long_value);
        if (charra_rc != CHARRA_RC_SUCCESS) {
            charra_log_error("Attestation key: invalid handle value '%s'.",
                    config->attestation_key.ctx_path);
            charra_rc = CHARRA_RC_ERROR;
            break;
        }
        if (long_value > UINT32_MAX) {
            charra_log_error("Attestation key: handle value %lu is too large",
                    long_value);
        }
        config->attestation_key.tpm2_handle = (ESYS_TR)long_value;
        break;
    case ATTESTER_ATTESTATION_KEY_FORMAT_UNKNOWN:
    default:
        charra_log_error("Unknown attestation key format");
        charra_rc = CHARRA_RC_ERROR;
        break;
    }
    return charra_rc;
}
