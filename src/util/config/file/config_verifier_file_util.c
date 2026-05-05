/* SPDX-License-Identifier: BSD-3-Clause */
/*****************************************************************************
 * Copyright 2025, Fraunhofer Institute for Secure Information Technology SIT.
 * All rights reserved.
 ****************************************************************************/

/**
 * @file config_verifier_file_util.c
 * @author Markus Horn (markus.horn@sit.fraunhofer.de)
 * @brief Provides parsing for verifier config files.
 * @version 0.1
 * @date 2025-05-11
 *
 * @copyright Copyright 2024, Fraunhofer Institute for Secure Information
 * Technology SIT. All rights reserved.
 *
 * @license BSD 3-Clause "New" or "Revised" License (SPDX-License-Identifier:
 * BSD-3-Clause).
 */

#include "config_verifier_file_util.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <tss2/tss2_tpm2_types.h>
#include <yaml.h>

#include "../../coap_util.h"
#include "../../parser_util.h"
#include "../../yaml_util.h"
#include "../config_verifier_util.h"

#define CONFIG_KEY "charra-verifier"
#define BUFFER_LEN 1024

#define KEY_ENABLE "enable"
#define KEY_IDENTITY "identity"
#define KEY_KEY "key"
#define KEY_PRIVATE_KEY_PATH "private-key-path"
#define KEY_PUBLIC_KEY_PATH "public-key-path"
#define KEY_VERIFY_PEER_PUBLIC_KEY "verify-peer-public-key"
#define KEY_PEER_PUBLIC_KEY_PATH "peer-public-key-path"
#define KEY_DTLS_PSK "dtls-psk"
#define KEY_DTLS_RPK "dtls-rpk"
#define KEY_LOG_LEVEL "log-level"
#define KEY_IO_PROCESS_TIME_MS "io-process-time-ms"
#define KEY_UDP "udp"
#define KEY_START "start"
#define KEY_COUNT "count"
#define KEY_IMA "ima"
#define KEY_TCG_BOOT "tcg-boot"
#define KEY_SHA1 "sha1"
#define KEY_SHA256 "sha256"
#define KEY_SHA384 "sha384"
#define KEY_SHA512 "sha512"
#define KEY_PATH "path"
#define KEY_FORMAT "format"
#define KEY_RESPONSE_TIMEOUT "response-timeout"
#define KEY_USE_TPM_FOR_NONCE "use-tpm-for-random-nonce-generation"
#define KEY_TPM_SIG_KEY_ID "tpm-sig-key-id"
#define KEY_TPM_QUOTE_SIG_HASH_ALG "tpm-quote-signature-hash-algorithm"
#define KEY_REFERENCE_PCR_FILE "reference-pcr-file"
#define KEY_TPM_PCR_SELECTION "tpm-pcr-selection"
#define KEY_PCR_LOG "pcr-log"
#define KEY_LOCK_CONFIG "lock-config"
#define KEY_TARGET_HOST "target-host"
#define KEY_TARGET_PORT "target-port"
#define KEY_COAP "coap"
#define KEY_ATTESTATION "attestation"

static CHARRA_RC verifier_dtls_psk_field_handler(
        charra_yaml_parser_state_t* parser_state, const char* const key,
        void* data) {
    CHARRA_RC charra_rc = CHARRA_RC_SUCCESS;
    config_verifier* config = (config_verifier*)data;

    if (strncmp(key, KEY_ENABLE, sizeof(KEY_ENABLE)) == 0) {
        charra_rc = parse_yaml_bool_value(parser_state, &config->use_dtls_psk);
        if (charra_rc != CHARRA_RC_SUCCESS) {
            return charra_rc;
        }
    } else if (strncmp(key, KEY_IDENTITY, sizeof(KEY_IDENTITY)) == 0) {
        charra_rc = parse_yaml_string_value(parser_state,
                config->dtls_psk_identity, sizeof(config->dtls_psk_identity));
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

static CHARRA_RC verifier_dtls_rpk_field_handler(
        charra_yaml_parser_state_t* parser_state, const char* const key,
        void* data) {
    CHARRA_RC charra_rc = CHARRA_RC_SUCCESS;
    config_verifier* config = (config_verifier*)data;

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

static CHARRA_RC verifier_udp_field_handler(
        charra_yaml_parser_state_t* parser_state, const char* const key,
        void* data) {
    CHARRA_RC charra_rc = CHARRA_RC_SUCCESS;
    if (strncmp(key, KEY_DTLS_PSK, sizeof(KEY_DTLS_PSK)) == 0) {
        charra_rc = parse_yaml_mapping(
                parser_state, verifier_dtls_psk_field_handler, data);
    } else if (strncmp(key, KEY_DTLS_RPK, sizeof(KEY_DTLS_RPK)) == 0) {
        charra_rc = parse_yaml_mapping(
                parser_state, verifier_dtls_rpk_field_handler, data);
    } else {
        charra_rc = CHARRA_RC_ERROR;
        CHARRA_YAML_PARSER_ERROR_LOG_F(
                parser_state->parser, "unknown field '%s'", key);
    }
    return charra_rc;
}

static CHARRA_RC verifier_coap_field_handler(
        charra_yaml_parser_state_t* parser_state, const char* const key,
        void* data) {
    CHARRA_RC charra_rc = CHARRA_RC_SUCCESS;
    config_verifier* config = (config_verifier*)data;

    char string_value[BUFFER_LEN] = {0};
    uint64_t long_value = 0;

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
    } else if (strncmp(key, KEY_IO_PROCESS_TIME_MS,
                       sizeof(KEY_IO_PROCESS_TIME_MS)) == 0) {
        charra_rc = parse_yaml_ulong_value(parser_state, &long_value);
        if (charra_rc != CHARRA_RC_SUCCESS) {
            return charra_rc;
        }
        if (long_value > UINT32_MAX) {
            charra_rc = CHARRA_RC_ERROR;
            CHARRA_YAML_PARSER_ERROR_LOG_F(parser_state->parser,
                    KEY_IO_PROCESS_TIME_MS " value %lu is too large",
                    long_value);
        }
        config->io_process_time_ms = (uint32_t)long_value;
    } else if (strncmp(key, KEY_UDP, sizeof(KEY_UDP)) == 0) {
        charra_rc = parse_yaml_mapping(
                parser_state, verifier_udp_field_handler, data);
    } else {
        charra_rc = CHARRA_RC_ERROR;
        CHARRA_YAML_PARSER_ERROR_LOG_F(
                parser_state->parser, "unknown field '%s'", key);
    }
    return charra_rc;
}

static CHARRA_RC verifier_pcr_log_request_field_handler(
        charra_yaml_parser_state_t* parser_state, const char* const key,
        void* data) {
    CHARRA_RC charra_rc = CHARRA_RC_SUCCESS;
    pcr_log_dto* pcr_log = (pcr_log_dto*)data;

    if (strncmp(key, KEY_START, sizeof(KEY_START)) == 0) {
        charra_rc = parse_yaml_ulong_value(parser_state, &pcr_log->start);
        if (charra_rc != CHARRA_RC_SUCCESS) {
            return charra_rc;
        }
    } else if (strncmp(key, KEY_COUNT, sizeof(KEY_COUNT)) == 0) {
        charra_rc = parse_yaml_ulong_value(parser_state, &pcr_log->count);
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

static CHARRA_RC verifier_pcr_log_field_handler(
        charra_yaml_parser_state_t* parser_state, const char* const key,
        void* data) {
    CHARRA_RC charra_rc = CHARRA_RC_SUCCESS;
    config_verifier* config = (config_verifier*)data;

    pcr_log_dto pcr_log = {0};

    /* setting the identifier */
    if (strncmp(key, KEY_IMA, sizeof(KEY_IMA)) == 0) {
        memcpy(pcr_log.identifier, KEY_IMA, sizeof(KEY_IMA));
    } else if (strncmp(key, KEY_TCG_BOOT, sizeof(KEY_TCG_BOOT)) == 0) {
        memcpy(pcr_log.identifier, KEY_TCG_BOOT, sizeof(KEY_TCG_BOOT));
    } else {
        charra_rc = CHARRA_RC_ERROR;
        CHARRA_YAML_PARSER_ERROR_LOG_F(
                parser_state->parser, "unknown field '%s'", key);
        return charra_rc;
    }

    /* setting count and start value */
    charra_rc = parse_yaml_mapping(
            parser_state, verifier_pcr_log_request_field_handler, &pcr_log);
    if (charra_rc != CHARRA_RC_SUCCESS) {
        return charra_rc;
    }

    /* adding or overwriting new PCR log value to pcr_logs */
    charra_config_verifier_set_pcr_log(config, &pcr_log);

    return charra_rc;
}

static CHARRA_RC pcr_selection_item_handler(
        charra_yaml_parser_state_t* parser_state __attribute__((unused)),
        const yaml_token_t* const token, size_t index __attribute__((unused)),
        void* data, size_t data_len __attribute__((unused))) {
    CHARRA_RC charra_rc = CHARRA_RC_SUCCESS;
    uint64_t parsed_value = 0;
    bool* pcr_set = (bool*)data;

    if (token->type != YAML_SCALAR_TOKEN) {
        charra_rc = CHARRA_RC_ERROR;
        CHARRA_YAML_TOKEN_ERROR_LOG(*token, "invalid representation");
        return charra_rc;
    }

    if (token->data.scalar.style != YAML_PLAIN_SCALAR_STYLE) {
        charra_rc = CHARRA_RC_ERROR;
        CHARRA_YAML_TOKEN_ERROR_LOG(*token, "invalid number representation");
        return charra_rc;
    }

    const char* const token_value = (char*)token->data.scalar.value;
    charra_rc = parse_ulong(token_value, 0, &parsed_value);
    if (charra_rc != CHARRA_RC_SUCCESS) {
        CHARRA_YAML_TOKEN_ERROR_LOG(*token, "invalid unsigned long value");
        charra_rc = CHARRA_RC_ERROR;
    }
    if (parsed_value >= TPM2_MAX_PCRS) {
        charra_rc = CHARRA_RC_ERROR;
        CHARRA_YAML_TOKEN_ERROR_LOG(*token, "pcr index out of range");
        return charra_rc;
    }

    pcr_set[parsed_value] = true;
    return charra_rc;
}

static CHARRA_RC pcr_selection_parse_bank(
        charra_yaml_parser_state_t* parser_state, config_verifier* config,
        uint8_t bank_index) {
    CHARRA_RC charra_rc = CHARRA_RC_SUCCESS;

    bool pcr_set[TPM2_MAX_PCRS] = {0};
    uint8_t pcrs[TPM2_MAX_PCRS] = {0};
    size_t read_len = 0;
    size_t pcr_len = 0;

    charra_rc = parse_yaml_sequence(parser_state, pcr_selection_item_handler,
            pcr_set, TPM2_MAX_PCRS, &read_len);
    if (charra_rc != CHARRA_RC_SUCCESS) {
        return charra_rc;
    }
    for (int i = 0; i < TPM2_MAX_PCRS; i++) {
        if (!pcr_set[i]) {
            continue;
        }
        pcrs[pcr_len++] = i;
    }
    memcpy(config->tpm_pcr_selection[bank_index], pcrs, TPM2_MAX_PCRS);
    config->tpm_pcr_selection_len[bank_index] = pcr_len;
    return charra_rc;
}

static CHARRA_RC verifier_tpm_pcr_selection_field_handler(
        charra_yaml_parser_state_t* parser_state, const char* const key,
        void* data) {
    CHARRA_RC charra_rc = CHARRA_RC_SUCCESS;
    config_verifier* config = (config_verifier*)data;

    config_verifier_pcr_bank_index pcr_bank_index = VERIFIER_PCR_BANK_UNKNOWN;

    charra_config_verifier_pcr_bank_index_from_str(key, &pcr_bank_index);
    if (pcr_bank_index == VERIFIER_PCR_BANK_UNKNOWN) {
        charra_rc = CHARRA_RC_ERROR;
        CHARRA_YAML_PARSER_ERROR_LOG_F(
                parser_state->parser, "unknown field '%s'", key);
        return charra_rc;
    }

    charra_rc = pcr_selection_parse_bank(parser_state, config, pcr_bank_index);

    return charra_rc;
}

static CHARRA_RC verifier_reference_pcr_file_field_handler(
        charra_yaml_parser_state_t* parser_state, const char* const key,
        void* data) {
    CHARRA_RC charra_rc = CHARRA_RC_SUCCESS;
    config_verifier* config = (config_verifier*)data;

    char string_value[BUFFER_LEN] = {0};

    if (strncmp(key, KEY_PATH, sizeof(KEY_PATH)) == 0) {
        charra_rc = parse_yaml_string_value(parser_state,
                config->reference_pcr_file_path,
                sizeof(config->reference_pcr_file_path));
        if (charra_rc != CHARRA_RC_SUCCESS) {
            return charra_rc;
        }
    } else if (strncmp(key, KEY_FORMAT, sizeof(KEY_FORMAT)) == 0) {
        charra_rc =
                parse_yaml_string_value(parser_state, string_value, BUFFER_LEN);
        if (charra_rc != CHARRA_RC_SUCCESS) {
            return charra_rc;
        }
        charra_config_verifier_reference_pcr_file_format_from_str(
                string_value, &config->reference_pcr_file_format);
        if (config->reference_pcr_file_format ==
                VERIFIER_REFERENCE_PCRP_FILE_FORMAT_UNKNOWN) {
            CHARRA_YAML_PARSER_ERROR_LOG_F(parser_state->parser,
                    "unknown " KEY_REFERENCE_PCR_FILE " format '%s'",
                    string_value);
            return charra_rc;
        }
    } else {
        charra_rc = CHARRA_RC_ERROR;
        CHARRA_YAML_PARSER_ERROR_LOG_F(
                parser_state->parser, "unknown field '%s'", key);
    }

    return charra_rc;
}

static CHARRA_RC verifier_attestation_field_handler(
        charra_yaml_parser_state_t* parser_state, const char* const key,
        void* data) {
    CHARRA_RC charra_rc = CHARRA_RC_SUCCESS;
    config_verifier* config = (config_verifier*)data;

    char string_value[BUFFER_LEN] = {0};
    uint64_t long_value = 0;

    if (strncmp(key, KEY_RESPONSE_TIMEOUT, sizeof(KEY_RESPONSE_TIMEOUT)) == 0) {
        charra_rc = parse_yaml_ulong_value(parser_state, &long_value);
        if (charra_rc != CHARRA_RC_SUCCESS) {
            return charra_rc;
        }
        if (long_value > UINT16_MAX) {
            charra_rc = CHARRA_RC_ERROR;
            CHARRA_YAML_PARSER_ERROR_LOG_F(parser_state->parser,
                    KEY_RESPONSE_TIMEOUT " value %lu is too large", long_value);
            return charra_rc;
        }
        config->attestation_response_timeout = (uint16_t)long_value;
    } else if (strncmp(key, KEY_USE_TPM_FOR_NONCE,
                       sizeof(KEY_USE_TPM_FOR_NONCE)) == 0) {
        charra_rc = parse_yaml_bool_value(
                parser_state, &config->use_tpm_for_random_nonce_generation);
        if (charra_rc != CHARRA_RC_SUCCESS) {
            return charra_rc;
        }
    } else if (strncmp(key, KEY_TPM_SIG_KEY_ID, sizeof KEY_TPM_SIG_KEY_ID) ==
               0) {
        charra_rc = parse_yaml_string_value(parser_state,
                config->tpm_sig_key_id, sizeof(config->tpm_sig_key_id));
        config->tpm2_sig_key_id_len = strlen(config->tpm_sig_key_id);
    } else if (strncmp(key, KEY_TPM_QUOTE_SIG_HASH_ALG,
                       sizeof(KEY_TPM_QUOTE_SIG_HASH_ALG)) == 0) {
        charra_rc =
                parse_yaml_string_value(parser_state, string_value, BUFFER_LEN);
        if (charra_rc != CHARRA_RC_SUCCESS) {
            return charra_rc;
        }
        charra_config_verifier_hash_algorithm_from_str(
                string_value, &config->signature_hash_algorithm);
        if (config->signature_hash_algorithm.mbedtls_hash_algorithm ==
                        MBEDTLS_MD_NONE ||
                config->signature_hash_algorithm.tpm2_hash_algorithm ==
                        TPM2_ALG_ERROR) {
            charra_rc = CHARRA_RC_ERROR;
            CHARRA_YAML_PARSER_ERROR_LOG_F(parser_state->parser,
                    "unknown hash algorithm '%s'", string_value);
            return charra_rc;
        }
    } else if (strncmp(key, KEY_PUBLIC_KEY_PATH, sizeof(KEY_PUBLIC_KEY_PATH)) ==
               0) {
        charra_rc = parse_yaml_string_value(parser_state,
                config->attestation_public_key_path,
                sizeof(config->attestation_public_key_path));
        if (charra_rc != CHARRA_RC_SUCCESS) {
            return charra_rc;
        }
    } else if (strncmp(key, KEY_REFERENCE_PCR_FILE,
                       sizeof(KEY_REFERENCE_PCR_FILE)) == 0) {
        charra_rc = parse_yaml_mapping(
                parser_state, verifier_reference_pcr_file_field_handler, data);
    } else if (strncmp(key, KEY_TPM_PCR_SELECTION,
                       sizeof(KEY_TPM_PCR_SELECTION)) == 0) {
        charra_rc = parse_yaml_mapping(
                parser_state, verifier_tpm_pcr_selection_field_handler, data);
    } else if (strncmp(key, KEY_PCR_LOG, sizeof(KEY_PCR_LOG)) == 0) {
        charra_rc = parse_yaml_mapping(
                parser_state, verifier_pcr_log_field_handler, data);
    } else {
        charra_rc = CHARRA_RC_ERROR;
        CHARRA_YAML_PARSER_ERROR_LOG_F(
                parser_state->parser, "unknown field '%s'", key);
    }
    return charra_rc;
}

static CHARRA_RC verifier_inner_field_handler(
        charra_yaml_parser_state_t* parser_state, const char* const key,
        void* data) {
    CHARRA_RC charra_rc = CHARRA_RC_SUCCESS;
    config_verifier* config = (config_verifier*)data;

    char string_value[BUFFER_LEN] = {0};
    uint64_t long_value = 0;
    if (strncmp(key, KEY_LOCK_CONFIG, sizeof(KEY_LOCK_CONFIG)) == 0) {
        charra_rc = parse_yaml_bool_value(parser_state, &config->lock_config);
        if (charra_rc != CHARRA_RC_SUCCESS) {
            return charra_rc;
        }
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
    } else if (strncmp(key, KEY_TARGET_HOST, sizeof(KEY_TARGET_HOST)) == 0) {
        charra_rc = parse_yaml_string_value(
                parser_state, config->dst_host, sizeof(config->dst_host));
    } else if (strncmp(key, KEY_TARGET_PORT, sizeof(KEY_TARGET_PORT)) == 0) {
        charra_rc = parse_yaml_ulong_value(parser_state, &long_value);
        if (charra_rc != CHARRA_RC_SUCCESS) {
            return charra_rc;
        }
        if (long_value > UINT16_MAX) {
            charra_rc = CHARRA_RC_ERROR;
            CHARRA_YAML_PARSER_ERROR_LOG_F(parser_state->parser,
                    KEY_TARGET_PORT " value %lu is too large", long_value);
        }
        config->dst_port = (uint16_t)long_value;
    } else if (strncmp(key, KEY_COAP, sizeof(KEY_COAP)) == 0) {
        charra_rc = parse_yaml_mapping(
                parser_state, verifier_coap_field_handler, data);
    } else if (strncmp(key, KEY_ATTESTATION, sizeof(KEY_ATTESTATION)) == 0) {
        charra_rc = parse_yaml_mapping(
                parser_state, verifier_attestation_field_handler, data);
    } else {
        charra_rc = CHARRA_RC_ERROR;
        CHARRA_YAML_PARSER_ERROR_LOG_F(
                parser_state->parser, "unknown field '%s'", key);
    }

    return charra_rc;
}

static CHARRA_RC verifier_field_handler(
        charra_yaml_parser_state_t* parser_state, const char* const key,
        void* data) {
    CHARRA_RC charra_rc = CHARRA_RC_SUCCESS;
    if (strncmp(key, CONFIG_KEY, sizeof(CONFIG_KEY)) == 0) {
        return parse_yaml_mapping(
                parser_state, verifier_inner_field_handler, data);
    } else {
        charra_rc = CHARRA_RC_ERROR;
        CHARRA_YAML_PARSER_ERROR_LOG_F(parser_state->parser,
                "invalid mapping '%s' use '" CONFIG_KEY "' instead", key);
    }
    return charra_rc;
}

CHARRA_RC load_verifier_yaml_config_file(
        const char* const path, config_verifier* const config) {
    return parse_yaml_file(path, verifier_field_handler, config);
}
