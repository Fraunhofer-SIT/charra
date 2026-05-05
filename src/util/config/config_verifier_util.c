/* SPDX-License-Identifier: BSD-3-Clause */
/*****************************************************************************
 * Copyright 2025, Fraunhofer Institute for Secure Information Technology SIT.
 * All rights reserved.
 ****************************************************************************/

/**
 * @file config_verifier_util.c
 * @author Markus Horn (markus.horn@sit.fraunhofer.de)
 * @brief Provides config parsing for verifier.
 * @version 0.1
 * @date 2025-05-11
 *
 * @copyright Copyright 2024, Fraunhofer Institute for Secure Information
 * Technology SIT. All rights reserved.
 *
 * @license BSD 3-Clause "New" or "Revised" License (SPDX-License-Identifier:
 * BSD-3-Clause).
 */

#include "config_verifier_util.h"

#include <coap3/coap_pdu.h>
#include <mbedtls/md.h>
#include <string.h>

#include "../coap_util.h"
#include "../io_util.h"
#include "./cli/cli_util_verifier.h"
#include "./file/config_verifier_file_util.h"
#include "cli/cli_options.h"

/* config file paths */
#define SYSTEM_CONFIG_VERIFIER_FILE_PATH "/etc/charra/verifier-config.yaml"

/* default values */

/* logging */
static coap_log_t coap_log_level = LOG_INFO;
static charra_log_t charra_log_level = CHARRA_LOG_INFO;

/* config */
#define COAP_IO_PROCESS_TIME_MS 2000  // CoAP IO process time in milliseconds
#define VERIFIER_DEFAULT_USE_TPM_FOR_RANDOM_NONCE_GENERATION false

#define TPM_SIG_KEY_ID_LEN 14
#define TPM_SIG_KEY_ID "PK.RSA.default"

/* config */
#define VERIFIER_DEFAULT_DST_HOST "127.0.0.1"  // 15 characters for IPv4 plus \0
#define VERIFIER_DEFAULT_DST_PORT COAP_DEFAULT_PORT  // default port

// clang-format off
// TODO: Implement integration of all PCR banks
static const uint8_t
        VERIFIER_DEFAULT_TPM_PCR_SELECTION[TPM2_PCR_BANK_COUNT][TPM2_MAX_PCRS] = {
                /* sha1 */
                {0},
                /* sha256 */
                {0, 1, 2, 3, 4,5, 6, 7,10},
                /* sha384 */
                {0},
                /* sha512 */
                {0}};
static const uint32_t
        VERIFIER_DEFAULT_TPM_PCR_SELECTION_LEN[TPM2_PCR_BANK_COUNT] = {
                0,   // sha1
                9,   // sha256
                0,   // sha384
                0};  // sha512
// clang-format on

// timeout when waiting for attestation answer in seconds
#define VERIFIER_DEFAULT_ATTESTATION_RESPONSE_TIMEOUT 30

#define VERIFIER_DEFAULT_SIGNATURE_HASH_ALGORITHM                              \
    (config_verifier_signature_hash_algorithm){                                \
            .mbedtls_hash_algorithm = MBEDTLS_MD_SHA256,                       \
            .tpm2_hash_algorithm = TPM2_ALG_SHA256};

// for DTLS-PSK
#define VERIFIER_DEFAULT_USE_DTLS_PSK false
#define VERIFIER_DEFAULT_DTLS_PSK_KEY "Charra DTLS Key"
#define VERIFIER_DEFAULT_DTLS_PSK_IDENTITY "Charra Verifier"

// for DTLS-RPK
#define VERIFIER_DEFAULT_USE_DTLS_RPK false
#define VERIFIER_DEFAULT_DTLS_RPK_PRIVATE_KEY_PATH "keys/verifier.der"
#define VERIFIER_DEFAULT_DTLS_RPK_PUBLIC_KEY_PATH "keys/verifier.pub.der"
#define VERIFIER_DEFAULT_DTLS_RPK_PEER_PUBLIC_KEY_PATH "keys/attester.pub.der"
#define VERIFIER_DEFAULT_DTLS_RPK_VERIFY_PEER_PUBLIC_KEY true

/* hash algorithm strings */
#define VERIFIER_SHA1_STR "sha1"
#define VERIFIER_SHA256_STR "sha256"
#define VERIFIER_SHA384_STR "sha384"
#define VERIFIER_SHA512_STR "sha512"

/* reference PCR file format strings */
#define VERIFIER_REFERENCE_PCR_FILE_FORMAT_YAML_STR "yaml"

void trace_log_verifier_config(const config_verifier* config) {
    charra_log_trace("=== Verifier configuration ===");

    charra_log_trace(
            "Lock config : %s", config->lock_config ? "true" : "false");

    // Network settings
    charra_log_trace("Destination host: %s", config->dst_host);
    charra_log_trace("Destination port: %u", config->dst_port);

    // Log levels
    charra_log_trace("CHARRA log level: %d", config->charra_log_level);
    charra_log_trace("CoAP log level: %d", config->coap_log_level);

    // IO process time
    charra_log_trace("CoAP IO process time: %u ms", config->io_process_time_ms);
    charra_log_trace("Use TPM for random nonce generation: %s",
            config->use_tpm_for_random_nonce_generation ? "true" : "false");
    charra_log_trace(
            "TPM signature key ID length: %u", config->tpm2_sig_key_id_len);
    charra_log_trace("TPM signature key ID: %s", config->tpm_sig_key_id);

    // DTLS PSK settings
    charra_log_trace(
            "Use DTLS PSK: %s", config->use_dtls_psk ? "true" : "false");
    charra_log_trace("DTLS PSK key: %s", config->dtls_psk_key);
    charra_log_trace("DTLS PSK identity: %s", config->dtls_psk_identity);

    // DTLS RPK settings
    charra_log_trace(
            "Use DTLS RPK: %s", config->use_dtls_rpk ? "true" : "false");
    charra_log_trace(
            "DTLS RPK private key path: %s", config->dtls_rpk_private_key_path);
    charra_log_trace(
            "DTLS RPK public key path: %s", config->dtls_rpk_public_key_path);
    charra_log_trace("DTLS RPK verify peer public key: %s ",
            config->dtls_rpk_verify_peer_public_key ? "true" : "false");
    charra_log_trace("DTLS RPK peer public key path: %s",
            config->dtls_rpk_peer_public_key_path);

    // Attestation settings
    charra_log_trace("Attestation response timeout: %u",
            config->attestation_response_timeout);
    charra_log_trace("Signature hash algorithm - MbedTLS: %d, TPM2: 0x%x",
            config->signature_hash_algorithm.mbedtls_hash_algorithm,
            config->signature_hash_algorithm.tpm2_hash_algorithm);
    charra_log_trace("Attestation public key path: %s",
            config->attestation_public_key_path);

    // PCR settings
    charra_log_trace(
            "Reference PCR file format: %c", config->reference_pcr_file_format);
    charra_log_trace(
            "Reference PCR file path: %s", config->reference_pcr_file_path);

    // PCR selection
    charra_log_trace("TPM PCR selection:");
    for (int bank = 0; bank < TPM2_PCR_BANK_COUNT; bank++) {
        charra_log_trace("  Bank %d (len=%u): ", bank,
                config->tpm_pcr_selection_len[bank]);
        if (config->tpm_pcr_selection_len[bank] == 0) {
            continue;
        }
        charra_log_log_raw(CHARRA_LOG_TRACE,
                "                                            "
                "                     ");
        for (int i = 0; i < config->tpm_pcr_selection_len[bank]; i++) {
            charra_log_log_raw(CHARRA_LOG_TRACE, "%u ",
                    config->tpm_pcr_selection[bank][i]);
        }
        charra_log_log_raw(CHARRA_LOG_TRACE, "\n");
    }

    // PCR logs
    charra_log_trace("PCR log count: %u", config->pcr_log_len);
    for (int i = 0; i < config->pcr_log_len; i++) {
        charra_log_trace("  PCR Log %d:", i);
        charra_log_trace("    identifier: %s", config->pcr_logs[i].identifier);
        charra_log_trace("    start: %lu", config->pcr_logs[i].start);
        charra_log_trace("    count: %lu", config->pcr_logs[i].count);
    }

    charra_log_trace("=== End of verifier configuration ===");
}

/**
 * @brief Checks whether all required options have been specified.
 *
 * @param variables the cli config variables
 */
static bool charra_check_required_options(const config_verifier* const config) {
    bool rc = true;
    /* check if PCR reference file was specified */
    if (config->reference_pcr_file_format !=
                    VERIFIER_REFERENCE_PCRP_FILE_FORMAT_YAML ||
            config->reference_pcr_file_path[0] == '\0') {
        charra_log_error("Missing argument: no PCR reference file");
        rc = false;
    }
    /* check if attestation-public-key file was specified */
    if (config->attestation_public_key_path[0] == '\0') {
        charra_log_error("Missing argument: no attestation public key file");
        rc = false;
    }
    return rc;
}

static void init_config(config_verifier* const config) {
    config->lock_config = false;
    strncpy(config->dst_host, VERIFIER_DEFAULT_DST_HOST,
            sizeof(config->dst_host));
    config->dst_port = VERIFIER_DEFAULT_DST_PORT;
    config->charra_log_level = charra_log_level;
    config->coap_log_level = coap_log_level;
    config->io_process_time_ms = COAP_IO_PROCESS_TIME_MS;
    config->use_tpm_for_random_nonce_generation =
            VERIFIER_DEFAULT_USE_TPM_FOR_RANDOM_NONCE_GENERATION;
    config->tpm2_sig_key_id_len = TPM_SIG_KEY_ID_LEN;
    strncpy(config->tpm_sig_key_id, TPM_SIG_KEY_ID,
            sizeof(config->tpm_sig_key_id));
    config->use_dtls_psk = VERIFIER_DEFAULT_USE_DTLS_PSK;
    strncpy(config->dtls_psk_key, VERIFIER_DEFAULT_DTLS_PSK_KEY,
            sizeof(config->dtls_psk_key));
    strncpy(config->dtls_psk_identity, VERIFIER_DEFAULT_DTLS_PSK_IDENTITY,
            sizeof(config->dtls_psk_identity));
    config->use_dtls_rpk = VERIFIER_DEFAULT_USE_DTLS_RPK;
    strncpy(config->dtls_rpk_private_key_path,
            VERIFIER_DEFAULT_DTLS_RPK_PRIVATE_KEY_PATH,
            sizeof(config->dtls_rpk_private_key_path));
    strncpy(config->dtls_rpk_public_key_path,
            VERIFIER_DEFAULT_DTLS_RPK_PUBLIC_KEY_PATH,
            sizeof(config->dtls_rpk_public_key_path));
    config->dtls_rpk_verify_peer_public_key =
            VERIFIER_DEFAULT_DTLS_RPK_VERIFY_PEER_PUBLIC_KEY;
    strncpy(config->dtls_rpk_peer_public_key_path,
            VERIFIER_DEFAULT_DTLS_RPK_PEER_PUBLIC_KEY_PATH,
            sizeof(config->dtls_rpk_peer_public_key_path));
    config->attestation_response_timeout =
            VERIFIER_DEFAULT_ATTESTATION_RESPONSE_TIMEOUT;
    config->signature_hash_algorithm =
            VERIFIER_DEFAULT_SIGNATURE_HASH_ALGORITHM;
    memcpy(config->tpm_pcr_selection_len,
            VERIFIER_DEFAULT_TPM_PCR_SELECTION_LEN,
            sizeof(VERIFIER_DEFAULT_TPM_PCR_SELECTION_LEN));
    memcpy(config->tpm_pcr_selection, VERIFIER_DEFAULT_TPM_PCR_SELECTION,
            sizeof(VERIFIER_DEFAULT_TPM_PCR_SELECTION));
    trace_log_verifier_config(config);
}

static void load_config_file(
        const char* const path, config_verifier* const config) {
    CHARRA_RC charra_rc = CHARRA_RC_SUCCESS;
    config_verifier clone_config = {0};

    charra_rc = charra_io_file_exists(path);
    if (charra_rc != CHARRA_RC_SUCCESS) {
        charra_log_debug("Config file does not exist: %s", path);
        return;
    }

    memcpy(&clone_config, config, sizeof(config_verifier));

    charra_rc = load_verifier_yaml_config_file(path, &clone_config);
    if (charra_rc != CHARRA_RC_SUCCESS) {
        charra_log_debug(
                "Something went wrong with loading the config file: %s", path);
        return;
    }
    memcpy(config, &clone_config, sizeof(config_verifier));
}

cli_option_code load_verifier_config(
        int argc, char* argv[], config_verifier* const config) {
    // loading config in this order
    // 1. hardcoded config
    // 2. /etc/charra/verifier-config.yaml
    // 3. --config
    // 4. cli
    cli_option_code rc = cli_option_code_continue;

    /* check environment variables */
    charra_log_level_from_str(
            (const char*)getenv("LOG_LEVEL_CHARRA"), &charra_log_level);
    charra_coap_log_level_from_str(
            (const char*)getenv("LOG_LEVEL_COAP"), &coap_log_level);

    // hardcoded config
    init_config(config);

    // system config
    load_config_file(SYSTEM_CONFIG_VERIFIER_FILE_PATH, config);
    if (config->lock_config) {
        charra_log_info(
                "Verifier config is locked. No further changes are allowed.");
        goto locked_arguments;
    }

locked_arguments:
    // if locked, check only for --help
    rc = charra_parse_command_line_verifier_arguments(argc, argv, config);

    trace_log_verifier_config(config);

    if (rc != cli_option_code_continue) {
        return rc;
    }

    if (!charra_check_required_options(config)) {
        rc = cli_option_code_error;
        charra_cli_util_verifier_print_help_message();
    }

    return rc;
}

void charra_config_verifier_pcr_bank_index_from_str(const char* const pcr_bank,
        config_verifier_pcr_bank_index* const pcr_bank_index) {
    if (strncmp(pcr_bank, VERIFIER_SHA1_STR, sizeof(VERIFIER_SHA1_STR)) == 0) {
        *pcr_bank_index = VERIFIER_PCR_BANK_SHA1;
    } else if (strncmp(pcr_bank, VERIFIER_SHA256_STR,
                       sizeof(VERIFIER_SHA256_STR)) == 0) {
        *pcr_bank_index = VERIFIER_PCR_BANK_SHA256;
    } else if (strncmp(pcr_bank, VERIFIER_SHA384_STR,
                       sizeof(VERIFIER_SHA384_STR)) == 0) {
        *pcr_bank_index = VERIFIER_PCR_BANK_SHA384;
    } else if (strncmp(pcr_bank, VERIFIER_SHA512_STR,
                       sizeof(VERIFIER_SHA512_STR)) == 0) {
        *pcr_bank_index = VERIFIER_PCR_BANK_SHA512;
    } else {
        *pcr_bank_index = VERIFIER_PCR_BANK_UNKNOWN;
    }
}

void charra_config_verifier_hash_algorithm_from_str(const char* const hash,
        config_verifier_signature_hash_algorithm* const hash_algo) {
    if (strncmp(hash, VERIFIER_SHA1_STR, sizeof(VERIFIER_SHA1_STR)) == 0) {
        hash_algo->mbedtls_hash_algorithm = MBEDTLS_MD_SHA1;
        hash_algo->tpm2_hash_algorithm = TPM2_ALG_SHA1;
    } else if (strncmp(hash, VERIFIER_SHA256_STR,
                       sizeof(VERIFIER_SHA256_STR)) == 0) {
        hash_algo->mbedtls_hash_algorithm = MBEDTLS_MD_SHA256;
        hash_algo->tpm2_hash_algorithm = TPM2_ALG_SHA256;
    } else if (strncmp(hash, VERIFIER_SHA384_STR,
                       sizeof(VERIFIER_SHA384_STR)) == 0) {
        hash_algo->mbedtls_hash_algorithm = MBEDTLS_MD_SHA384;
        hash_algo->tpm2_hash_algorithm = TPM2_ALG_SHA384;
    } else if (strncmp(hash, VERIFIER_SHA512_STR,
                       sizeof(VERIFIER_SHA512_STR)) == 0) {
        hash_algo->mbedtls_hash_algorithm = MBEDTLS_MD_SHA512;
        hash_algo->tpm2_hash_algorithm = TPM2_ALG_SHA512;
    } else {
        /* This algorithms are not supported by mbedTLS:
        sm3_256, sha3_256, sha3_384, sha3_512 */
        hash_algo->mbedtls_hash_algorithm = MBEDTLS_MD_NONE;
        hash_algo->tpm2_hash_algorithm = TPM2_ALG_ERROR;
    }
}

void charra_config_verifier_reference_pcr_file_format_from_str(
        const char* const format,
        config_verifier_reference_pcr_file_format_e* const
                reference_pcr_file_format) {
    if (strncmp(format, VERIFIER_REFERENCE_PCR_FILE_FORMAT_YAML_STR,
                sizeof(VERIFIER_REFERENCE_PCR_FILE_FORMAT_YAML_STR)) == 0) {
        *reference_pcr_file_format = VERIFIER_REFERENCE_PCRP_FILE_FORMAT_YAML;
    } else {
        *reference_pcr_file_format =
                VERIFIER_REFERENCE_PCRP_FILE_FORMAT_UNKNOWN;
    }
}

void charra_config_verifier_set_pcr_log(
        config_verifier* const config, const pcr_log_dto* const pcr_log) {
    pcr_log_dto* const pcr_logs = config->pcr_logs;
    uint8_t* pcr_log_len = &config->pcr_log_len;

    for (uint8_t index = 0; index < SUPPORTED_PCR_LOGS_COUNT; ++index) {
        /* identifier is new */
        if (pcr_logs[index].identifier[0] == '\0') {
            *pcr_log_len = (*pcr_log_len) + 1;
            memcpy(&pcr_logs[index], pcr_log, sizeof(pcr_log_dto));
            break;
        }
        /* identifier is already in the list and should be overridden */
        if (strncmp(pcr_log->identifier, pcr_logs[index].identifier,
                    CHARRA_TAP_PCR_LOG_IDENTIFIER_MAXLEN) == 0) {
            memcpy(&pcr_logs[index], pcr_log, sizeof(pcr_log_dto));
            break;
        }
    }
}
