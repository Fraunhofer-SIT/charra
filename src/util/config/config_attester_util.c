/* SPDX-License-Identifier: BSD-3-Clause */
/*****************************************************************************
 * Copyright 2025, Fraunhofer Institute for Secure Information Technology SIT.
 * All rights reserved.
 ****************************************************************************/

/**
 * @file config_attester_util.c
 * @author Markus Horn (markus.horn@sit.fraunhofer.de)
 * @brief Provides config parsing for attester.
 * @version 0.1
 * @date 2025-05-11
 *
 * @copyright Copyright 2024, Fraunhofer Institute for Secure Information
 * Technology SIT. All rights reserved.
 *
 * @license BSD 3-Clause "New" or "Revised" License (SPDX-License-Identifier:
 * BSD-3-Clause).
 */

#include "config_attester_util.h"

#include <string.h>
#include <tss2/tss2_tpm2_types.h>

#include "../coap_util.h"
#include "../io_util.h"
#include "./cli/cli_util_attester.h"
#include "./file/config_attester_file_util.h"
#include "cli/cli_options.h"

/* config file paths */
#define SYSTEM_CONFIG_ATTESTER_FILE_PATH "/etc/charra/attester-config.yaml"

/* default values */

/* logging */
static coap_log_t coap_log_level = LOG_INFO;
static charra_log_t charra_log_level = CHARRA_LOG_INFO;

/* config */
#define ATTESTER_DEFAULT_LISTEN_IP "0.0.0.0"
#define ATTESTER_DEFAULT_PORT COAP_DEFAULT_PORT  // default port 5683

/* TPM2-Quote */
#define ATTESTER_DEFAULT_SIGNATURE_SCHEME TPM2_ALG_NULL
#define ATTESTER_DEFAULT_HASH_ALGORITHM TPM2_ALG_SHA256

// for DTLS-PSK
#define ATTESTER_DEFAULT_USE_DTLS_PSK false
#define ATTESTER_DEFAULT_DTLS_PSK_KEY "Charra DTLS Key"
#define ATTESTER_DEFAULT_DTLS_PSK_HINT "Charra Attester"

// for DTLS-RPK
#define ATTESTER_DEFAULT_USE_DTLS_RPK false
#define ATTESTER_DEFAULT_DTLS_RPK_PRIVATE_KEY_PATH "keys/attester.der"
#define ATTESTER_DEFAULT_DTLS_RPK_PUBLIC_KEY_PATH "keys/attester.pub.der"
#define ATTESTER_DEFAULT_DTLS_RPK_PEER_PUBLIC_KEY_PATH "keys/verifier.pub.der"
#define ATTESTER_DTLS_RPK_VERIFY_PUBLIC_KEY true

/* Attestation key format strings */
#define ATTESTER_ATTESTATION_KEY_FORMAT_CONTEXT_STR "context"
#define ATTESTER_ATTESTATION_KEY_FORMAT_HANDLE_STR "handle"

void trace_log_attester_config(const config_attester* const config) {
    charra_log_trace("=== Attester configuration ===");

    charra_log_trace(
            "Lock config : %s", config->lock_config ? "true" : "false");

    // Network settings
    charra_log_trace("Listen IP: %s", config->listen_ip);
    charra_log_trace("Port: %u", config->port);

    // Log levels
    charra_log_trace("CHARRA log level: %d", config->charra_log_level);
    charra_log_trace("CoAP log level: %d", config->coap_log_level);

    // DTLS PSK settings
    charra_log_trace(
            "Use DTLS PSK: %s", config->use_dtls_psk ? "true" : "false");
    charra_log_trace("DTLS PSK hint: %s", config->dtls_psk_hint);
    charra_log_trace("DTLS PSK key: %s", config->dtls_psk_key);

    // DTLS RPK settings
    charra_log_trace(
            "Use DTLS RPK: %s", config->use_dtls_rpk ? "true" : "false");
    charra_log_trace(
            "DTLS RPK private key path: %s", config->dtls_rpk_private_key_path);
    charra_log_trace(
            "DTLS RPK public key path: %s", config->dtls_rpk_public_key_path);
    charra_log_trace("DTLS RPK verify peer public key: %s",
            config->dtls_rpk_verify_peer_public_key ? "true" : "false");
    charra_log_trace("DTLS RPK peer public key path: %s",
            config->dtls_rpk_peer_public_key_path);

    // Attestation key settings
    charra_log_trace("Attestation key format: ");
    switch (config->attestation_key_format) {
    case ATTESTER_ATTESTATION_KEY_FORMAT_FILE:
        charra_log_trace("File (%c)", ATTESTER_ATTESTATION_KEY_FORMAT_FILE);
        charra_log_trace("Attestation key context path: %s",
                config->attestation_key.ctx_path);
        break;
    case ATTESTER_ATTESTATION_KEY_FORMAT_HANDLE:
        charra_log_trace(
                "TPM Handle (%c)", ATTESTER_ATTESTATION_KEY_FORMAT_HANDLE);
        charra_log_trace("Attestation key TPM handle: 0x%x",
                config->attestation_key.tpm2_handle);
        break;
    default:
        charra_log_trace("Unknown (%c)", config->attestation_key_format);
        break;
    }

    // TPM2-quote options
    charra_log_trace("Signature scheme: 0x%x", config->signature_scheme);
    charra_log_trace("Hash algorithm: 0x%x", config->hash_algorithm);

    // Log paths
    charra_log_trace("IMA log path: %s", config->ima_log_path);
    charra_log_trace("TCG boot log path: %s", config->tcg_boot_log_path);

    charra_log_trace("=== End of attester configuration ===");
}

/**
 * @brief Checks whether all required options have been specified.
 *
 * @param config the config struct to check
 */
static bool charra_check_required_options(const config_attester* const config) {
    bool rc = true;
    /* check if attestation key file was specified */
    bool set_attestation_key_path =
            config->attestation_key_format ==
                    ATTESTER_ATTESTATION_KEY_FORMAT_FILE &&
            config->attestation_key.ctx_path[0] != '\0';
    bool set_attestation_key_handle =
            config->attestation_key_format ==
                    ATTESTER_ATTESTATION_KEY_FORMAT_HANDLE &&
            config->attestation_key.tpm2_handle != 0;
    bool set_attestation_key =
            set_attestation_key_path || set_attestation_key_handle;
    if (!set_attestation_key) {
        charra_log_error("Missing argument: no attestation key");
        rc = false;
    }
    return rc;
}

static void init_config(config_attester* const config) {
    config->lock_config = false;
    strncpy(config->listen_ip, ATTESTER_DEFAULT_LISTEN_IP,
            sizeof(config->listen_ip));
    config->port = ATTESTER_DEFAULT_PORT;
    config->charra_log_level = charra_log_level;
    config->coap_log_level = coap_log_level;
    config->signature_scheme = ATTESTER_DEFAULT_SIGNATURE_SCHEME;
    config->hash_algorithm = ATTESTER_DEFAULT_HASH_ALGORITHM;
    config->use_dtls_psk = ATTESTER_DEFAULT_USE_DTLS_PSK;
    strncpy(config->dtls_psk_hint, ATTESTER_DEFAULT_DTLS_PSK_HINT,
            sizeof(config->dtls_psk_hint));
    strncpy(config->dtls_psk_key, ATTESTER_DEFAULT_DTLS_PSK_KEY,
            sizeof(config->dtls_psk_key));
    config->use_dtls_rpk = ATTESTER_DEFAULT_USE_DTLS_RPK;
    strncpy(config->dtls_rpk_private_key_path,
            ATTESTER_DEFAULT_DTLS_RPK_PRIVATE_KEY_PATH,
            sizeof(config->dtls_rpk_private_key_path));
    strncpy(config->dtls_rpk_public_key_path,
            ATTESTER_DEFAULT_DTLS_RPK_PUBLIC_KEY_PATH,
            sizeof(config->dtls_rpk_public_key_path));
    strncpy(config->dtls_rpk_peer_public_key_path,
            ATTESTER_DEFAULT_DTLS_RPK_PEER_PUBLIC_KEY_PATH,
            sizeof(config->dtls_rpk_peer_public_key_path));
    config->dtls_rpk_verify_peer_public_key =
            ATTESTER_DTLS_RPK_VERIFY_PUBLIC_KEY;
}

static void load_config_file(const char* const path, config_attester* config) {
    CHARRA_RC charra_rc = CHARRA_RC_SUCCESS;
    config_attester clone_config = {0};

    charra_rc = charra_io_file_exists(path);
    if (charra_rc != CHARRA_RC_SUCCESS) {
        charra_log_debug("Config file does not exist: %s", path);
        return;
    }

    memcpy(&clone_config, config, sizeof(config_attester));

    charra_rc = load_attester_yaml_config_file(path, &clone_config);
    if (charra_rc != CHARRA_RC_SUCCESS) {
        charra_log_debug(
                "Something went wrong with loading the config file: %s", path);
        return;
    }
    memcpy(config, &clone_config, sizeof(config_attester));
}

cli_option_code load_attester_config(
        int argc, char* argv[], config_attester* const config) {
    // loading config in this order
    // 1. hardcoded config
    // 2. /etc/charra/attester-config.yaml
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
    load_config_file(SYSTEM_CONFIG_ATTESTER_FILE_PATH, config);
    if (config->lock_config) {
        charra_log_info(
                "Attester config is locked. No further changes are allowed.");
        goto locked_arguments;
    }

locked_arguments:
    // if locked, check only for --help
    rc = charra_parse_command_line_attester_arguments(argc, argv, config);

    trace_log_attester_config(config);

    if (rc != cli_option_code_continue) {
        return rc;
    }

    if (!charra_check_required_options(config)) {
        rc = cli_option_code_error;
        charra_cli_util_attester_print_help_message();
    }

    return rc;
}

void charra_config_attester_attestation_key_format_from_str(
        const char* const format,
        config_attester_attestation_key_format_e* const
                attestation_key_format) {
    if (strncmp(format, ATTESTER_ATTESTATION_KEY_FORMAT_CONTEXT_STR,
                sizeof(ATTESTER_ATTESTATION_KEY_FORMAT_CONTEXT_STR)) == 0) {
        *attestation_key_format = ATTESTER_ATTESTATION_KEY_FORMAT_FILE;
    } else if (strncmp(format, ATTESTER_ATTESTATION_KEY_FORMAT_HANDLE_STR,
                       sizeof(ATTESTER_ATTESTATION_KEY_FORMAT_HANDLE_STR)) ==
               0) {
        *attestation_key_format = ATTESTER_ATTESTATION_KEY_FORMAT_HANDLE;
    } else {
        *attestation_key_format = ATTESTER_ATTESTATION_KEY_FORMAT_UNKNOWN;
    }
}
