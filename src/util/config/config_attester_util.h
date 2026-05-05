/* SPDX-License-Identifier: BSD-3-Clause */
/*****************************************************************************
 * Copyright 2025, Fraunhofer Institute for Secure Information Technology SIT.
 * All rights reserved.
 ****************************************************************************/

/**
 * @file config_attester_util.h
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

#ifndef CONFIG_ATTESTER_UTIL_H
#define CONFIG_ATTESTER_UTIL_H

#include <stdbool.h>
#include <stdint.h>

#include <coap3/coap.h>
#include <tss2/tss2_esys.h>

#include "../../common/charra_error.h"
#include "../../common/charra_log.h"
#include "cli/cli_options.h"

/**
 * An enum containing the possible formats of the attestation key.
 */
typedef enum {
    ATTESTER_ATTESTATION_KEY_FORMAT_FILE = 'f',
    ATTESTER_ATTESTATION_KEY_FORMAT_HANDLE = 'h',
    ATTESTER_ATTESTATION_KEY_FORMAT_UNKNOWN = 0,
} config_attester_attestation_key_format_e;

/**
 * A structure holding all config parameters.
 */
typedef struct {
    bool lock_config;
    char listen_ip[16];
    uint16_t port;
    charra_log_t charra_log_level;
    coap_log_t coap_log_level;
    bool use_dtls_psk;
    char dtls_psk_hint[256];
    char dtls_psk_key[256];
    bool use_dtls_rpk;
    char dtls_rpk_private_key_path[1024];
    char dtls_rpk_public_key_path[1024];
    bool dtls_rpk_verify_peer_public_key;
    char dtls_rpk_peer_public_key_path[1024];
    config_attester_attestation_key_format_e attestation_key_format;
    union {
        char ctx_path[1024];
        ESYS_TR tpm2_handle;
    } attestation_key;
    TPM2_ALG_ID signature_scheme;
    TPM2_ALG_ID hash_algorithm;
    char ima_log_path[1024];
    char tcg_boot_log_path[1024];
} config_attester;

/**
 *  @brief prints the config values.
 *
 * @param config A struct holding the config values.
 */
void trace_log_attester_config(const config_attester* const config);

/**
 *  @brief parses the system and user config file and afterwards the command
 * line interface arguments.
 *
 * @param argc The number of arguments which were given to the CLI.
 * @param argv The arguments which were given to the CLI.
 * @param config A struct holding the new config values.
 * @return  A cli_option_code indicating if an error, further processing
 *  or an immediate exit is desired.
 */
cli_option_code load_attester_config(
        int argc, char* argv[], config_attester* const config);

/**
 *  @brief parses the string as a attestation key format.
 *
 * @param format the string holding the format.
 * @param attestation_key_format the attestation key format to be set.
 */
void charra_config_attester_attestation_key_format_from_str(
        const char* const format,
        config_attester_attestation_key_format_e* const attestation_key_format);

#endif  // CONFIG_ATTESTER_UTIL_H
