/* SPDX-License-Identifier: BSD-3-Clause */
/*****************************************************************************
 * Copyright 2025, Fraunhofer Institute for Secure Information Technology SIT.
 * All rights reserved.
 ****************************************************************************/

/**
 * @file config_verifier_util.h
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

#ifndef CONFIG_VERIFIER_UTIL_H
#define CONFIG_VERIFIER_UTIL_H

#include <stdbool.h>
#include <stdint.h>

#include <coap3/coap.h>
#include <mbedtls/md.h>
#include <tss2/tss2_tpm2_types.h>

#include "../../common/charra_log.h"
#include "../../core/charra_tap/charra_tap_dto.h"
#include "../crypto_util.h"
#include "cli/cli_options.h"

typedef struct {
    mbedtls_md_type_t mbedtls_hash_algorithm;
    TPM2_ALG_ID tpm2_hash_algorithm;
} config_verifier_signature_hash_algorithm;

typedef enum {
    VERIFIER_REFERENCE_PCRP_FILE_FORMAT_UNKNOWN = 0,
    VERIFIER_REFERENCE_PCRP_FILE_FORMAT_YAML = 'y',
} config_verifier_reference_pcr_file_format_e;

/**
 * A structure holding all config parameters.
 */
typedef struct {
    bool lock_config;
    char dst_host[16];  // 15 characters for IPv4 plus \0
    uint16_t dst_port;
    charra_log_t charra_log_level;
    coap_log_t coap_log_level;
    uint32_t io_process_time_ms;
    bool use_dtls_psk;
    char dtls_psk_key[256];
    char dtls_psk_identity[128];
    bool use_dtls_rpk;
    char dtls_rpk_private_key_path[1024];
    char dtls_rpk_public_key_path[1024];
    bool dtls_rpk_verify_peer_public_key;
    char dtls_rpk_peer_public_key_path[1024];
    uint16_t attestation_response_timeout;
    bool use_tpm_for_random_nonce_generation;
    uint8_t tpm2_sig_key_id_len;
    char tpm_sig_key_id[64];
    config_verifier_signature_hash_algorithm signature_hash_algorithm;
    char attestation_public_key_path[1024];
    config_verifier_reference_pcr_file_format_e reference_pcr_file_format;
    char reference_pcr_file_path[1024];
    uint8_t tpm_pcr_selection_len[TPM2_PCR_BANK_COUNT];
    charra_tpm_pcr_selection tpm_pcr_selection;
    uint8_t pcr_log_len;
    pcr_log_dto pcr_logs[SUPPORTED_PCR_LOGS_COUNT];
} config_verifier;

void trace_log_verifier_config(const config_verifier* const config);

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
cli_option_code load_verifier_config(
        int argc, char* argv[], config_verifier* const config);

/**
 *  @brief parses the string as a hash algorithm.
 *
 * @param hash the string holding the hash algorithm.
 * @param hash_algo the hash algorithm to be set.
 */
void charra_config_verifier_hash_algorithm_from_str(const char* const hash,
        config_verifier_signature_hash_algorithm* const hash_algo);

/**
 *  @brief parses the string as a reference PCR file format.
 *
 * @param format the string holding the format.
 * @param reference_pcr_file_format the reference PCR file format to be set.
 */
void charra_config_verifier_reference_pcr_file_format_from_str(
        const char* const format,
        config_verifier_reference_pcr_file_format_e* const
                reference_pcr_file_format);

/**
 *  @brief sets the PCR log in the config.
 *
 * @param config The config which holds all PCR logs.
 * @param pcr_log The PCR log to be set.
 */
void charra_config_verifier_set_pcr_log(
        config_verifier* const config, const pcr_log_dto* const pcr_log);

#endif  // CONFIG_VERIFIER_UTIL_H
