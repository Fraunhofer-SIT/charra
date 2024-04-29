/* SPDX-License-Identifier: BSD-3-Clause */
/*****************************************************************************
 * Copyright 2024, Fraunhofer Institute for Secure Information Technology SIT.
 * All rights reserved.
 ****************************************************************************/

/**
 * @file cli_util_attester.c
 * @author Markus Horn (markus.horn@sit.fraunhofer.de)
 * @author Dominik Lorych(dominik.lorych @sit.fraunhofer.de)
 * @brief Provides command line parsing for verifier & attester.
 * @version 0.1
 * @date 2024-04-22
 *
 * @copyright Copyright 2024, Fraunhofer Institute for Secure Information
 * Technology SIT. All rights reserved.
 *
 * @license BSD 3-Clause "New" or "Revised" License (SPDX-License-Identifier:
 * BSD-3-Clause).
 */

#include "cli_util_attester.h"
#include "../io_util.h"
#include "cli_util_common.h"
#include <bits/getopt_core.h>
#include <stdint.h>
#include <stdlib.h>

#define LOG_NAME "attester"
#define ATTESTER_SHORT_OPTIONS "vl:c:pk:h:r"

typedef enum {
    CLI_ATTESTER_HINT = 'h',
    CLI_ATTESTER_ATTESTATION_KEY = '5',
} cli_util_attester_args_e;

static const struct option attester_options[] = {
        /* attester specific psk group-options */
        {"hint", required_argument, 0, CLI_ATTESTER_HINT},
        /* attester specific options */
        {"attestation-key", required_argument, 0, CLI_ATTESTER_ATTESTATION_KEY},
        {0}};

/**
 * @brief Checks whether all required options have been specified.
 *
 * @param caller the cli parser caller
 * @param LOG_NAME the log name
 * @param variables the cli config variables
 */
static int check_required_options(const cli_config* const variables) {
    /* check if attestation key file was specified */
    if (variables->specific_config.attester_config.attestation_key.ctx_path ==
            NULL) {
        charra_log_error("[%s] ERROR: no attestation key file", LOG_NAME);
        return -1;
    }
    return 0;
}

static void print_attester_help_message(const cli_config* const variables) {
    /* print specific attester options */
    printf("     --attestation-key=FORMAT:VALUE:     Specifies the path to "
           "the attestation key. Available are: context, handle.\n");
    printf("     --port=PORT:                Open PORT instead of "
           "port %u.\n",
            *(variables->common_config.port));

    /* print DTLS-PSK grouped options */
    printf("DTLS-PSK Options:\n");
    printf(" -p, --psk:                      Enable DTLS protocol "
           "with PSK. By default the key '%s' and hint '%s' are "
           "used.\n",
            *variables->common_config.dtls_psk_key,
            *variables->specific_config.attester_config.dtls_psk_hint);
    printf(" -k, --key=KEY:                  Use KEY as pre-shared "
           "key for DTLS. Implicitly enables DTLS-PSK.\n");
    printf(" -h, --hint=HINT:                Use HINT as hint for "
           "DTLS. Implicitly enables DTLS-PSK.\n");
}

static cli_config_attester_attestation_key_format_e
parse_attestation_key_format(const char* const format) {
    if (strcmp(format, "context") == 0) {
        return CLI_UTIL_ATTESTATION_KEY_FORMAT_FILE;
    } else if (strcmp(format, "handle") == 0) {
        return CLI_UTIL_ATTESTATION_KEY_FORMAT_HANDLE;
    }
    return CLI_UTIL_ATTESTATION_KEY_FORMAT_UNKNOWN;
}

static int cli_attester_attestation_key(cli_config* variables) {
    char* format = NULL;
    char* value = NULL;
    uint64_t handle_value = 0;
    if (cli_util_common_split_option_string(optarg, &format, &value) != 0) {
        charra_log_error("[%s] Argument syntax error: please use "
                         "'--attestation-key=FORMAT:VALUE:'",
                LOG_NAME);
        return -1;
    }
    variables->specific_config.attester_config.attestation_key_format =
            parse_attestation_key_format(format);
    switch (variables->specific_config.attester_config.attestation_key_format) {
    case CLI_UTIL_ATTESTATION_KEY_FORMAT_FILE:
        if (charra_io_file_exists(value) != CHARRA_RC_SUCCESS) {
            charra_log_error("[%s] Attestation key: file '%s' does not exist.",
                    LOG_NAME, value);
            return -1;
        }
        variables->specific_config.attester_config.attestation_key.ctx_path =
                value;
        break;
    case CLI_UTIL_ATTESTATION_KEY_FORMAT_HANDLE:
        if (cli_util_common_parse_option_as_ulong(value, 16, &handle_value) !=
                0) {
            charra_log_error(
                    "[%s] Attestation key: handle '%s' cannot be parsed.",
                    LOG_NAME, value);
            return -1;
        }
        variables->specific_config.attester_config.attestation_key.tpm2_handle =
                (ESYS_TR)handle_value;
        break;
    case CLI_UTIL_ATTESTATION_KEY_FORMAT_UNKNOWN:
        charra_log_error("[%s] Unknown format: '%s'", LOG_NAME, format);
        return -1;
    }

    return 0;
}

static void cli_attester_psk_hint(const cli_config* variables) {
    *variables->common_config.use_dtls_psk = true;
    uint32_t length = strlen(optarg);
    char* hint = malloc(length * sizeof(char));
    strcpy(hint, optarg);
    *(variables->specific_config.attester_config.dtls_psk_hint) = hint;
}

int parse_command_line_attester_arguments(
        int argc, char** argv, cli_config* variables) {
    int rc = 0;
    const size_t attester_options_length =
            sizeof(attester_options) / sizeof(struct option);
    struct option* combined_options = NULL;
    rc = cli_util_common_get_combined_option_array(&combined_options,
            attester_options, attester_options_length, LOG_NAME);
    if (rc != 0) {
        return -1;
    }
    for (;;) {
        int index = -1;
        int identifier = getopt_long(
                argc, argv, ATTESTER_SHORT_OPTIONS, combined_options, &index);
        switch (identifier) {
        case -1:
            rc = check_required_options(variables);
            goto cleanup;
        /* parse specific options */
        case CLI_ATTESTER_ATTESTATION_KEY:
            rc = cli_attester_attestation_key(variables);
            break;
        case CLI_ATTESTER_HINT:
            cli_attester_psk_hint(variables);
            break;
        /* parse common options */
        default:
            rc = cli_util_common_parse_command_line_argument(identifier,
                    variables, LOG_NAME, print_attester_help_message);
            break;
        }
        if (rc != 0) {
            goto cleanup;
        }
    }
cleanup:
    free((void*)combined_options);
    return rc;
}
