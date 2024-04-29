/* SPDX-License-Identifier: BSD-3-Clause */
/*****************************************************************************
 * Copyright 2024, Fraunhofer Institute for Secure Information Technology SIT.
 * All rights reserved.
 ****************************************************************************/

/**
 * @file cli_util_common.c
 * @author Markus Horn (markus.horn@sit.fraunhofer.de)
 * @author Dominik Lorych (dominik.lorych@sit.fraunhofer.de)
 * @brief Provides command line parsing for verifier & attester.
 * @version 0.1
 * @date 2024-04-22
 *
 * @copyright Copyright 2021, Fraunhofer Institute for Secure Information
 * Technology SIT. All rights reserved.
 *
 * @license BSD 3-Clause "New" or "Revised" License (SPDX-License-Identifier:
 * BSD-3-Clause).
 */

#include "cli_util_common.h"
#include "../coap_util.h"
#include "../io_util.h"
#include <bits/getopt_ext.h>
#include <errno.h>
#include <stdlib.h>

typedef enum {
    CLI_COMMON_VERBOSE = 'v',
    CLI_COMMON_LOG_LEVEL = 'l',
    CLI_COMMON_COAP_LOG_LEVEL = 'c',
    CLI_COMMON_HELP = '0',
    CLI_COMMON_PORT = 'b',
    CLI_COMMON_RPK = 'r',
    CLI_COMMON_PRIVATE_KEY = '1',
    CLI_COMMON_PUBLIC_KEY = '2',
    CLI_COMMON_PEER_PUBLIC_KEY = '3',
    CLI_COMMON_VERIFY_PEER = '4',
    CLI_COMMON_PSK = 'p',
    CLI_COMMON_KEY = 'k',
} cli_util_common_args_e;

const struct option cli_util_common_options[] = {
        /* common options */
        {"verbose", no_argument, 0, CLI_COMMON_VERBOSE},
        {"log-level", required_argument, 0, CLI_COMMON_LOG_LEVEL},
        {"coap-log-level", required_argument, 0, CLI_COMMON_COAP_LOG_LEVEL},
        {"help", no_argument, 0, CLI_COMMON_HELP},
        /* port only has a specific help message */
        {"port", required_argument, 0, CLI_COMMON_PORT},
        /* common rpk group-options */
        {"rpk", no_argument, 0, CLI_COMMON_RPK},
        {"private-key", required_argument, 0, CLI_COMMON_PRIVATE_KEY},
        {"public-key", required_argument, 0, CLI_COMMON_PUBLIC_KEY},
        {"peer-public-key", required_argument, 0, CLI_COMMON_PEER_PUBLIC_KEY},
        {"verify-peer", required_argument, 0, CLI_COMMON_VERIFY_PEER},
        /* common psk group-options (they have specific help messages) */
        {"psk", no_argument, 0, CLI_COMMON_PSK},
        {"key", required_argument, 0, CLI_COMMON_KEY}};

const size_t cli_util_common_options_size = sizeof(cli_util_common_options);
const size_t cli_util_common_options_length =
        sizeof(cli_util_common_options) / sizeof(struct option);

int cli_util_common_get_combined_option_array(struct option** combined_options,
        const struct option* const specific_options,
        const size_t specific_option_length, const char* const log_name) {
    *combined_options =
            calloc(cli_util_common_options_length + specific_option_length,
                    sizeof(struct option));
    if (*combined_options == NULL) {
        charra_log_error("[%s] ERROR: cli-parser ran out of memory", log_name);
        return -1;
    }
    memcpy((void*)*combined_options, (void*)cli_util_common_options,
            cli_util_common_options_size);
    memcpy((void*)(*combined_options + cli_util_common_options_length),
            specific_options, (specific_option_length * sizeof(struct option)));
    return 0;
}

static void print_dtls_psk_help_message(const cli_config* const variables) {
    printf("DTLS-RPK Options:\n");
    printf("                                 Charra includes default "
           "'keys' in the keys folder, but these are only intended for "
           "testing. They MUST be changed in actual production "
           "environments!\n");
    printf(" -r, --rpk:                      Enable DTLS-RPK (raw "
           "public keys) protocol . The protocol is intended for "
           "scenarios in which public keys of either attester or "
           "verifier or both of them are pre-shared.\n");
    printf("     --private-key=PATH:         Specify the path of the "
           "private key used for RPK. Currently only supports DER "
           "(ASN.1) format.\n");
    printf("                                 By default '%s' is used. "
           "Implicitly enables DTLS-RPK.\n",
            *variables->common_config.dtls_rpk_private_key_path);
    printf("     --public-key=PATH:          Specify the path of the "
           "public key used for RPK. Currently only supports DER "
           "(ASN.1) format.\n");
    printf("                                 By default '%s' is used. "
           "Implicitly enables DTLS-RPK.\n",
            *variables->common_config.dtls_rpk_public_key_path);
    printf("     --peer-public-key=PATH:     Specify the path of the "
           "reference public key of the peer, used for RPK. Currently "
           "only supports DER (ASN.1) format.\n");
    printf("                                 By default '%s' is used. "
           "Implicitly enables DTLS-RPK.\n",
            *variables->common_config.dtls_rpk_peer_public_key_path);
    printf("     --verify-peer=[0,1]:        Specify whether the peers "
           "public key shall be checked against the reference public "
           "key. 0 means no check, 1 means check. By default the check "
           "is performed.\n");
    printf("                                 WARNING: Disabling the "
           "verification means that connections from any peer will be "
           "accepted. This is primarily intended for the verifier, "
           "which may not have\n");
    printf("                                 the public keys of all "
           "attesters and does an identity check with the attestation "
           "response. Implicitly enables DTLS-RPK.\n");
    printf("\nTo specify TCTI commands for the TPM, set the "
           "'CHARRA_TCTI' environment variable accordingly.\n");
}

static void cli_util_common_print_help_message(const char* const log_name,
        void (*print_specific_help_message)(const cli_config* const variables),
        const cli_config* const variables) {
    /* print help messages of common arguments */
    printf("\nUsage: %s [OPTIONS]\n", log_name);
    printf("     --help:                     Print this help "
           "message.\n");
    printf(" -v, --verbose:                  Set CHARRA and CoAP "
           "log-level to DEBUG.\n");
    printf(" -l, --log-level=LEVEL:          Set CHARRA log-level to "
           "LEVEL. Available are: TRACE, DEBUG, INFO, WARN, ERROR, "
           "FATAL. Default is INFO.\n");
    printf(" -c, --coap-log-level=LEVEL:     Set CoAP log-level to "
           "LEVEL. Available are: DEBUG, INFO, NOTICE, WARNING, ERR, "
           "CRIT, ALERT, EMERG, CIPHERS. Default is INFO.\n");

    if (print_specific_help_message != NULL) {
        print_specific_help_message(variables);
    }

    print_dtls_psk_help_message(variables);
}

static void cli_util_common_verbose(const cli_config* variables) {
    *(variables->common_config.charra_log_level) = CHARRA_LOG_DEBUG;
    *(variables->common_config.coap_log_level) = LOG_DEBUG;
}

static int cli_util_common_charra_log_level(
        const cli_config* variables, const char* const log_name) {
    int result = charra_log_level_from_str(
            optarg, variables->common_config.charra_log_level);
    if (result != 0) {
        charra_log_error("[%s] Error while parsing '-l/--log-level': "
                         "Unrecognized argument %s",
                log_name, optarg);
        return -1;
    }
    return 0;
}

static int cli_util_common_coap_log_level(
        const cli_config* variables, const char* const log_name) {
    int result = charra_coap_log_level_from_str(
            optarg, variables->common_config.coap_log_level);
    if (result != 0) {
        charra_log_error("[%s] Error while parsing '-c/--coap-log-level': "
                         "Unrecognized argument %s",
                log_name, optarg);
        return -1;
    }
    return 0;
}

static int cli_util_common_port(
        const cli_config* variables, const char* const log_name) {
    char* end;
    *(variables->common_config.port) = (unsigned int)strtoul(optarg, &end, 10);
    if (*(variables->common_config.port) == 0 || end == optarg) {
        charra_log_error("[%s] Error while parsing '--port': Port could not be "
                         "parsed",
                log_name);
        return -1;
    }
    return 0;
}

static void cli_util_common_psk(const cli_config* variables) {
    *variables->common_config.use_dtls_psk = true;
}

static void cli_util_common_psk_key(const cli_config* variables) {
    *variables->common_config.use_dtls_psk = true;
    uint32_t length = strlen(optarg);
    char* key = malloc(length * sizeof(char));
    strcpy(key, optarg);
    *(variables->common_config.dtls_psk_key) = key;
}

static void cli_util_common_rpk(const cli_config* variables) {
    *variables->common_config.use_dtls_rpk = true;
}

static int cli_util_common_dtls_rpk_private_key(
        const cli_config* variables, const char* const log_name) {
    *variables->common_config.use_dtls_rpk = true;
    char* path = malloc(strlen(optarg));
    strcpy(path, optarg);
    if (charra_io_file_exists(path) == CHARRA_RC_SUCCESS) {
        *(variables->common_config.dtls_rpk_private_key_path) = path;
        return 0;
    } else {
        charra_log_error("[%s] DTLS-RPK: private key file '%s' does not exist.",
                log_name, path);
        return -1;
    }
}

static int cli_util_common_dtls_rpk_public_key(
        const cli_config* variables, const char* const log_name) {
    *variables->common_config.use_dtls_rpk = true;
    char* path = malloc(strlen(optarg));
    strcpy(path, optarg);
    if (charra_io_file_exists(path) == CHARRA_RC_SUCCESS) {
        *(variables->common_config.dtls_rpk_public_key_path) = path;
        return 0;
    } else {
        charra_log_error("[%s] DTLS-RPK: public key file '%s' does not exist.",
                log_name, path);
        return -1;
    }
}

static int cli_util_common_dtls_rpk_peer_public_key(
        const cli_config* variables, const char* const log_name) {
    *variables->common_config.use_dtls_rpk = true;
    char* path = malloc(strlen(optarg));
    strcpy(path, optarg);
    if (charra_io_file_exists(path) == CHARRA_RC_SUCCESS) {
        *(variables->common_config.dtls_rpk_peer_public_key_path) = path;
        return 0;
    } else {
        charra_log_error("[%s] DTLS-RPK: peers' public key file '%s' "
                         "does not exist.",
                log_name, path);
        return -1;
    }
}

static int cli_util_common_verify_rpk_peer_public_key(
        const cli_config* variables, const char* const log_name) {
    if (strcmp("0", optarg) == 0) {
        *variables->common_config.dtls_rpk_verify_peer_public_key = false;
    } else if (strcmp("1", optarg) == 0) {
        *variables->common_config.dtls_rpk_verify_peer_public_key = true;
    } else {
        charra_log_error("[%s] Error while parsing '--verify-peer': "
                         "'%s' could not be parsed as 0 or 1.",
                log_name, optarg);
        return -1;
    }
    return 0;
}

int cli_util_common_parse_command_line_argument(const int identifier,
        const cli_config* variables, const char* const log_name,
        void (*print_specific_help_message)(
                const cli_config* const variables)) {
    switch (identifier) {
    case CLI_COMMON_HELP:
    case '?':
        cli_util_common_print_help_message(
                log_name, print_specific_help_message, variables);
        return (identifier == '?') ? -1 : 1;
    case CLI_COMMON_VERBOSE:
        cli_util_common_verbose(variables);
        return 0;
    case CLI_COMMON_LOG_LEVEL:
        return cli_util_common_charra_log_level(variables, log_name);
    case CLI_COMMON_COAP_LOG_LEVEL:
        return cli_util_common_coap_log_level(variables, log_name);
    case CLI_COMMON_PEER_PUBLIC_KEY:
        return cli_util_common_dtls_rpk_peer_public_key(variables, log_name);
    case CLI_COMMON_PRIVATE_KEY:
        return cli_util_common_dtls_rpk_private_key(variables, log_name);
    case CLI_COMMON_VERIFY_PEER:
        return cli_util_common_verify_rpk_peer_public_key(variables, log_name);
    case CLI_COMMON_RPK:
        cli_util_common_rpk(variables);
        return 0;
    case CLI_COMMON_PUBLIC_KEY:
        return cli_util_common_dtls_rpk_public_key(variables, log_name);
    case CLI_COMMON_PSK:
        cli_util_common_psk(variables);
        return 0;
    case CLI_COMMON_PORT:
        return cli_util_common_port(variables, log_name);
    case CLI_COMMON_KEY:
        cli_util_common_psk_key(variables);
        return 0;
    default:
        // undefined behaviour, probably because getopt_long returned an
        // identifier which is not checked here
        charra_log_error("[%s] Error: Undefined behaviour while parsing "
                         "command line",
                log_name);
        return -1;
    }
}

int cli_util_common_split_option_string(
        char* option, char** format, char** value) {
    if (option == NULL) {
        return -1;
    }
    char* token = NULL;
    const char delimiter[] = ":";

    /* get the token representing the file format */
    token = strtok(optarg, delimiter);
    *format = token;

    /* get the token representing the value */
    token = strtok(NULL, delimiter);
    /* check if there is a delimiter */
    if (token == NULL) {
        return -1;
    }
    *value = token;
    return 0;
}

int cli_util_common_parse_option_as_ulong(
        const char* const option, int base, uint64_t* value) {
    char* endptr = NULL;
    errno = 0;
    *value = strtoul(option, &endptr, base);
    if (errno != 0 || *endptr != '\0') {
        return -1;
    }
    return 0;
}
