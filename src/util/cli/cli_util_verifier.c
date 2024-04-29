/* SPDX-License-Identifier: BSD-3-Clause */
/*****************************************************************************
 * Copyright 2024, Fraunhofer Institute for Secure Information Technology SIT.
 * All rights reserved.
 ****************************************************************************/

/**
 * @file cli_util_verifier.c
 * @author Markus Horn (markus.horn@sit.fraunhofer.de)
 * @author Dominik Lorych (dominik.lorych@sit.fraunhofer.de)
 * @brief Provides command line parsing for verifier.
 * @version 0.1
 * @date 2024-04-22
 *
 * @copyright Copyright 2024, Fraunhofer Institute for Secure Information
 * Technology SIT. All rights reserved.
 *
 * @license BSD 3-Clause "New" or "Revised" License (SPDX-License-Identifier:
 * BSD-3-Clause).
 */

#include "cli_util_verifier.h"
#include "../io_util.h"
#include "cli_util_common.h"
#include <bits/getopt_core.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define LOG_NAME "verifier"
#define VERIFIER_SHORT_OPTIONS "vl:c:t:f:s:pk:i:r"

typedef enum {
    CLI_VERIFIER_IDENTITY = 'i',
    CLI_VERIFIER_IP = 'a',
    CLI_VERIFIER_TIMEOUT = 't',
    CLI_VERIFIER_ATTESTATION_PUBLIC_KEY = '5',
    CLI_VERIFIER_PCR_FILE = 'f',
    CLI_VERIFIER_PCR_SELECTION = 's',
    CLI_VERIFIER_IMA = 'm',
} cli_util_verifier_args_e;

static const struct option verifier_options[] = {
        /* verifier specific psk group-options */
        {"identity", required_argument, 0, CLI_VERIFIER_IDENTITY},
        /* attester specific options */
        {"ip", required_argument, 0, CLI_VERIFIER_IP},
        {"timeout", required_argument, 0, CLI_VERIFIER_TIMEOUT},
        {"attestation-public-key", required_argument, 0,
                CLI_VERIFIER_ATTESTATION_PUBLIC_KEY},
        {"pcr-file", required_argument, 0, CLI_VERIFIER_PCR_FILE},
        {"pcr-selection", required_argument, 0, CLI_VERIFIER_PCR_SELECTION},
        {"ima", optional_argument, 0, CLI_VERIFIER_IMA}, {0}};

/**
 * @brief Checks whether all required options have been specified.
 *
 * @param caller the cli parser caller
 * @param LOG_NAME the log name
 * @param variables the cli config variables
 */
static int check_required_options(const cli_config* const variables) {
    /* check if PCR reference file was specified */
    if (*(variables->specific_config.verifier_config.reference_pcr_file_path) ==
            NULL) {
        charra_log_error("[%s] ERROR: no PCR reference file", LOG_NAME);
        return -1;
    }
    /* check if attestation-public-key file was specified */
    if (*(variables->specific_config.verifier_config
                        .attestation_public_key_path) == NULL) {
        charra_log_error(
                "[%s] ERROR: no attestation public key file", LOG_NAME);
        return -1;
    }
    return 0;
}

static void print_verifier_help_message(const cli_config* const variables) {
    /* print specific verifier options */
    printf("     --ip=IP:                    Connect to IP instead "
           "of doing the attestation on localhost.\n");
    printf("     --port=PORT:                Connect to PORT "
           "instead of default port %u.\n",
            *(variables->common_config.port));
    printf(" -t, --timeout=SECONDS:          Wait up to SECONDS "
           "for the attestation answer. Default is %d seconds.\n",
            *(variables->specific_config.verifier_config.timeout));
    printf("     --attestation-public-key=PATH:      Specifies the path to "
           "the public portion of the attestation key.\n");
    printf(" -f, --pcr-file=FORMAT:PATH:     Read reference PCRs "
           "from PATH in a specified FORMAT. Available is: "
           "yaml.\n");
    printf(" -s, --pcr-selection=X1[,X2...]: Specifies which PCRs "
           "to check on the attester. Each X references one PCR. "
           "PCR numbers shall be ordered from smallest to biggest, "
           "comma-seperated\n");
    printf("                                 and without "
           "whitespace. By default these PCRs are checked: sha256:");
    const uint32_t tpm_pcr_selection_len =
            variables->specific_config.verifier_config.tpm_pcr_selection_len[1];
    for (uint32_t i = 0; i < tpm_pcr_selection_len; i++) {
        printf("%d", variables->specific_config.verifier_config
                             .tpm_pcr_selection[1][i]);
        if (i != variables->specific_config.verifier_config
                                 .tpm_pcr_selection_len[1] -
                         1) {
            printf(", ");
        }
    }

    printf("\n");
    printf("     --ima[=PATH]:               Request the attester "
           "to include an IMA event log in the attestation "
           "response. By default IMA requests the file\n");
    printf("                                 '%s'. Alternatives "
           "can be passed.\n",
            *(variables->specific_config.verifier_config.ima_event_log_path));

    /* print DTLS-PSK grouped options */
    printf("DTLS-PSK Options:\n");
    printf(" -p, --psk:                      Enable DTLS protocol "
           "with PSK. By default the key '%s' and identity '%s' "
           "are used.\n",
            *variables->common_config.dtls_psk_key,
            *variables->specific_config.verifier_config.dtls_psk_identity);
    printf(" -k, --key=KEY:                  Use KEY as pre-shared "
           "key for DTLS-PSK. Implicitly enables DTLS-PSK.\n");
    printf(" -i, --identity=IDENTITY:        Use IDENTITY as "
           "identity for DTLS. Implicitly enables DTLS-PSK.\n");
}

static void cli_verifer_identity(const cli_config* variables) {
    *variables->common_config.use_dtls_psk = true;
    uint32_t length = strlen(optarg);
    char* identity = malloc(length * sizeof(char));
    strcpy(identity, optarg);
    *(variables->specific_config.verifier_config.dtls_psk_identity) = identity;
}

static int cli_verifier_ip(const cli_config* variables) {
    int argument_length = strlen(optarg);
    if (argument_length > 15) {
        charra_log_error("[%s] Error while parsing '--ip': Input too long "
                         "for IPv4 address",
                LOG_NAME);
        return -1;
    }
    strncpy(variables->specific_config.verifier_config.dst_host, optarg, 16);
    return 0;
}

static int cli_verifier_timeout(const cli_config* variables) {
    char* end;
    *(variables->specific_config.verifier_config.timeout) =
            (uint16_t)strtoul(optarg, &end, 10);
    if (*(variables->specific_config.verifier_config.timeout) == 0 ||
            end == optarg) {
        charra_log_error("[%s] Error while parsing '--port': Port "
                         "could not be parsed",
                LOG_NAME);
        return -1;
    }
    return 0;
}

static int cli_verifier_attestation_public_key(const cli_config* variables) {
    char* path = malloc(strlen(optarg) + 1);
    strcpy(path, optarg);
    if (charra_io_file_exists(path) != CHARRA_RC_SUCCESS) {
        charra_log_error("[%s] Attestation key: file '%s' does not exist.",
                LOG_NAME, path);
        return -1;
    }
    *(variables->specific_config.verifier_config.attestation_public_key_path) =
            path;
    return 0;
}

static int cli_verifier_pcr_file(const cli_config* variables) {
    size_t length = 0;
    char* token = NULL;
    const char delimiter[] = ":";
    char* format = NULL;
    char* path = NULL;

    /* get the token representing the file format */
    token = strtok(optarg, delimiter);
    format = token;

    /* get the token representing the path of the file */
    token = strtok(NULL, delimiter);
    /* check if there is a delimiter */
    if (token == NULL) {
        charra_log_error("[%s] Argument syntax error: please use "
                         "'--pcr-file=FORMAT:PATH'",
                LOG_NAME, format);
        return -1;
    }
    length = strlen(token) + 1;
    path = malloc(length * sizeof(char));
    if (path == NULL) {
        charra_log_error("[%s] Could not allocate enough memory");
        return -1;
    }
    strcpy(path, token);
    path[length - 1] = '\0';

    /* check if format is valid */
    if (strcmp(format, "yaml") != 0) {
        charra_log_error(
                "[%s] File format '%s' is not supported.", LOG_NAME, format);
        return -1;
    }
    /* check if file exists */
    if (charra_io_file_exists(path) == CHARRA_RC_SUCCESS) {
        *(variables->specific_config.verifier_config.reference_pcr_file_path) =
                path;
        return 0;
    } else {
        charra_log_error(
                "[%s] Reference PCR file '%s' does not exist.", LOG_NAME, path);
        return -1;
    }
}

static char* cli_verifier_strtok(
        char* str, const char* const delim, char** saveptr) {
    char* token = NULL;

    if (str == NULL) {
        /* get string from saveptr */
        str = *saveptr;
    }

    if (*str == '\0') {
        /* check if string reached its end */
        *saveptr = str;
        return NULL;
    }

    token = str;
    /* get first character which is part of the delimiter */
    str += strcspn(token, delim);
    if (*str != '\0') {
        /* setup next token */
        *str = '\0';
        *saveptr = str + 1;
    } else {
        /* there is no more token */
        *saveptr = str;
    }

    return token;
}

static int cli_verifier_parse_pcr_bank(uint8_t* tpm_pcr_selection_bank,
        uint32_t* tpm_pcr_selection_len, char* pcr_list) {
    if (strcmp(pcr_list, "all") == 0) {
        for (uint8_t i = 0; i < TPM2_MAX_PCRS; i++) {
            tpm_pcr_selection_bank[i] = true;
        }
        *tpm_pcr_selection_len = TPM2_MAX_PCRS;
        return 0;
    }
    char* pcr_token = NULL;
    char* next_token = pcr_list;
    uint8_t tpm_pcr_selection_hash_set[TPM2_MAX_PCRS] = {0};
    uint8_t pcr = 0;
    uint64_t parse_value = 0;
    /* fill the hash_set with  */
    while ((pcr_token = cli_verifier_strtok(NULL, ",", &next_token)) != NULL) {
        if (cli_util_common_parse_option_as_ulong(
                    pcr_token, 10, &parse_value) != 0) {
            charra_log_error("[%s] Could not parse '%s'.", LOG_NAME, pcr_token);
            return -1;
        }
        if (parse_value >= TPM2_MAX_PCRS) {
            charra_log_error(
                    "[%s] Unsupported handle '%s'.", LOG_NAME, pcr_token);
            return -1;
        }
        pcr = (uint8_t)parse_value;
        tpm_pcr_selection_hash_set[pcr] = true;
    }
    /* add hash set values sorted into tpm_pcr_selection_bank */
    *tpm_pcr_selection_len = 0;
    for (uint8_t i = 0; i < TPM2_MAX_PCRS; i++) {
        if (tpm_pcr_selection_hash_set[i] == 0) {
            continue;
        }
        tpm_pcr_selection_bank[*tpm_pcr_selection_len] = i;
        *tpm_pcr_selection_len = *tpm_pcr_selection_len + 1;
    }
    return 0;
}

static int cli_verifier_parse_pcr_bank_to_index(const char* const pcr_bank) {
    if (strcmp(pcr_bank, "sha1") == 0) {
        return 0;
    } else if (strcmp(pcr_bank, "sha256") == 0) {
        return 1;
    } else if (strcmp(pcr_bank, "sha384") == 0) {
        return 2;
    } else if (strcmp(pcr_bank, "sha512") == 0) {
        return 3;
    }
    return -1;
}

static int cli_verifier_parse_pcr_selection(
        const cli_config* variables, char* pcr_selections) {
    /*
    Syntax of PCR selections is: "bank1:pcr1,pcr2,pcr3+bank2:pcr4,pcr5"
    best way to parse is by splitting the string by '+' for each bank
    */
    char* bank_token = NULL;
    char* next_token = pcr_selections;
    char* bank_name = NULL;
    char* pcr_list = NULL;
    int bank = -1;
    while ((bank_token = cli_verifier_strtok(NULL, "+", &next_token)) != NULL) {
        bank_name = cli_verifier_strtok(bank_token, ":", &pcr_list);
        if (bank_name == NULL) {
            charra_log_error("[%s] No bank defined '%s'", LOG_NAME);
            return -1;
        }
        bank = cli_verifier_parse_pcr_bank_to_index(bank_name);
        if (bank < 0 || bank >= TPM2_PCR_BANK_COUNT) {
            charra_log_error("[%s] Invalid PCR bank '%s'", LOG_NAME, bank_name);
            return -1;
        }
        if (cli_verifier_parse_pcr_bank(
                    variables->specific_config.verifier_config
                            .tpm_pcr_selection[bank],
                    &variables->specific_config.verifier_config
                             .tpm_pcr_selection_len[bank],
                    pcr_list) != 0) {
            return -1;
        }
    }
    return 0;
}

static int cli_verifier_pcr_selection(const cli_config* variables) {
    uint8_t(*tpm_pcr_selection)[TPM2_MAX_PCRS] =
            variables->specific_config.verifier_config.tpm_pcr_selection;
    uint32_t* tpm_pcr_selection_len =
            variables->specific_config.verifier_config.tpm_pcr_selection_len;
    for (uint32_t i = 0; i < TPM2_PCR_BANK_COUNT; i++) {
        for (uint32_t j = 0; j < TPM2_MAX_PCRS; j++) {
            /*
             * overwrite static config with zeros in case CLI config uses
             * less PCRs
             */
            tpm_pcr_selection[i][j] = 0;
        }
        tpm_pcr_selection_len[i] = 0;
    }
    if (cli_verifier_parse_pcr_selection(variables, optarg) != 0) {
        return -1;
    }
    return 0;
}

static void cli_verifier_ima(const cli_config* variables) {
    *(variables->specific_config.verifier_config.use_ima_event_log) = true;
    if (optarg != NULL) {
        *(variables->specific_config.verifier_config.ima_event_log_path) =
                malloc(strlen(optarg) + 1);
        strncpy(*(variables->specific_config.verifier_config
                                .ima_event_log_path),
                optarg, strlen(optarg));
    }
}

int parse_command_line_verifier_arguments(
        int argc, char** argv, cli_config* variables) {
    int rc = 0;
    const size_t verifier_options_length =
            sizeof(verifier_options) / sizeof(struct option);
    struct option* combined_options = NULL;
    rc = cli_util_common_get_combined_option_array(&combined_options,
            verifier_options, verifier_options_length, LOG_NAME);
    if (rc != 0) {
        return -1;
    }
    for (;;) {
        int index = -1;
        int identifier = getopt_long(
                argc, argv, VERIFIER_SHORT_OPTIONS, combined_options, &index);
        switch (identifier) {
        case -1:
            rc = check_required_options(variables);
            goto cleanup;
        /* parse specific options */
        case CLI_VERIFIER_IDENTITY:
            cli_verifer_identity(variables);
            break;
        case CLI_VERIFIER_IP:
            rc = cli_verifier_ip(variables);
            break;
        case CLI_VERIFIER_TIMEOUT:
            rc = cli_verifier_timeout(variables);
            break;
        case CLI_VERIFIER_ATTESTATION_PUBLIC_KEY:
            rc = cli_verifier_attestation_public_key(variables);
            break;
        case CLI_VERIFIER_PCR_FILE:
            rc = cli_verifier_pcr_file(variables);
            break;
        case CLI_VERIFIER_PCR_SELECTION:
            rc = cli_verifier_pcr_selection(variables);
            break;
        case CLI_VERIFIER_IMA:
            cli_verifier_ima(variables);
            break;
        /* parse common options */
        default:
            rc = cli_util_common_parse_command_line_argument(identifier,
                    variables, LOG_NAME, print_verifier_help_message);
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
