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

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <coap3/coap_debug.h>
#include <mbedtls/md.h>

#include "../../coap_util.h"
#include "../../io_util.h"
#include "../../parser_util.h"
#include "../file/config_verifier_file_util.h"

#define LOG_NAME "verifier"
#define VERIFIER_SHORT_OPTIONS "vl:c:t:f:s:pk:i:rg:h"

/* string values */
#define ATTESTER_FALSE_BIT_VALUE_STR "0"
#define ATTESTER_TRUE_BIT_VALUE_STR "1"
#define ATTESTER_PCR_LOG_FORMAT_TCG_BOOT_STR "tcg-boot"
#define ATTESTER_PCR_LOG_FORMAT_IMA_STR "ima"
#define ATTESTER_PCR_LIST_ALL_STR "all"

/* options (long) */
#define CLI_VERIFIER_VERBOSE_LONG "verbose"
#define CLI_VERIFIER_LOG_LEVEL_LONG "log-level"
#define CLI_VERIFIER_COAP_LOG_LEVEL_LONG "coap-log-level"
#define CLI_VERIFIER_HELP_LONG "help"
#define CLI_VERIFIER_IP_LONG "ip"
#define CLI_VERIFIER_PORT_LONG "port"
#define CLI_VERIFIER_TIMEOUT_LONG "timeout"
#define CLI_VERIFIER_ATTESTATION_PUBLIC_KEY_LONG "attestation-public-key"
#define CLI_VERIFIER_PCR_FILE_LONG "pcr-file"
#define CLI_VERIFIER_PCR_SELECTION_LONG "pcr-selection"
#define CLI_VERIFIER_PCR_LOG_LONG "pcr-log"
#define CLI_VERIFIER_HASH_ALGORITHM_LONG "hash-algorithm"
#define CLI_VERIFIER_CONFIG_LONG "config"

/* rpk options (long) */
#define CLI_VERIFIER_RPK_LONG "rpk"
#define CLI_VERIFIER_RPK_PRIVATE_KEY_LONG "rpk-private-key"
#define CLI_VERIFIER_RPK_PUBLIC_KEY_LONG "rpk-public-key"
#define CLI_VERIFIER_RPK_PEER_PUBLIC_KEY_LONG "rpk-peer-public-key"
#define CLI_VERIFIER_RPK_VERIFY_PEER_LONG "rpk-verify-peer"

/* psk options (long) */
#define CLI_VERIFIER_PSK_LONG "psk"
#define CLI_VERIFIER_PSK_KEY_LONG "psk-key"
#define CLI_VERIFIER_PSK_IDENTITY_LONG "psk-identity"

typedef enum {
    /* options (short) */
    CLI_VERIFIER_VERBOSE = 'v',
    CLI_VERIFIER_LOG_LEVEL = 'l',
    CLI_VERIFIER_COAP_LOG_LEVEL = '0',
    CLI_VERIFIER_HELP = 'h',
    CLI_VERIFIER_IP = 'i',
    CLI_VERIFIER_PORT = '1',
    CLI_VERIFIER_TIMEOUT = 't',
    CLI_VERIFIER_ATTESTATION_PUBLIC_KEY = 'k',
    CLI_VERIFIER_PCR_FILE = 'f',
    CLI_VERIFIER_PCR_SELECTION = 's',
    CLI_VERIFIER_PCR_LOG = '2',
    CLI_VERIFIER_HASH_ALGORITHM = 'g',
    CLI_VERIFIER_CONFIG = 'c',
    /* rpk options (short) */
    CLI_VERIFIER_RPK = 'r',
    CLI_VERIFIER_RPK_PRIVATE_KEY = '3',
    CLI_VERIFIER_RPK_PUBLIC_KEY = '4',
    CLI_VERIFIER_RPK_PEER_PUBLIC_KEY = '5',
    CLI_VERIFIER_RPK_VERIFY_PEER = '6',
    /* psk options (short) */
    CLI_VERIFIER_PSK = 'p',
    CLI_VERIFIER_PSK_KEY = '7',
    CLI_VERIFIER_PSK_IDENTITY = '8',
} cli_util_verifier_args_e;

static const struct option verifier_options[] = {
        {CLI_VERIFIER_VERBOSE_LONG, no_argument, 0, CLI_VERIFIER_VERBOSE},
        {CLI_VERIFIER_LOG_LEVEL_LONG, required_argument, 0,
                CLI_VERIFIER_LOG_LEVEL},
        {CLI_VERIFIER_COAP_LOG_LEVEL_LONG, required_argument, 0,
                CLI_VERIFIER_COAP_LOG_LEVEL},
        {CLI_VERIFIER_HELP_LONG, no_argument, 0, CLI_VERIFIER_HELP},
        {CLI_VERIFIER_IP_LONG, required_argument, 0, CLI_VERIFIER_IP},
        {CLI_VERIFIER_PORT_LONG, required_argument, 0, CLI_VERIFIER_PORT},
        {CLI_VERIFIER_TIMEOUT_LONG, required_argument, 0, CLI_VERIFIER_TIMEOUT},
        {CLI_VERIFIER_ATTESTATION_PUBLIC_KEY_LONG, required_argument, 0,
                CLI_VERIFIER_ATTESTATION_PUBLIC_KEY},
        {CLI_VERIFIER_PCR_FILE_LONG, required_argument, 0,
                CLI_VERIFIER_PCR_FILE},
        {CLI_VERIFIER_PCR_SELECTION_LONG, required_argument, 0,
                CLI_VERIFIER_PCR_SELECTION},
        {CLI_VERIFIER_PCR_LOG_LONG, required_argument, 0, CLI_VERIFIER_PCR_LOG},
        {CLI_VERIFIER_HASH_ALGORITHM_LONG, required_argument, 0,
                CLI_VERIFIER_HASH_ALGORITHM},
        {CLI_VERIFIER_CONFIG_LONG, required_argument, 0, CLI_VERIFIER_CONFIG},
        /* rpk options */
        {CLI_VERIFIER_RPK_LONG, no_argument, 0, CLI_VERIFIER_RPK},
        {CLI_VERIFIER_RPK_PRIVATE_KEY_LONG, required_argument, 0,
                CLI_VERIFIER_RPK_PRIVATE_KEY},
        {CLI_VERIFIER_RPK_PUBLIC_KEY_LONG, required_argument, 0,
                CLI_VERIFIER_RPK_PUBLIC_KEY},
        {CLI_VERIFIER_RPK_PEER_PUBLIC_KEY_LONG, required_argument, 0,
                CLI_VERIFIER_RPK_PEER_PUBLIC_KEY},
        {CLI_VERIFIER_RPK_VERIFY_PEER_LONG, required_argument, 0,
                CLI_VERIFIER_RPK_VERIFY_PEER},
        /* psk options */
        {CLI_VERIFIER_PSK_LONG, no_argument, 0, CLI_VERIFIER_PSK},
        {CLI_VERIFIER_PSK_KEY_LONG, required_argument, 0, CLI_VERIFIER_PSK_KEY},
        {CLI_VERIFIER_PSK_IDENTITY_LONG, required_argument, 0,
                CLI_VERIFIER_PSK_IDENTITY},
        {0}};

static const size_t verifier_options_len =
        sizeof(verifier_options) / sizeof(struct option);

static config_verifier* config = NULL;

static void charra_print_dtls_psk_help_message(void) {
    printf("DTLS-PSK Options:\n");
    printf(" -%c, --%s:                      Enable DTLS protocol "
           "with PSK. By default the key '%s' and identity '%s' "
           "are used.\n",
            CLI_VERIFIER_PSK, CLI_VERIFIER_PSK_LONG, config->dtls_psk_key,
            config->dtls_psk_identity);
    printf("     --%s=KEY:              Use KEY as pre-shared "
           "key for DTLS-PSK. Implicitly enables DTLS-PSK.\n",
            CLI_VERIFIER_PSK_KEY_LONG);
    printf("     --%s=IDENTITY:    Use IDENTITY as "
           "identity for DTLS. Implicitly enables DTLS-PSK.\n",
            CLI_VERIFIER_PSK_IDENTITY_LONG);
}

static void charra_print_dtls_rpk_help_message(void) {
    printf("DTLS-RPK Options:\n");
    printf("                                 Charra includes default "
           "'keys' in the keys folder, but these are only intended for "
           "testing. They MUST be changed in actual production "
           "environments!\n");
    printf(" -%c, --%s:                      Enable DTLS-RPK (raw "
           "public keys) protocol. The protocol is intended for "
           "scenarios in which public keys of either attester or "
           "verifier or both of them are pre-shared.\n",
            CLI_VERIFIER_RPK, CLI_VERIFIER_RPK_LONG);
    printf("     --%s=PATH:     Specify the path of the "
           "private key used for RPK. Currently only supports DER "
           "(ASN.1) format.\n",
            CLI_VERIFIER_RPK_PRIVATE_KEY_LONG);
    printf("                                 By default '%s' is used. "
           "Implicitly enables DTLS-RPK.\n",
            config->dtls_rpk_private_key_path);
    printf("     --%s=PATH:      Specify the path of the "
           "public key used for RPK. Currently only supports DER "
           "(ASN.1) format.\n",
            CLI_VERIFIER_RPK_PUBLIC_KEY_LONG);
    printf("                                 By default '%s' is used. "
           "Implicitly enables DTLS-RPK.\n",
            config->dtls_rpk_public_key_path);
    printf("     --%s=PATH: Specify the path of the "
           "reference public key of the peer, used for RPK. Currently "
           "only supports DER (ASN.1) format.\n",
            CLI_VERIFIER_RPK_PEER_PUBLIC_KEY_LONG);
    printf("                                 By default '%s' is used. "
           "Implicitly enables DTLS-RPK.\n",
            config->dtls_rpk_peer_public_key_path);
    printf("     --%s=[0,1]:    Specify whether the peers "
           "public key shall be checked against the reference public "
           "key. 0 means no check, 1 means check. By default the check "
           "is performed.\n",
            CLI_VERIFIER_RPK_VERIFY_PEER_LONG);
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

void charra_cli_util_verifier_print_help_message(void) {
    /* print help messages of common arguments */
    printf("Usage: %s [<options>]\n", LOG_NAME);
    printf("Where <options> are:\n");
    printf(" -%c, --%s:                     Print this help "
           "message.\n",
            CLI_VERIFIER_HELP, CLI_VERIFIER_HELP_LONG);
    printf(" -%c, --%s=PATH:              Load verifier config from a file.\n",
            CLI_VERIFIER_CONFIG, CLI_VERIFIER_CONFIG_LONG);
    printf(" -%c, --%s:                  Set CHARRA and CoAP "
           "log-level to DEBUG.\n",
            CLI_VERIFIER_VERBOSE, CLI_VERIFIER_VERBOSE_LONG);
    printf(" -%c, --%s=LEVEL:          Set CHARRA log-level to "
           "LEVEL. Available are: TRACE, DEBUG, INFO, WARN, ERROR, "
           "FATAL. Default is INFO.\n",
            CLI_VERIFIER_LOG_LEVEL, CLI_VERIFIER_LOG_LEVEL_LONG);
    printf("     --%s=LEVEL:     Set CoAP log-level to "
           "LEVEL. Available are: DEBUG, INFO, NOTICE, WARNING, ERR, "
           "CRIT, ALERT, EMERG, CIPHERS. Default is INFO.\n",
            CLI_VERIFIER_COAP_LOG_LEVEL_LONG);

    printf(" -%c, --%s=IP:                    Connect to IP instead "
           "of doing the attestation on localhost.\n",
            CLI_VERIFIER_IP, CLI_VERIFIER_IP_LONG);
    printf("     --%s=PORT:                Connect to PORT "
           "instead of default port %u.\n",
            CLI_VERIFIER_PORT_LONG, config->dst_port);
    printf(" -%c, --%s=SECONDS:          Wait up to SECONDS "
           "for the attestation answer. Default is %d seconds.\n",
            CLI_VERIFIER_TIMEOUT, CLI_VERIFIER_TIMEOUT_LONG,
            config->attestation_response_timeout);
    printf(" -%c, --%s=PATH:      Specifies the path to "
           "the public portion of the attestation key.\n",
            CLI_VERIFIER_ATTESTATION_PUBLIC_KEY,
            CLI_VERIFIER_ATTESTATION_PUBLIC_KEY_LONG);
    printf(" -%c, --%s=FORMAT:PATH:     Read reference PCRs "
           "from PATH in a specified FORMAT. Available is: "
           "yaml.\n",
            CLI_VERIFIER_PCR_FILE, CLI_VERIFIER_PCR_FILE_LONG);
    printf(" -%c, --%s=X1[+X2...]: Specifies which PCRs "
           "to check on the attester. Each X refers to a PCR bank that "
           "begins with the algorithm, followed by a ':' and a comma-separated "
           "list of PCRs. \n"
           "                                 Each PCR bank is separated "
           "by a '+'. ",
            CLI_VERIFIER_PCR_SELECTION, CLI_VERIFIER_PCR_SELECTION_LONG);
    printf("By default these PCRs are checked: sha256:");
    const uint32_t tpm_pcr_selection_len = config->tpm_pcr_selection_len[1];
    for (uint8_t i = 0; i < tpm_pcr_selection_len; i++) {
        printf("%d", config->tpm_pcr_selection[1][i]);
        if (i != config->tpm_pcr_selection_len[1] - 1) {
            printf(",");
        }
    }

    printf("\n");
    printf("     --%s=FORMAT:START,COUNT: Specifies the desired PCR log "
           "format with a starting index and the number of logs. If 'START' is "
           "0, an empty log is requested. If 'COUNT' is 0, all logs beginning "
           "with 'START' are requested.\n"
           "                                 Available formats are: ima, "
           "tcg-boot.\n",
            CLI_VERIFIER_PCR_LOG_LONG);
    printf(" -%c, --%s=ALGORITHM: The hash algorithm used to digest "
           "the tpm quote.\n",
            CLI_VERIFIER_HASH_ALGORITHM, CLI_VERIFIER_HASH_ALGORITHM_LONG);

    charra_print_dtls_psk_help_message();

    charra_print_dtls_rpk_help_message();
}

/**
 * @brief Splits an option string into format and value
 *
 * @param[in] option The option string
 * @param[out] format The format
 * @param[out] value The value
 * @return true on success, false on error
 */
static bool charra_cli_util_verifier_split_option_string(
        char* option, char** format, char** value) {
    if (option == NULL) {
        return false;
    }
    char* token = NULL;
    const char delimiter[] = ":";

    /* get the token representing the file format */
    token = strtok(option, delimiter);
    *format = token;

    /* get the token representing the value */
    token = strtok(NULL, delimiter);
    /* check if there is a delimiter */
    if (token == NULL) {
        return false;
    }
    *value = token;
    return true;
}

static void charra_cli_util_verifier_verbose(void) {
    config->charra_log_level = CHARRA_LOG_DEBUG;
    config->coap_log_level = LOG_DEBUG;
}

static bool charra_cli_util_verifier_charra_log_level(const char* arg) {
    int result = charra_log_level_from_str(arg, &config->charra_log_level);
    if (result != 0) {
        charra_log_error("[%s] Error while parsing '-%c/--%s': "
                         "Unrecognized argument %s",
                LOG_NAME, CLI_VERIFIER_LOG_LEVEL, CLI_VERIFIER_LOG_LEVEL_LONG,
                arg);
        return false;
    }
    return true;
}

static bool charra_cli_util_verifier_coap_log_level(const char* arg) {
    int result = charra_coap_log_level_from_str(arg, &config->coap_log_level);
    if (result != 0) {
        charra_log_error("[%s] Error while parsing '-%c/--%s': "
                         "Unrecognized argument %s",
                LOG_NAME, CLI_VERIFIER_COAP_LOG_LEVEL,
                CLI_VERIFIER_COAP_LOG_LEVEL_LONG, arg);
        return false;
    }
    return true;
}

static bool charra_cli_util_verifier_port(char* arg) {
    char* end;
    config->dst_port = (unsigned int)strtoul(arg, &end, 10);
    if (config->dst_port == 0 || end == arg) {
        charra_log_error("[%s] Error while parsing '--%s': Port could not be "
                         "parsed",
                LOG_NAME, CLI_VERIFIER_PORT_LONG);
        return false;
    }
    return true;
}

static void charra_cli_util_verifier_psk(void) { config->use_dtls_psk = true; }

static void charra_cli_util_verifier_psk_key(char* arg) {
    config->use_dtls_psk = true;
    if (strlen(arg) >= sizeof(config->dtls_psk_key)) {
        charra_log_error(
                "[%s] DTLS-PSK: PSK key '%s' is too long.", LOG_NAME, arg);
        return;
    }
    strncpy(config->dtls_psk_key, arg, sizeof(config->dtls_psk_key));
}

static void charra_cli_util_verifier_rpk(void) { config->use_dtls_rpk = true; }

static bool charra_cli_util_verifier_dtls_rpk_private_key(char* arg) {
    config->use_dtls_rpk = true;
    char* path = arg;
    if (charra_io_file_exists(path) == CHARRA_RC_SUCCESS) {
        if (strlen(path) >= sizeof(config->dtls_rpk_private_key_path)) {
            charra_log_error("[%s] DTLS-RPK: private key file '%s' "
                             "is too long.",
                    LOG_NAME, path);
            return false;
        }
        strncpy(config->dtls_rpk_private_key_path, path,
                sizeof(config->dtls_rpk_private_key_path));
        return true;
    } else {
        charra_log_error("[%s] DTLS-RPK: private key file '%s' does not exist.",
                LOG_NAME, path);
        return false;
    }
}

static bool charra_cli_util_verifier_dtls_rpk_public_key(char* arg) {
    config->use_dtls_rpk = true;
    char* path = arg;
    if (charra_io_file_exists(path) == CHARRA_RC_SUCCESS) {
        if (strlen(path) >= sizeof(config->dtls_rpk_public_key_path)) {
            charra_log_error("[%s] DTLS-RPK: public key file '%s' "
                             "is too long.",
                    LOG_NAME, path);
            return false;
        }
        strncpy(config->dtls_rpk_public_key_path, path,
                sizeof(config->dtls_rpk_public_key_path));
        return true;
    } else {
        charra_log_error("[%s] DTLS-RPK: public key file '%s' does not exist.",
                LOG_NAME, path);
        return false;
    }
}

static bool charra_cli_util_verifier_dtls_rpk_peer_public_key(char* arg) {
    config->use_dtls_rpk = true;
    char* path = arg;
    if (charra_io_file_exists(path) == CHARRA_RC_SUCCESS) {
        if (strlen(path) >= sizeof(config->dtls_rpk_peer_public_key_path)) {
            charra_log_error("[%s] DTLS-RPK: peers' public key file '%s' "
                             "is too long.",
                    LOG_NAME, path);
            return false;
        }
        strncpy(config->dtls_rpk_peer_public_key_path, path,
                sizeof(config->dtls_rpk_peer_public_key_path));
        return true;
    } else {
        charra_log_error("[%s] DTLS-RPK: peers' public key file '%s' "
                         "does not exist.",
                LOG_NAME, path);
        return false;
    }
}

static bool charra_cli_util_verifier_verify_rpk_peer_public_key(char* arg) {
    if (strncmp(ATTESTER_FALSE_BIT_VALUE_STR, arg,
                sizeof(ATTESTER_FALSE_BIT_VALUE_STR)) == 0) {
        config->dtls_rpk_verify_peer_public_key = false;
    } else if (strncmp(ATTESTER_TRUE_BIT_VALUE_STR, arg,
                       sizeof(ATTESTER_TRUE_BIT_VALUE_STR)) == 0) {
        config->dtls_rpk_verify_peer_public_key = true;
    } else {
        charra_log_error("[%s] Error while parsing '--%s': "
                         "'%s' could not be parsed as 0 or 1.",
                LOG_NAME, CLI_VERIFIER_RPK_VERIFY_PEER_LONG, arg);
        return false;
    }
    return true;
}

static bool charra_parse_pcr_log_start_count(
        char* const value, pcr_log_dto* const pcr_log) {
    char* number1 = NULL;
    char* number2 = NULL;
    number1 = strtok(value, ",");
    number2 = strtok(NULL, ",");
    /* check if there is a comma */
    if (number2 == NULL) {
        return false;
    }
    /* parse start and count */
    if (parse_ulong(number1, 10, &pcr_log->start) != CHARRA_RC_SUCCESS) {
        return false;
    }
    if (parse_ulong(number2, 10, &pcr_log->count) != CHARRA_RC_SUCCESS) {
        return false;
    }
    return true;
}

static bool charra_check_pcr_log_format(const char* const format) {
    if (strncmp(format, ATTESTER_PCR_LOG_FORMAT_IMA_STR,
                sizeof(ATTESTER_PCR_LOG_FORMAT_IMA_STR)) == 0 ||
            strncmp(format, ATTESTER_PCR_LOG_FORMAT_TCG_BOOT_STR,
                    sizeof(ATTESTER_PCR_LOG_FORMAT_TCG_BOOT_STR)) == 0) {
        return true;
    }
    return false;
}

static bool charra_cli_verifier_pcr_log(char* arg) {
    char* format = NULL;
    char* value = NULL;
    pcr_log_dto pcr_log = {0};

    if (!charra_cli_util_verifier_split_option_string(arg, &format, &value)) {
        charra_log_error("[%s] Argument syntax error: please use "
                         "'--%s=FORMAT:START,COUNT'",
                LOG_NAME, CLI_VERIFIER_PCR_LOG_LONG);
        return false;
    }

    /* check and insert start and count PCR log */
    if (!charra_parse_pcr_log_start_count(value, &pcr_log)) {
        charra_log_error("[%s] Argument syntax error: please use "
                         "'--%s=FORMAT:START,COUNT'",
                LOG_NAME, CLI_VERIFIER_PCR_LOG_LONG);
        return false;
    }

    /* check and insert identifier into PCR log */
    if (!charra_check_pcr_log_format(format)) {
        charra_log_error("[%s] Unknown format '%s'", LOG_NAME, format);
        return false;
    }
    size_t format_len = strlen(format);
    memcpy(pcr_log.identifier, format, format_len + 1);

    charra_config_verifier_set_pcr_log(config, &pcr_log);

    return true;
}

static bool charra_cli_verifier_identity(char* arg) {
    config->use_dtls_psk = true;
    if (strlen(arg) >= sizeof(config->dtls_psk_identity)) {
        charra_log_error("[%s] Error while parsing '--%s': Identity "
                         "is too long",
                LOG_NAME, CLI_VERIFIER_PSK_IDENTITY_LONG);
        return false;
    }
    strncpy(config->dtls_psk_identity, arg, sizeof(config->dtls_psk_identity));
    return true;
}

static bool charra_cli_verifier_ip(char* arg) {
    size_t argument_length = strlen(arg);
    if (argument_length >= sizeof(config->dst_host)) {
        charra_log_error("[%s] Error while parsing '--%s': Input too long "
                         "for IPv4 address",
                LOG_NAME, CLI_VERIFIER_IP_LONG);
        return false;
    }
    strncpy(config->dst_host, arg, sizeof(config->dst_host));
    return true;
}

static bool charra_cli_verifier_timeout(char* arg) {
    char* end;
    config->attestation_response_timeout = (uint16_t)strtoul(arg, &end, 10);
    if (config->attestation_response_timeout == 0 || end == arg) {
        charra_log_error("[%s] Error while parsing '--%s': Port "
                         "could not be parsed",
                LOG_NAME, CLI_VERIFIER_PORT_LONG);
        return false;
    }
    return true;
}

static bool charra_cli_verifier_attestation_public_key(char* arg) {
    if (charra_io_file_exists(arg) != CHARRA_RC_SUCCESS) {
        charra_log_error("[%s] Attestation key: file '%s' does not exist.",
                LOG_NAME, arg);
        return false;
    }
    if (strlen(arg) >= sizeof(config->attestation_public_key_path)) {
        charra_log_error("[%s] Attestation key: file path '%s' is too long.",
                LOG_NAME, arg);
        return false;
    }
    strncpy(config->attestation_public_key_path, arg,
            sizeof(config->attestation_public_key_path));
    return true;
}

static bool charra_cli_verifier_pcr_file(char* arg) {
    char* token = NULL;
    const char delimiter[] = ":";
    char* format = NULL;
    char* path = NULL;

    /* get the token representing the file format */
    token = strtok(arg, delimiter);
    format = token;

    /* get the token representing the path of the file */
    token = strtok(NULL, delimiter);
    /* check if there is a delimiter */
    if (token == NULL) {
        charra_log_error("[%s] Argument syntax error: please use "
                         "'--%s=FORMAT:PATH'",
                LOG_NAME, CLI_VERIFIER_PCR_FILE_LONG);
        return false;
    }
    path = token;

    /* check if format is valid */
    charra_config_verifier_reference_pcr_file_format_from_str(
            format, &config->reference_pcr_file_format);
    if (config->reference_pcr_file_format ==
            VERIFIER_REFERENCE_PCRP_FILE_FORMAT_UNKNOWN) {
        charra_log_error(
                "[%s] File format '%s' is not supported.", LOG_NAME, format);
        return false;
    }
    /* check if file exists */
    if (charra_io_file_exists(path) == CHARRA_RC_SUCCESS) {
        if (strlen(path) >= sizeof(config->reference_pcr_file_path)) {
            charra_log_error(
                    "[%s] File path '%s' is too long.", LOG_NAME, path);
            return false;
        }
        strncpy(config->reference_pcr_file_path, path,
                sizeof(config->reference_pcr_file_path));
        return true;
    } else {
        charra_log_error(
                "[%s] Reference PCR file '%s' does not exist.", LOG_NAME, path);
        return false;
    }
}

static char* charra_cli_verifier_strtok(
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

static bool charra_cli_verifier_parse_pcr_bank(uint8_t* tpm_pcr_selection_bank,
        uint8_t* tpm_pcr_selection_len, char* pcr_list) {
    if (strncmp(pcr_list, ATTESTER_PCR_LIST_ALL_STR,
                sizeof(ATTESTER_PCR_LIST_ALL_STR)) == 0) {
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
    while ((pcr_token = charra_cli_verifier_strtok(NULL, ",", &next_token)) !=
            NULL) {
        if (parse_ulong(pcr_token, 10, &parse_value) != CHARRA_RC_SUCCESS) {
            charra_log_error("[%s] Could not parse '%s'.", LOG_NAME, pcr_token);
            return false;
        }
        if (parse_value >= TPM2_MAX_PCRS) {
            charra_log_error(
                    "[%s] Unsupported handle '%s'.", LOG_NAME, pcr_token);
            return false;
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
    return true;
}

static bool charra_cli_verifier_parse_pcr_selection(char* pcr_selections) {
    /*
    Syntax of PCR selections is: "bank1:pcr1,pcr2,pcr3+bank2:pcr4,pcr5"
    best way to parse is by splitting the string by '+' for each bank
    */
    char* bank_token = NULL;
    char* next_token = pcr_selections;
    char* bank_name = NULL;
    char* pcr_list = NULL;
    charra_tpm_pcr_bank_index bank = -1;
    while ((bank_token = charra_cli_verifier_strtok(NULL, "+", &next_token)) !=
            NULL) {
        bank_name = charra_cli_verifier_strtok(bank_token, ":", &pcr_list);
        if (bank_name == NULL) {
            charra_log_error("[%s] No bank defined '%s'", LOG_NAME);
            return false;
        }
        bank = charra_tpm_pcr_bank_index_from_str(bank_name);
        if (bank == CHARRA_TPM_PCR_BANK_UNKNOWN) {
            charra_log_error("[%s] Invalid PCR bank '%s'", LOG_NAME, bank_name);
            return false;
        }
        if (!charra_cli_verifier_parse_pcr_bank(config->tpm_pcr_selection[bank],
                    &config->tpm_pcr_selection_len[bank], pcr_list)) {
            return false;
        }
    }
    return true;
}

static bool charra_cli_verifier_pcr_selection(char* arg) {
    uint8_t (*tpm_pcr_selection)[TPM2_MAX_PCRS] = config->tpm_pcr_selection;
    uint8_t* tpm_pcr_selection_len = config->tpm_pcr_selection_len;
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
    if (!charra_cli_verifier_parse_pcr_selection(arg)) {
        return false;
    }
    return true;
}

static bool charra_cli_verifier_hash_algorithm(const char* const arg) {
    charra_config_verifier_hash_algorithm_from_str(
            arg, &config->signature_hash_algorithm);
    if (config->signature_hash_algorithm.mbedtls_hash_algorithm ==
                    MBEDTLS_MD_NONE ||
            config->signature_hash_algorithm.tpm2_hash_algorithm ==
                    TPM2_ALG_NULL) {
        charra_log_error(
                "[%s] Unsupported hash algorithm: '%s'", LOG_NAME, arg);
        return false;
    }
    return true;
}

static bool on_opt(char key, char* value) {
    if (config->lock_config) {
        // config is locked, arguments are ignored
        return true;
    }

    bool rc = true;

    switch (key) {
    case CLI_VERIFIER_VERBOSE:
        charra_cli_util_verifier_verbose();
        break;
    case CLI_VERIFIER_LOG_LEVEL:
        rc = charra_cli_util_verifier_charra_log_level(value);
        break;
    case CLI_VERIFIER_COAP_LOG_LEVEL:
        rc = charra_cli_util_verifier_coap_log_level(value);
        break;
    case CLI_VERIFIER_IP:
        rc = charra_cli_verifier_ip(value);
        break;
    case CLI_VERIFIER_PORT:
        rc = charra_cli_util_verifier_port(value);
        break;
    case CLI_VERIFIER_TIMEOUT:
        rc = charra_cli_verifier_timeout(value);
        break;
    case CLI_VERIFIER_ATTESTATION_PUBLIC_KEY:
        rc = charra_cli_verifier_attestation_public_key(value);
        break;
    case CLI_VERIFIER_PCR_FILE:
        rc = charra_cli_verifier_pcr_file(value);
        break;
    case CLI_VERIFIER_PCR_SELECTION:
        rc = charra_cli_verifier_pcr_selection(value);
        break;
    case CLI_VERIFIER_PCR_LOG:
        rc = charra_cli_verifier_pcr_log(value);
        break;
    case CLI_VERIFIER_HASH_ALGORITHM:
        rc = charra_cli_verifier_hash_algorithm(value);
        break;
    case CLI_VERIFIER_CONFIG:
        // ignore config files in this iteration
        break;
    /* rpk options */
    case CLI_VERIFIER_RPK:
        charra_cli_util_verifier_rpk();
        break;
    case CLI_VERIFIER_RPK_PRIVATE_KEY:
        rc = charra_cli_util_verifier_dtls_rpk_private_key(value);
        break;
    case CLI_VERIFIER_RPK_PUBLIC_KEY:
        rc = charra_cli_util_verifier_dtls_rpk_public_key(value);
        break;
    case CLI_VERIFIER_RPK_PEER_PUBLIC_KEY:
        rc = charra_cli_util_verifier_dtls_rpk_peer_public_key(value);
        break;
    case CLI_VERIFIER_RPK_VERIFY_PEER:
        rc = charra_cli_util_verifier_verify_rpk_peer_public_key(value);
        break;
    /* psk options */
    case CLI_VERIFIER_PSK:
        charra_cli_util_verifier_psk();
        break;
    case CLI_VERIFIER_PSK_KEY:
        charra_cli_util_verifier_psk_key(value);
        break;
    case CLI_VERIFIER_PSK_IDENTITY:
        rc = charra_cli_verifier_identity(value);
        break;
    default:
        // undefined behaviour, probably because getopt_long returned an
        // identifier which is not checked here
        charra_log_error("[%s] Error: Undefined behaviour while parsing "
                         "command line",
                LOG_NAME);
        return false;
    }
    return rc;
}

static bool load_config_file_on_opt(char key, char* value) {
    if (config->lock_config) {
        // config is locked, arguments are ignored
        return true;
    }

    CHARRA_RC charra_rc = CHARRA_RC_SUCCESS;
    // init config clone if something goes wrong
    config_verifier clone_config = {0};
    memcpy(&clone_config, config, sizeof(config_verifier));

    switch (key) {
    case CLI_VERIFIER_CONFIG:
        charra_rc = load_verifier_yaml_config_file(value, &clone_config);
        if (charra_rc != CHARRA_RC_SUCCESS) {
            charra_log_warn(
                    "[%s] Error while loading config file. Ignoring file: %s.",
                    LOG_NAME, value);
        } else {
            // overwrite config with loaded config
            memcpy(config, &clone_config, sizeof(config_verifier));
            if (config->lock_config) {
                charra_log_info(
                        "Verifier config is locked. No further changes are "
                        "allowed.");
            }
        }
        break;
    default:
        break;
    }

    return true;
}

cli_option_code charra_parse_command_line_verifier_arguments(
        const int argc, char** const argv, config_verifier* const variables) {
    if (variables == NULL) {
        return -1;
    }
    cli_option_code rc = cli_option_code_continue;
    config = variables;
    cli_options* load_config_options = cli_options_new(VERIFIER_SHORT_OPTIONS,
            verifier_options_len, verifier_options, load_config_file_on_opt,
            charra_cli_util_verifier_print_help_message);
    cli_options* options = cli_options_new(VERIFIER_SHORT_OPTIONS,
            verifier_options_len, verifier_options, on_opt,
            charra_cli_util_verifier_print_help_message);
    if (load_config_options == NULL || options == NULL) {
        charra_log_error("[%s] Error while creating option parser", LOG_NAME);
        rc = cli_option_code_error;
        goto cleanup;
    }
    charra_log_info("Loading custom config files");
    rc = cli_handle_options(load_config_options, argc, argv);
    if (rc != cli_option_code_continue) {
        goto cleanup;
    }
    rc = cli_handle_options(options, argc, argv);

cleanup:
    cli_options_free(load_config_options);
    cli_options_free(options);
    return rc;
}
