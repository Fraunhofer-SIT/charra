/* SPDX-License-Identifier: BSD-3-Clause */
/*****************************************************************************
 * Copyright 2024, Fraunhofer Institute for Secure Information Technology SIT.
 * All rights reserved.
 ****************************************************************************/

/**
 * @file cli_util_attester.c
 * @author Markus Horn (markus.horn@sit.fraunhofer.de)
 * @author Dominik Lorych(dominik.lorych @sit.fraunhofer.de)
 * @brief Provides command line parsing for attester.
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

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "../../coap_util.h"
#include "../../crypto_util.h"
#include "../../io_util.h"
#include "../../parser_util.h"
#include "../file/config_attester_file_util.h"

#define LOG_NAME "attester"
#define ATTESTER_SHORT_OPTIONS "vl:c:pk:hrg:"

/* string values */
#define ATTESTER_FALSE_BIT_VALUE_STR "0"
#define ATTESTER_TRUE_BIT_VALUE_STR "1"
#define ATTESTER_PCR_LOG_FORMAT_TCG_BOOT_STR "tcg-boot"
#define ATTESTER_PCR_LOG_FORMAT_IMA_STR "ima"

/* options (long) */
#define CLI_ATTESTER_VERBOSE_LONG "verbose"
#define CLI_ATTESTER_LOG_LEVEL_LONG "log-level"
#define CLI_ATTESTER_COAP_LOG_LEVEL_LONG "coap-log-level"
#define CLI_ATTESTER_HELP_LONG "help"
#define CLI_ATTESTER_PORT_LONG "port"
#define CLI_ATTESTER_PCR_LOG_LONG "pcr-log"
#define CLI_ATTESTER_ATTESTATION_KEY_LONG "attestation-key"
#define CLI_ATTESTER_CONFIG_LONG "config"

/* TPM2-quote options (long) */
#define CLI_ATTESTER_TPM2_QUOTE_SIGNATURE_SCHEME_LONG "scheme"
#define CLI_ATTESTER_TPM2_QUOTE_HASH_ALGORITHM_LONG "hash-algorithm"

/* rpk options (long) */
#define CLI_ATTESTER_RPK_LONG "rpk"
#define CLI_ATTESTER_RPK_PRIVATE_KEY_LONG "rpk-private-key"
#define CLI_ATTESTER_RPK_PUBLIC_KEY_LONG "rpk-public-key"
#define CLI_ATTESTER_RPK_PEER_PUBLIC_KEY_LONG "rpk-peer-public-key"
#define CLI_ATTESTER_RPK_VERIFY_PEER_LONG "rpk-verify-peer"

/* psk options (long) */
#define CLI_ATTESTER_PSK_LONG "psk"
#define CLI_ATTESTER_PSK_KEY_LONG "psk-key"
#define CLI_ATTESTER_PSK_HINT_LONG "psk-hint"

typedef enum {
    /* options (short) */
    CLI_ATTESTER_VERBOSE = 'v',
    CLI_ATTESTER_LOG_LEVEL = 'l',
    CLI_ATTESTER_COAP_LOG_LEVEL = '0',
    CLI_ATTESTER_HELP = 'h',
    CLI_ATTESTER_PORT = '1',
    CLI_ATTESTER_PCR_LOG = '2',
    CLI_ATTESTER_ATTESTATION_KEY = 'k',
    CLI_ATTESTER_CONFIG = 'c',
    /* TPM2-quote options (short) */
    CLI_ATTESTER_TPM2_QUOTE_SIGNATURE_SCHEME = '3',
    CLI_ATTESTER_TPM2_QUOTE_HASH_ALGORITHM = 'g',
    /* rpk options (short) */
    CLI_ATTESTER_RPK = 'r',
    CLI_ATTESTER_RPK_PRIVATE_KEY = '4',
    CLI_ATTESTER_RPK_PUBLIC_KEY = '5',
    CLI_ATTESTER_RPK_PEER_PUBLIC_KEY = '6',
    CLI_ATTESTER_RPK_VERIFY_PEER = '7',
    /* psk options (short) */
    CLI_ATTESTER_PSK = 'p',
    CLI_ATTESTER_PSK_KEY = '8',
    CLI_ATTESTER_PSK_HINT = '9',
} cli_util_attester_args_e;

static const struct option attester_options[] = {
        {CLI_ATTESTER_VERBOSE_LONG, no_argument, 0, CLI_ATTESTER_VERBOSE},
        {CLI_ATTESTER_LOG_LEVEL_LONG, required_argument, 0,
                CLI_ATTESTER_LOG_LEVEL},
        {CLI_ATTESTER_COAP_LOG_LEVEL_LONG, required_argument, 0,
                CLI_ATTESTER_COAP_LOG_LEVEL},
        {CLI_ATTESTER_HELP_LONG, no_argument, 0, CLI_ATTESTER_HELP},
        {CLI_ATTESTER_PORT_LONG, required_argument, 0, CLI_ATTESTER_PORT},
        {CLI_ATTESTER_PCR_LOG_LONG, required_argument, 0, CLI_ATTESTER_PCR_LOG},
        {CLI_ATTESTER_ATTESTATION_KEY_LONG, required_argument, 0,
                CLI_ATTESTER_ATTESTATION_KEY},
        {CLI_ATTESTER_CONFIG_LONG, required_argument, 0, CLI_ATTESTER_CONFIG},
        /* TPM2-quote options */
        {CLI_ATTESTER_TPM2_QUOTE_SIGNATURE_SCHEME_LONG, required_argument, 0,
                CLI_ATTESTER_TPM2_QUOTE_SIGNATURE_SCHEME},
        {CLI_ATTESTER_TPM2_QUOTE_HASH_ALGORITHM_LONG, required_argument, 0,
                CLI_ATTESTER_TPM2_QUOTE_HASH_ALGORITHM},
        /* rpk options */
        {CLI_ATTESTER_RPK_LONG, no_argument, 0, CLI_ATTESTER_RPK},
        {CLI_ATTESTER_RPK_PRIVATE_KEY_LONG, required_argument, 0,
                CLI_ATTESTER_RPK_PRIVATE_KEY},
        {CLI_ATTESTER_RPK_PUBLIC_KEY_LONG, required_argument, 0,
                CLI_ATTESTER_RPK_PUBLIC_KEY},
        {CLI_ATTESTER_RPK_PEER_PUBLIC_KEY_LONG, required_argument, 0,
                CLI_ATTESTER_RPK_PEER_PUBLIC_KEY},
        {CLI_ATTESTER_RPK_VERIFY_PEER_LONG, required_argument, 0,
                CLI_ATTESTER_RPK_VERIFY_PEER},
        /* psk options */
        {CLI_ATTESTER_PSK_LONG, no_argument, 0, CLI_ATTESTER_PSK},
        {CLI_ATTESTER_PSK_KEY_LONG, required_argument, 0, CLI_ATTESTER_PSK_KEY},
        {CLI_ATTESTER_PSK_HINT_LONG, required_argument, 0,
                CLI_ATTESTER_PSK_HINT},
        {0}};

static const size_t attester_options_len =
        sizeof(attester_options) / sizeof(struct option);

static config_attester* config = NULL;

static void charra_print_dtls_psk_help_message(void) {
    printf("DTLS-PSK Options:\n");
    printf(" -%c, --%s:                      Enable DTLS protocol "
           "with PSK. By default the key '%s' and hint '%s' are "
           "used.\n",
            CLI_ATTESTER_PSK, CLI_ATTESTER_PSK_LONG, config->dtls_psk_key,
            config->dtls_psk_hint);
    printf("     --%s=KEY:              Use KEY as pre-shared "
           "key for DTLS. Implicitly enables DTLS-PSK.\n",
            CLI_ATTESTER_PSK_KEY_LONG);
    printf("     --%s=HINT:            Use HINT as hint for "
           "DTLS. Implicitly enables DTLS-PSK.\n",
            CLI_ATTESTER_PSK_HINT_LONG);
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
            CLI_ATTESTER_RPK, CLI_ATTESTER_RPK_LONG);
    printf("     --%s=PATH:     Specify the path of the "
           "private key used for RPK. Currently only supports DER "
           "(ASN.1) format.\n",
            CLI_ATTESTER_RPK_PRIVATE_KEY_LONG);
    printf("                                 By default '%s' is used. "
           "Implicitly enables DTLS-RPK.\n",
            config->dtls_rpk_private_key_path);
    printf("     --%s=PATH:      Specify the path of the "
           "public key used for RPK. Currently only supports DER "
           "(ASN.1) format.\n",
            CLI_ATTESTER_RPK_PUBLIC_KEY_LONG);
    printf("                                 By default '%s' is used. "
           "Implicitly enables DTLS-RPK.\n",
            config->dtls_rpk_public_key_path);
    printf("     --%s=PATH: Specify the path of the "
           "reference public key of the peer, used for RPK. Currently "
           "only supports DER (ASN.1) format.\n",
            CLI_ATTESTER_RPK_PEER_PUBLIC_KEY_LONG);
    printf("                                 By default '%s' is used. "
           "Implicitly enables DTLS-RPK.\n",
            config->dtls_rpk_peer_public_key_path);
    printf("     --%s=[0,1]:    Specify whether the peers "
           "public key shall be checked against the reference public "
           "key. 0 means no check, 1 means check. By default the check "
           "is performed.\n",
            CLI_ATTESTER_RPK_VERIFY_PEER_LONG);
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

void charra_cli_util_attester_print_help_message(void) {
    /* print help messages of common arguments */
    printf("Usage: %s [<options>]\n", LOG_NAME);
    printf("Where <options> are:\n");
    printf(" -%c, --%s:                     Print this help "
           "message.\n",
            CLI_ATTESTER_HELP, CLI_ATTESTER_HELP_LONG);
    printf(" -%c, --%s=PATH:              Load attester config from a file.\n",
            CLI_ATTESTER_CONFIG, CLI_ATTESTER_CONFIG_LONG);
    printf(" -%c, --%s:                  Set CHARRA and CoAP "
           "log-level to DEBUG.\n",
            CLI_ATTESTER_VERBOSE, CLI_ATTESTER_VERBOSE_LONG);
    printf(" -%c, --%s=LEVEL:          Set CHARRA log-level to "
           "LEVEL. Available are: TRACE, DEBUG, INFO, WARN, ERROR, "
           "FATAL. Default is INFO.\n",
            CLI_ATTESTER_LOG_LEVEL, CLI_ATTESTER_LOG_LEVEL_LONG);
    printf("     --%s=LEVEL:     Set CoAP log-level to "
           "LEVEL. Available are: DEBUG, INFO, NOTICE, WARNING, ERR, "
           "CRIT, ALERT, EMERG, CIPHERS. Default is INFO.\n",
            CLI_ATTESTER_COAP_LOG_LEVEL_LONG);

    /* print specific attester options */
    printf(" -%c, --%s=FORMAT:VALUE:     Specifies the path to "
           "the attestation key. Available are: context, handle.\n",
            CLI_ATTESTER_ATTESTATION_KEY, CLI_ATTESTER_ATTESTATION_KEY_LONG);
    printf("     --%s=PORT:                Open PORT instead of "
           "port %u.\n",
            CLI_ATTESTER_PORT_LONG, config->port);
    printf("     --%s=FORMAT:FILE:      Specifies the path to the PCR log "
           "file. Available formats are: ima, tcg-boot.\n",
            CLI_ATTESTER_PCR_LOG_LONG);

    /* TPM2-quote options */
    printf("     --%s=SCHEME:            Specifies the signature "
           "scheme used for the TPM2 quote.\n",
            CLI_ATTESTER_TPM2_QUOTE_SIGNATURE_SCHEME_LONG);
    printf(" -%c, --%s=ALGORITHM: Specifies the hash "
           "algorithm used for the TPM2 quote.\n",
            CLI_ATTESTER_TPM2_QUOTE_HASH_ALGORITHM,
            CLI_ATTESTER_TPM2_QUOTE_HASH_ALGORITHM_LONG);

    /* print DTLS-PSK grouped options */
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
static bool charra_cli_util_attester_split_option_string(
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

static void charra_cli_util_attester_verbose(void) {
    config->charra_log_level = CHARRA_LOG_DEBUG;
    config->coap_log_level = LOG_DEBUG;
}

static bool charra_cli_util_attester_charra_log_level(char* arg) {
    int result = charra_log_level_from_str(arg, &config->charra_log_level);
    if (result != 0) {
        charra_log_error("[%s] Error while parsing '-%c/--%s': "
                         "Unrecognized argument %s",
                LOG_NAME, CLI_ATTESTER_LOG_LEVEL, CLI_ATTESTER_LOG_LEVEL_LONG,
                arg);
        return false;
    }
    return true;
}

static bool charra_cli_util_attester_coap_log_level(char* arg) {
    int result = charra_coap_log_level_from_str(arg, &config->coap_log_level);
    if (result != 0) {
        charra_log_error("[%s] Error while parsing '-%c/--%s': "
                         "Unrecognized argument %s",
                LOG_NAME, CLI_ATTESTER_COAP_LOG_LEVEL,
                CLI_ATTESTER_COAP_LOG_LEVEL_LONG, arg);
        return false;
    }
    return true;
}

static bool charra_cli_util_attester_port(char* arg) {
    char* end;
    config->port = (unsigned int)strtoul(arg, &end, 10);
    if (config->port == 0 || end == arg) {
        charra_log_error("[%s] Error while parsing '--%s': Port could not be "
                         "parsed",
                LOG_NAME, CLI_ATTESTER_PORT_LONG);
        return false;
    }
    return true;
}

static void charra_cli_util_attester_psk(void) { config->use_dtls_psk = true; }

static bool charra_cli_util_attester_psk_key(char* arg) {
    config->use_dtls_psk = true;
    if (strlen(arg) >= sizeof(config->dtls_psk_key)) {
        charra_log_error("[%s] DTLS-PSK PSK key is too long.", LOG_NAME,
                CLI_ATTESTER_PSK_KEY_LONG);
        return false;
    }
    strncpy(config->dtls_psk_key, arg, sizeof(config->dtls_psk_key));
    return true;
}

static void charra_cli_util_attester_rpk(void) { config->use_dtls_rpk = true; }

static bool charra_cli_util_attester_dtls_rpk_private_key(char* arg) {
    config->use_dtls_rpk = true;
    char* path = arg;
    if (charra_io_file_exists(path) == CHARRA_RC_SUCCESS) {
        if (strlen(path) >= sizeof(config->dtls_rpk_private_key_path)) {
            charra_log_error(
                    "[%s] DTLS-RPK: private key path is too long.", LOG_NAME);
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

static bool charra_cli_util_attester_dtls_rpk_public_key(char* arg) {
    config->use_dtls_rpk = true;
    char* path = arg;
    if (charra_io_file_exists(path) == CHARRA_RC_SUCCESS) {
        if (strlen(path) >= sizeof(config->dtls_rpk_public_key_path)) {
            charra_log_error(
                    "[%s] DTLS-RPK: public key path is too long.", LOG_NAME);
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

static bool charra_cli_util_attester_dtls_rpk_peer_public_key(char* arg) {
    config->use_dtls_rpk = true;
    char* path = arg;
    if (charra_io_file_exists(path) == CHARRA_RC_SUCCESS) {
        if (strlen(path) >= sizeof(config->dtls_rpk_peer_public_key_path)) {
            charra_log_error(
                    "[%s] DTLS-RPK: peers' public key path is too long.",
                    LOG_NAME);
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

static bool charra_cli_util_attester_verify_rpk_peer_public_key(char* arg) {
    if (strncmp(ATTESTER_FALSE_BIT_VALUE_STR, arg,
                sizeof(ATTESTER_FALSE_BIT_VALUE_STR)) == 0) {
        config->dtls_rpk_verify_peer_public_key = false;
    } else if (strncmp(ATTESTER_TRUE_BIT_VALUE_STR, arg,
                       sizeof(ATTESTER_TRUE_BIT_VALUE_STR)) == 0) {
        config->dtls_rpk_verify_peer_public_key = true;
    } else {
        charra_log_error("[%s] Error while parsing '--%s': "
                         "'%s' could not be parsed as 0 or 1.",
                LOG_NAME, CLI_ATTESTER_RPK_VERIFY_PEER_LONG, arg);
        return false;
    }
    return true;
}

static bool charra_cli_attester_pcr_log(char* arg) {
    char* format = NULL;
    char* value = NULL;
    if (!charra_cli_util_attester_split_option_string(arg, &format, &value)) {
        charra_log_error("[%s] Argument syntax error: please use "
                         "'--%s=FORMAT:FILE'",
                LOG_NAME, CLI_ATTESTER_PCR_LOG_LONG);
        return false;
    }
    /* check if file is exists */
    if (charra_io_file_exists(value) != CHARRA_RC_SUCCESS) {
        charra_log_error(
                "[%s] PCR log: file '%s' does not exist.", LOG_NAME, value);
        return false;
    }
    /* check if format is valid */
    if (strncmp(format, ATTESTER_PCR_LOG_FORMAT_TCG_BOOT_STR,
                sizeof(ATTESTER_PCR_LOG_FORMAT_TCG_BOOT_STR)) == 0) {
        if (strlen(value) >= sizeof(config->tcg_boot_log_path)) {
            charra_log_error("[%s] TCG-boot log path is too long.", LOG_NAME);
            return false;
        }
        strncpy(config->tcg_boot_log_path, value,
                sizeof(config->tcg_boot_log_path));
    } else if (strncmp(format, ATTESTER_PCR_LOG_FORMAT_IMA_STR,
                       sizeof(ATTESTER_PCR_LOG_FORMAT_IMA_STR)) == 0) {
        if (strlen(value) >= sizeof(config->ima_log_path)) {
            charra_log_error("[%s] IMA log path is too long.", LOG_NAME);
            return false;
        }
        strncpy(config->ima_log_path, value, sizeof(config->ima_log_path));
    } else {
        charra_log_error(
                "[%s] PCR log format '%s' is not supported.", LOG_NAME, format);
        return false;
    }
    return true;
}

static bool charra_cli_attester_attestation_key(char* arg) {
    char* format = NULL;
    char* value = NULL;
    uint64_t handle_value = 0;
    if (!charra_cli_util_attester_split_option_string(arg, &format, &value)) {
        charra_log_error("[%s] Argument syntax error: please use "
                         "'--%s=FORMAT:VALUE'",
                LOG_NAME, CLI_ATTESTER_ATTESTATION_KEY_LONG);
        return false;
    }
    charra_config_attester_attestation_key_format_from_str(
            format, &config->attestation_key_format);
    switch (config->attestation_key_format) {
    case ATTESTER_ATTESTATION_KEY_FORMAT_FILE:
        if (charra_io_file_exists(value) != CHARRA_RC_SUCCESS) {
            charra_log_error("[%s] Attestation key: file '%s' does not exist.",
                    LOG_NAME, value);
            return false;
        }
        if (strlen(value) >= sizeof(config->attestation_key.ctx_path)) {
            charra_log_error(
                    "[%s] Attestation key path is too long.", LOG_NAME);
            return false;
        }
        strncpy(config->attestation_key.ctx_path, value,
                sizeof(config->attestation_key.ctx_path));
        break;
    case ATTESTER_ATTESTATION_KEY_FORMAT_HANDLE:
        if (parse_ulong(value, 16, &handle_value) != CHARRA_RC_SUCCESS) {
            charra_log_error(
                    "[%s] Attestation key: handle '%s' cannot be parsed.",
                    LOG_NAME, value);
            return false;
        }
        config->attestation_key.tpm2_handle = (ESYS_TR)handle_value;
        break;
    case ATTESTER_ATTESTATION_KEY_FORMAT_UNKNOWN:
        charra_log_error("[%s] Unknown format: '%s'", LOG_NAME, format);
        return false;
    }

    return true;
}

static bool charra_cli_attester_psk_hint(char* arg) {
    config->use_dtls_psk = true;
    if (strlen(arg) >= sizeof(config->dtls_psk_hint)) {
        charra_log_error("[%s] DTLS-PSK PSK hint is too long.", LOG_NAME,
                CLI_ATTESTER_PSK_HINT_LONG);
        return false;
    }
    strncpy(config->dtls_psk_hint, arg, sizeof(config->dtls_psk_hint));
    return true;
}

static bool charra_cli_util_attester_scheme(char* arg) {
    config->signature_scheme = charra_signature_scheme_from_str(arg);
    if (config->signature_scheme == TPM2_ALG_NULL) {
        charra_log_error(
                "[%s] Unsupported signature scheme: '%s'", LOG_NAME, arg);
        return false;
    }
    return true;
}

static bool charra_cli_util_attester_hash_algorithm(char* arg) {
    config->hash_algorithm = charra_tpm_hash_algorithm_from_str(arg);
    if (config->hash_algorithm == TPM2_ALG_NULL) {
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
    case CLI_ATTESTER_VERBOSE:
        charra_cli_util_attester_verbose();
        break;
    case CLI_ATTESTER_LOG_LEVEL:
        rc = charra_cli_util_attester_charra_log_level(value);
        break;
    case CLI_ATTESTER_COAP_LOG_LEVEL:
        rc = charra_cli_util_attester_coap_log_level(value);
        break;
    case CLI_ATTESTER_PORT:
        rc = charra_cli_util_attester_port(value);
        break;
    case CLI_ATTESTER_ATTESTATION_KEY:
        rc = charra_cli_attester_attestation_key(value);
        break;
    case CLI_ATTESTER_CONFIG:
        // ignore config files in this iteration
        break;
    /* TPM2-quote options */
    case CLI_ATTESTER_TPM2_QUOTE_SIGNATURE_SCHEME:
        rc = charra_cli_util_attester_scheme(value);
        break;
    case CLI_ATTESTER_TPM2_QUOTE_HASH_ALGORITHM:
        rc = charra_cli_util_attester_hash_algorithm(value);
        break;
    /* rpk options */
    case CLI_ATTESTER_RPK_PEER_PUBLIC_KEY:
        rc = charra_cli_util_attester_dtls_rpk_peer_public_key(value);
        break;
    case CLI_ATTESTER_RPK_PRIVATE_KEY:
        rc = charra_cli_util_attester_dtls_rpk_private_key(value);
        break;
    case CLI_ATTESTER_RPK_VERIFY_PEER:
        rc = charra_cli_util_attester_verify_rpk_peer_public_key(value);
        break;
    case CLI_ATTESTER_RPK:
        charra_cli_util_attester_rpk();
        break;
    case CLI_ATTESTER_RPK_PUBLIC_KEY:
        rc = charra_cli_util_attester_dtls_rpk_public_key(value);
        break;
    /* psk options */
    case CLI_ATTESTER_PSK:
        charra_cli_util_attester_psk();
        break;
    case CLI_ATTESTER_PSK_KEY:
        rc = charra_cli_util_attester_psk_key(value);
        break;
    case CLI_ATTESTER_PCR_LOG:
        rc = charra_cli_attester_pcr_log(value);
        break;
    case CLI_ATTESTER_PSK_HINT:
        charra_cli_attester_psk_hint(value);
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
    config_attester clone_config = {0};
    memcpy(&clone_config, config, sizeof(config_attester));

    switch (key) {
    case CLI_ATTESTER_CONFIG:
        charra_rc = load_attester_yaml_config_file(value, &clone_config);
        if (charra_rc != CHARRA_RC_SUCCESS) {
            charra_log_warn(
                    "[%s] Error while loading config file. Ignoring file: %s.",
                    LOG_NAME, value);
        } else {
            // overwrite config with loaded config
            memcpy(config, &clone_config, sizeof(config_attester));
            if (config->lock_config) {
                charra_log_info(
                        "Attester config is locked. No further changes are "
                        "allowed.");
            }
        }
        break;
    default:
        break;
    }

    return true;
}

cli_option_code charra_parse_command_line_attester_arguments(
        const int argc, char** const argv, config_attester* const variables) {
    if (variables == NULL) {
        return cli_option_code_error;
    }
    cli_option_code rc = cli_option_code_continue;
    config = variables;
    cli_options* load_config_options = cli_options_new(ATTESTER_SHORT_OPTIONS,
            attester_options_len, attester_options, load_config_file_on_opt,
            charra_cli_util_attester_print_help_message);
    cli_options* options = cli_options_new(ATTESTER_SHORT_OPTIONS,
            attester_options_len, attester_options, on_opt,
            charra_cli_util_attester_print_help_message);
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
    charra_log_info("Parsing command line arguments");
    rc = cli_handle_options(options, argc, argv);

cleanup:
    cli_options_free(load_config_options);
    cli_options_free(options);
    return rc;
}
