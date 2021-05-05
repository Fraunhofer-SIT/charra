/* SPDX-License-Identifier: BSD-3-Clause */
/*****************************************************************************
 * Copyright 2021, Fraunhofer Institute for Secure Information Technology SIT.
 * All rights reserved.
 ****************************************************************************/

/**
 * @file command_line_util.c
 * @author Dominik Lorych (dominik.lorych@sit.fraunhofer.de)
 * @brief Provides command line parsing for verifier & attester.
 * @version 0.1
 * @date 2021-02-18
 *
 * @copyright Copyright 2021, Fraunhofer Institute for Secure Information
 * Technology SIT. All rights reserved.
 *
 * @license BSD 3-Clause "New" or "Revised" License (SPDX-License-Identifier:
 * BSD-3-Clause).
 */

#include "cli_util.h"

#include "../common/charra_log.h"
#include "coap_util.h"
#include "io_util.h"
#include <errno.h>
#include <getopt.h>
#include <stdlib.h>

/* command line argument handling */
static const struct option verifier_options[] = {
	{"verbose", no_argument, 0, 'v'}, {"log-level", required_argument, 0, 'l'},
	{"coap-log-level", required_argument, 0, 'c'},
	{"timeout", required_argument, 0, 't'},
	{"pcr-file", required_argument, 0, 'f'},
	{"pcr-selection", required_argument, 0, 's'}, {"psk", no_argument, 0, 'p'},
	{"key", required_argument, 0, 'k'}, {"identity", required_argument, 0, 'i'},
	{"rpk", no_argument, 0, 'r'}, {"help", no_argument, 0, '0'},
	{"private-key", required_argument, 0, '1'},
	{"public-key", required_argument, 0, '2'},
	{"peer-public-key", required_argument, 0, '3'},
	{"verify-peer", required_argument, 0, '4'},
	{"ip", required_argument, 0, 'a'}, {"port", required_argument, 0, 'b'},
	{"ima", optional_argument, 0, 'm'}, {0}};

static const struct option attester_options[] = {
	{"verbose", no_argument, 0, 'v'}, {"log-level", required_argument, 0, 'l'},
	{"coap-log-level", required_argument, 0, 'c'}, {"psk", no_argument, 0, 'p'},
	{"key", required_argument, 0, 'k'}, {"hint", required_argument, 0, 'h'},
	{"rpk", no_argument, 0, 'r'}, {"help", no_argument, 0, '0'},
	{"private-key", required_argument, 0, '1'},
	{"public-key", required_argument, 0, '2'},
	{"peer-public-key", required_argument, 0, '3'},
	{"verify-peer", required_argument, 0, '4'},
	{"port", required_argument, 0, 'b'}, {0}};

int parse_command_line_arguments(int argc, char** argv, cli_config* variables) {
	cli_parser_caller caller = variables->caller;
	char* log_name;
	if (caller == VERIFIER) {
		log_name = "verifier";
	} else {
		log_name = "attester";
	}
	for (;;) {
		int index = -1;
		int identifier = getopt_long(argc, argv,
			((caller == VERIFIER) ? "vl:c:t:f:s:pk:i:r" : "vl:c:pk:h:r"),
			((caller == VERIFIER) ? verifier_options : attester_options),
			&index);

		if (identifier == -1)
			return 0; // end of command line arguments reached

		else if (identifier == '0' || identifier == '?') {
			// print help message
			printf("\nUsage: %s [OPTIONS]\n", log_name);
			printf(
				"     --help:                     Print this help message.\n");
			printf(" -v, --verbose:                  Set CHARRA and CoAP "
				   "log-level "
				   "to DEBUG.\n");
			printf(" -l, --log-level=LEVEL:          Set CHARRA log-level to "
				   "LEVEL. "
				   "Available are: TRACE, DEBUG, INFO, WARN, ERROR, FATAL. "
				   "Default is INFO.\n");
			printf(
				" -c, --coap-log-level=LEVEL:     Set CoAP log-level to LEVEL. "
				"Available are: DEBUG, INFO, NOTICE, WARNING, ERR, CRIT, "
				"ALERT, EMERG, CIPHERS. Default is INFO.\n");
			if (caller == VERIFIER) {
				printf(
					"     --ip=IP:                    Connect to IP instead of "
					"doing the attestation on localhost.\n");
				printf(
					"     --port=PORT:                Connect to PORT instead "
					"of default port %d.\n",
					*(variables->common_config.port));
				printf(
					" -t, --timeout=SECONDS:          Wait up to SECONDS for "
					"the attestation answer. Default is %d seconds.\n",
					*(variables->verifier_config.timeout));
				printf(
					" -f, --pcr-file=PATH:            Read reference PCRs from "
					"PATH. Default path is '%s'\n",
					*(variables->verifier_config.reference_pcr_file_path));
				printf(" -s, --pcr-selection=X1[,X2...]: Specifies which "
					   "PCRs to check on the attester. Each X references one "
					   "PCR. PCR numbers shall be ordered from smallest to "
					   "biggest, comma-seperated\n");
				printf("                                 and without "
					   "whitespace. By default these PCRs are checked: ");
				for (uint32_t i = 0;
					 i < *variables->verifier_config.tpm_pcr_selection_len;
					 i++) {
					printf(
						"%d", variables->verifier_config.tpm_pcr_selection[i]);
					if (i !=
						*variables->verifier_config.tpm_pcr_selection_len - 1) {
						printf(", ");
					}
				}
				printf("\n");
				printf(
					"     --ima[=PATH]:               Request the attester to "
					"include an IMA event log in the attestation response. "
					"By default IMA requests the file\n");
				printf(
					"                                 '%s'. Alternatives can "
					"be "
					"passed.\n",
					*(variables->verifier_config.ima_event_log_path));
				printf("DTLS-PSK Options:\n");
				printf(
					" -p, --psk:                      Enable DTLS protocol "
					"with PSK. "
					"By default the key '%s' and identity '%s' are used.\n",
					*variables->common_config.dtls_psk_key,
					*variables->verifier_config.dtls_psk_identity);
				printf(" -k, --key=KEY:                  Use KEY as pre-shared "
					   "key for DTLS-PSK. Implicitly enables DTLS-PSK.\n");
				printf(
					" -i, --identity=IDENTITY:        Use IDENTITY as identity "
					"for DTLS. Implicitly enables DTLS-PSK.\n");
			} else {
				printf("     --port=PORT:                Open PORT instead of "
					   "port "
					   "%d.\n",
					*(variables->common_config.port));
				printf("DTLS-PSK Options:\n");
				printf(" -p, --psk:                      Enable DTLS protocol "
					   "with PSK. "
					   "By default the key '%s' and hint '%s' are used.\n",
					*variables->common_config.dtls_psk_key,
					*variables->attester_config.dtls_psk_hint);
				printf(" -k, --key=KEY:                  Use KEY as pre-shared "
					   "key for DTLS. Implicitly enables DTLS-PSK.\n");
				printf(" -h, --hint=HINT:                Use HINT as hint for "
					   "DTLS. Implicitly enables DTLS-PSK.\n");
			}
			printf("DTLS-RPK Options:\n");
			printf("                                 Charra includes default "
				   "'keys' in the keys folder, but these are only intended for "
				   "testing. They MUST be changed in actual production "
				   "environments!\n");
			printf(" -r, --rpk:                      Enable DTLS-RPK (raw "
				   "public keys) protocol . The protocol is intended for "
				   "scenarios in which public keys of either attester or "
				   "verifier or both of them are pre-shared.\n");
			printf(
				"     --private-key=PATH:         Specify the path of the "
				"private key used for RPK. Currently only supports DER (ASN.1) "
				"format.\n");
			printf("                                 By default '%s' is used. "
				   "Implicitly enables DTLS-RPK.\n",
				*variables->common_config.dtls_rpk_private_key_path);
			printf(
				"     --public-key=PATH:          Specify the path of the "
				"public key used for RPK. Currently only supports DER (ASN.1) "
				"format.\n");
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

			// return -1 if argument could not be parsed, 1 if help message was
			// called via parameter
			return (identifier == '?') ? -1 : 1;
		}

		else if (identifier == 'v') { // verbose logging
			*(variables->common_config.charra_log_level) = CHARRA_LOG_DEBUG;
			*(variables->common_config.coap_log_level) = LOG_DEBUG;
			continue;
		}

		else if (identifier == 'l') { // set log level for charra
			int result = charra_log_level_from_str(
				optarg, variables->common_config.charra_log_level);
			if (result != 0) {
				charra_log_error("[%s] Error while parsing '-l/--log-level': "
								 "Unrecognized argument %s",
					log_name, optarg);
				return -1;
			}
			continue;
		}

		else if (identifier == 'c') { // set log level for libcoap
			int result = charra_coap_log_level_from_str(
				optarg, variables->common_config.coap_log_level);
			if (result != 0) {
				charra_log_error(
					"[%s] Error while parsing '-c/--coap-log-level': "
					"Unrecognized argument %s",
					log_name, optarg);
				return -1;
			}
			continue;
		}

		else if (identifier == 'b') { // set port
			char* end;
			*(variables->common_config.port) =
				(unsigned int)strtoul(optarg, &end, 10);
			if (*(variables->common_config.port) == 0 || end == optarg) {
				charra_log_error(
					"[%s] Error while parsing '--port': Port could not be "
					"parsed",
					log_name);
				return -1;
			}
			continue;
		}

		else if (identifier == 'p') {
			*variables->common_config.use_dtls_psk = true;
			continue;
		}

		else if (identifier == 'k') {
			*variables->common_config.use_dtls_psk = true;
			uint32_t length = strlen(optarg);
			char* key = malloc(length * sizeof(char));
			strcpy(key, optarg);
			*(variables->common_config.dtls_psk_key) = key;
			continue;
		}

		else if (identifier == 'r') {
			*variables->common_config.use_dtls_rpk = true;
			continue;
		}

		else if (identifier == '1') {
			*variables->common_config.use_dtls_rpk = true;
			char* path = malloc(strlen(optarg));
			strcpy(path, optarg);
			if (check_file_existence(path) == CHARRA_RC_SUCCESS) {
				*(variables->common_config.dtls_rpk_private_key_path) = path;
				continue;
			} else {
				charra_log_error(
					"[%s] DTLS-RPK: private key file '%s' does not exist.",
					log_name, path);
				return -1;
			}
		}

		else if (identifier == '2') {
			*variables->common_config.use_dtls_rpk = true;
			char* path = malloc(strlen(optarg));
			strcpy(path, optarg);
			if (check_file_existence(path) == CHARRA_RC_SUCCESS) {
				*(variables->common_config.dtls_rpk_public_key_path) = path;
				continue;
			} else {
				charra_log_error(
					"[%s] DTLS-RPK: public key file '%s' does not exist.",
					log_name, path);
				return -1;
			}
		}

		else if (identifier == '3') {
			*variables->common_config.use_dtls_rpk = true;
			char* path = malloc(strlen(optarg));
			strcpy(path, optarg);
			if (check_file_existence(path) == CHARRA_RC_SUCCESS) {
				*(variables->common_config.dtls_rpk_peer_public_key_path) =
					path;
				continue;
			} else {
				charra_log_error("[%s] DTLS-RPK: peers' public key file '%s' "
								 "does not exist.",
					log_name, path);
				return -1;
			}
		}

		else if (identifier == '4') {
			if (strcmp("0", optarg) == 0) {
				*variables->common_config.dtls_rpk_verify_peer_public_key =
					false;
			} else if (strcmp("1", optarg) == 0) {
				*variables->common_config.dtls_rpk_verify_peer_public_key =
					true;
			} else {
				charra_log_error("[%s] Error while parsing '--verify-peer': "
								 "'%s' could not be parsed as 0 or 1.",
					log_name, optarg);
				return -1;
			}
			continue;
		}

		if (caller == VERIFIER && identifier == 'a') { // set IP address
			int argument_length = strlen(optarg);
			if (argument_length > 15) {
				charra_log_error(
					"[%s] Error while parsing '--ip': Input too long "
					"for IPv4 address",
					log_name);
				return -1;
			}
			strncpy(variables->verifier_config.dst_host, optarg, 16);
			continue;
		}

		else if (caller == VERIFIER && identifier == 't') {
			char* end;
			*(variables->verifier_config.timeout) =
				(uint16_t)strtoul(optarg, &end, 10);
			if (*(variables->verifier_config.timeout) == 0 || end == optarg) {
				charra_log_error(
					"[%s] Error while parsing '--port': Port could not "
					"be parsed",
					log_name);
				return -1;
			}
			continue;
		}

		else if (caller == VERIFIER && identifier == 'f') {
			uint32_t length = strlen(optarg);
			char* path = malloc(length * sizeof(char));
			strcpy(path, optarg);
			if (check_file_existence(path) == CHARRA_RC_SUCCESS) {
				*(variables->verifier_config.reference_pcr_file_path) = path;
				continue;
			} else {
				charra_log_error(
					"[%s] Reference PCR file ''%s' does not exist.", log_name,
					path);
				return -1;
			}
		}

		else if (caller == VERIFIER && identifier == 's') {
			uint32_t length = strlen(optarg);
			uint8_t* tpm_pcr_selection =
				variables->verifier_config.tpm_pcr_selection;
			uint32_t* tpm_pcr_selection_len =
				variables->verifier_config.tpm_pcr_selection_len;
			for (uint32_t i = 0; i < *tpm_pcr_selection_len; i++) {
				tpm_pcr_selection[i] = 0; // overwrite static config with zeros
										  // in case CLI config uses less PCRs
			}
			*tpm_pcr_selection_len = 0;
			char* number_start = optarg;
			int last_number = -1;
			do {
				char* end = NULL;
				errno = 0;
				uint32_t number = strtoul(number_start, &end, 10);
				if (end == number_start || errno != 0) {
					charra_log_error("[%s] PCR selection could not be "
									 "parsed, parse error at '%s'",
						log_name, number_start);
					return -1;
				} else if (number >= TPM2_MAX_PCRS) {
					charra_log_error(
						"[%s] One PCR from the PCR selection was parsed as "
						"%d, but the TPM2 only has PCRs up to %d.",
						log_name, number, TPM2_MAX_PCRS - 1);
					return -1;
				} else if ((int)number <= last_number) {
					charra_log_error(
						"[%s] PCR selection was detected to not be ordered "
						"from smallest to biggest. Last parsed number %d "
						"is bigger or equal to current number %d.",
						log_name, last_number, number);
					return -1;
				}
				number_start = end + 1;
				tpm_pcr_selection[*tpm_pcr_selection_len] = number;
				(*tpm_pcr_selection_len)++;
				last_number = number;
			} while (number_start < optarg + length);
			continue;
		}

		else if (caller == VERIFIER && identifier == 'i') {
			*variables->common_config.use_dtls_psk = true;
			uint32_t length = strlen(optarg);
			char* identity = malloc(length * sizeof(char));
			strcpy(identity, optarg);
			*(variables->verifier_config.dtls_psk_identity) = identity;
			continue;
		}

		else if (caller == VERIFIER &&
				 identifier == 'm') { // enable request for IMA event log
			*(variables->verifier_config.use_ima_event_log) = true;
			if (optarg != NULL) {
				*(variables->verifier_config.ima_event_log_path) =
					malloc(strlen(optarg) + 1);
				strncpy(*(variables->verifier_config.ima_event_log_path),
					optarg, strlen(optarg));
			}
		}

		else if (caller == ATTESTER && identifier == 'n') {
			*variables->common_config.use_dtls_psk = true;
			uint32_t length = strlen(optarg);
			char* hint = malloc(length * sizeof(char));
			strcpy(hint, optarg);
			*(variables->attester_config.dtls_psk_hint) = hint;
			continue;
		}

		else {
			// undefined behaviour, probably because getopt_long returned an
			// identifier which is not checked here
			charra_log_error(
				"[%s] Error: Undefined behaviour while parsing command line",
				log_name);
			return -1;
		}
	}
}
