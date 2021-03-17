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
#include <getopt.h>
#include <stdlib.h>

/* command line argument handling */
static const struct option verifier_options[] = {{"help", no_argument, 0, 'h'},
	{"verbose", no_argument, 0, 'v'}, {"log-level", required_argument, 0, 'l'},
	{"coap-log-level", required_argument, 0, 'c'},
	{"port", required_argument, 0, 'p'}, {"ip", required_argument, 0, 'i'},
	{"timeout", required_argument, 0, 't'},
	{"pcr-file", required_argument, 0, 'f'}, {0}};

static const struct option attester_options[] = {{"help", no_argument, 0, 'h'},
	{"verbose", no_argument, 0, 'v'}, {"log-level", optional_argument, 0, 'l'},
	{"coap-log-level", optional_argument, 0, 'c'},
	{"port", required_argument, 0, 'p'}, {"ima", optional_argument, 0, 'i'},
	{0}};

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
		int identifier = getopt_long(argc, argv, "hv",
			((caller == VERIFIER) ? verifier_options : attester_options),
			&index);

		if (identifier == -1)
			return 0; // end of command line arguments reached

		if (identifier == 'h' || identifier == '?') {
			// '?' means that an error appeared while parsing
			if (identifier == '?') {
				printf("[%s] Error while parsing argument '%s' or '%s'!\n",
					log_name, argv[index], optarg);
			}
			// print help message
			printf("Usage: %s [OPTIONS]\n", log_name);
			printf(" -h, --help:                 Print this help message.\n");
			printf(" -v, --verbose:              Set CHARRA and CoAP log-level "
				   "to DEBUG.\n");
			printf(
				"     --log-level=LEVEL:      Set CHARRA log-level to LEVEL. "
				"Available are: TRACE, DEBUG, INFO, WARN, ERROR, FATAL. "
				"Default is INFO.\n");
			printf("     --coap-log-level=LEVEL: Set CoAP log-level to LEVEL. "
				   "Available are: DEBUG, INFO, NOTICE, WARNING, ERR, CRIT, "
				   "ALERT, EMERG, CIPHERS. Default is INFO.\n");
			if (caller == VERIFIER) {
				printf("     --ip=IP:                Connect to IP instead of "
					   "doing the attestation on localhost.\n");
				printf("     --port=PORT:            Connect to PORT instead "
					   "of port %d.\n",
					*(variables->common_config.port));
				printf("     --timeout=SECONDS:      Wait up to SECONDS for "
					   "the attestation answer. Default is %d.\n",
					*(variables->verifier_config.timeout));
				printf("     --pcr-file=PATH:        Read reference PCRs from "
					   "PATH. Default path is '%s'\n",
					*(variables->verifier_config.reference_pcr_file_path));
			} else {
				printf("     --port=PORT:            Open PORT instead of port "
					   "%d.\n",
					*(variables->common_config.port));
				printf("     --ima[=PATH]:           Enable attestation of ima "
					   "event logs. "
					   "By default IMA uses the file '%s'. Alternatives can be "
					   "passed.\n",
					*(variables->attester_config.ima_event_log_path));
			}
			printf("To specify TCTI commands for the TPM, set the "
				   "'CHARRA_TCTI' environment variable accordingly.\n");
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
				charra_log_error("[%s] Error while parsing '-l/--log-level': "
								 "Unrecognized argument %s",
					log_name, optarg);
				return -1;
			}
			continue;
		}

		else if (identifier == 'p') { // set port
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

		else if (caller == VERIFIER) {

			if (identifier == 'i') { // set IP address
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

			else if (identifier == 't') {
				char* end;
				*(variables->verifier_config.timeout) =
					(uint16_t)strtoul(optarg, &end, 10);
				if (*(variables->verifier_config.timeout) == 0 ||
					end == optarg) {
					charra_log_error(
						"[%s] Error while parsing '--port': Port could not "
						"be parsed",
						log_name);
					return -1;
				}
				continue;
			}

			else if (identifier == 'f') {
				uint32_t length = strlen(optarg);
				char* path = malloc(length * sizeof(char));
				strcpy(path, optarg);
				if (check_file_existence(path) == CHARRA_RC_SUCCESS) {
					*(variables->verifier_config.reference_pcr_file_path) =
						path;
					continue;
				} else {
					charra_log_error(
						"[%s] Reference PCR file ''%s' does not exist.",
						log_name, path);
					return -1;
				}
			}

		}

		else if (caller == ATTESTER) {

			if (identifier == 'i') { // set IMA event log on
				*(variables->attester_config.use_ima_event_log) = true;
				if (optarg != NULL) {
					*(variables->attester_config.ima_event_log_path) =
						malloc(strlen(optarg) + 1);
					strncpy(*(variables->attester_config.ima_event_log_path),
						optarg, strlen(optarg));
				}
				continue;
			}
		}

		// undefined behaviour, probably because getopt_long returned an
		// identifier which is not checked here
		charra_log_error(
			"[%s] Error: Undefined behaviour while parsing command line",
			log_name);
		return -1;
	}
}
