/* SPDX-License-Identifier: BSD-3-Clause */
/*****************************************************************************
 * Copyright 2024, Fraunhofer Institute for Secure Information Technology SIT.
 * All rights reserved.
 ****************************************************************************/

/**
 * @file cli_util_attester.h
 * @author Markus Horn (markus.horn@sit.fraunhofer.de)
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

#ifndef CLI_UTIL_ATTESTER_H
#define CLI_UTIL_ATTESTER_H

#include "../config_attester_util.h"
#include "cli_options.h"

/**
 *  @brief parses command line interface arguments
 *
 * @param argc The number of arguments which were given to the CLI.
 * @param argv The arguments which were given to the CLI.
 * @param variables A struct holding a caller identifier and pointers to config
 *                   variables which might get modified depending on the CLI
 *  arguments.
 * @return  A cli_option_code indicating if an error, further processing
 *  or an immediate exit is desired.
 */
cli_option_code charra_parse_command_line_attester_arguments(
        const int argc, char** const argv, config_attester* const variables);

/**
 * @brief Prints the help message for the attester CLI options.
 */
void charra_cli_util_attester_print_help_message(void);

#endif /* CLI_UTIL_ATTESTER_H */
