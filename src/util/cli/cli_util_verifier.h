/* SPDX-License-Identifier: BSD-3-Clause */
/*****************************************************************************
 * Copyright 2024, Fraunhofer Institute for Secure Information Technology SIT.
 * All rights reserved.
 ****************************************************************************/

/**
 * @file cli_util_verifier.h
 * @author Markus Horn (markus.horn@sit.fraunhofer.de)
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

#ifndef CLI_UTIL_VERIFIER_H
#define CLI_UTIL_VERIFIER_H

#include "cli_util_common.h"

/**
*  @brief parses command line interface arguments
*
* @param argc The number of arguments which were given to the CLI.
* @param argv The arguments which were given to the CLI.
* @param variables A struct holding a caller identifier and pointers to config
                   variables which might get modified depending on the CLI
arguments.
* @return 0 on success, -1 on parse error, 1 when help message was displayed
*/
int parse_command_line_verifier_arguments(int argc, char** argv, cli_config* variables);

#endif /* CLI_UTIL_VERIFIER_H */
