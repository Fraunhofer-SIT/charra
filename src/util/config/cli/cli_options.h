/* SPDX-License-Identifier: BSD-3-Clause */
/*****************************************************************************
 * Copyright 2025, Fraunhofer Institute for Secure Information Technology SIT.
 * All rights reserved.
 ****************************************************************************/

/**
 * @file cli_options.h
 * @author Markus Horn (markus.horn@sit.fraunhofer.de)
 * @author tpm2-software/tpm2-tools
 * (https://github.com/tpm2-software/tpm2-tools)
 * @brief The source code utilized in this file has been adapted and modified
 * from the tpm2-software/tpm2-tools github repository
 * (https://github.com/tpm2-software/tpm2-tools)
 * @version 0.1
 * @date 2025-03-7
 *
 * @copyright Copyright 2024, Fraunhofer Institute for Secure Information
 * Technology SIT. All rights reserved.
 *
 * @license BSD 3-Clause "New" or "Revised" License (SPDX-License-Identifier:
 * BSD-3-Clause).
 */

#ifndef CLI_OPTIONS_H
#define CLI_OPTIONS_H

#include <getopt.h>
#include <stdbool.h>
#include <stddef.h>

typedef bool (*cli_option_handler)(char key, char* value);
typedef void (*cli_print_usage_handler)(void);

typedef struct {
    cli_print_usage_handler print_usage;
    cli_option_handler on_opt;
    char* short_opts;
    size_t len;
    struct option long_opts[];
} cli_options;

typedef enum cli_option_code {
    cli_option_code_continue = 0,
    cli_option_code_stop = 1,
    cli_option_code_error = -1,
} cli_option_code;

/**
 * @brief Allocates and initializes a new cli_options structure.
 *
 * @param short_opts A string of valid short option characters.
 * @param len The number of long options.
 * @param long_opts An array of struct option defining long options.
 * @param on_opt A function pointer for handling options.
 * @param print_usage A function pointer for printing usage information.
 * @return A pointer to the newly created cli_options structure.
 */
cli_options* cli_options_new(const char* short_opts, size_t len,
        const struct option long_opts[], cli_option_handler on_opt,
        cli_print_usage_handler print_usage);

/**
 * @brief Frees a cli_options structure.
 *
 * @param opts The cli_options structure to free.
 */
void cli_options_free(cli_options* opts);

/**
 * @brief Parses and handles command-line options.
 *
 * @param opts The cli_options structure containing option definitions.
 * @param argc The argument count.
 * @param argv The argument vector.
 * @return A cli_option_code indicating if an error, further processing
 *  or an immediate exit is desired.
 */
cli_option_code cli_handle_options(
        const cli_options* opts, int argc, char** argv);

#endif  // CLI_OPTIONS_H
