/* SPDX-License-Identifier: BSD-3-Clause */
/*****************************************************************************
 * Copyright 2025, Fraunhofer Institute for Secure Information Technology SIT.
 * All rights reserved.
 ****************************************************************************/

/**
 * @file cli_options.c
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

#include "cli_options.h"

#include <libgen.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include "../../../common/charra_log.h"

#define CLI_UTIL_HELP 'h'

#define HELP_COL_WIDTH 40
#define LINE_WIDTH 80

static int get_terminal_width(void) {
    struct winsize w;

    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &w) == -1) {
        return LINE_WIDTH;  // set default value
    }

    if (w.ws_col <= HELP_COL_WIDTH) {
        return LINE_WIDTH;  // prevent one letter per line
    }

    return w.ws_col;
}

static void newline_with_indent(int indent, int* col) {
    putchar('\n');
    printf("%*s", indent, "");
    *col = indent;
}

static int word_length(const char* text) {
    int len = 0;

    while (text[len] && text[len] != ' ' && text[len] != '\t' &&
            text[len] != '\n') {
        len++;
    }

    return len;
}

static void print_split_word(
        const char* word, int len, int line_width, int indent, int* col) {
    for (int i = 0; i < len; i++) {

        if (*col >= line_width) {
            newline_with_indent(indent, col);
        }

        putchar(word[i]);
        (*col)++;
    }
}

static void print_word(
        const char* word, int len, int line_width, int indent, int* col) {
    int max_word_len = line_width - indent;

    if (len <= max_word_len) {

        if (*col > indent && *col + len > line_width) {
            newline_with_indent(indent, col);
        }

        fwrite(word, 1, len, stdout);
        *col += len;
    }
    // Word too long to fit in one line
    else {
        print_split_word(word, len, line_width, indent, col);
    }
}

static void print_wrapped_text(const char* text, int indent, int line_width) {
    int col = indent;

    while (*text) {

        switch (*text) {

        case '\n':
            newline_with_indent(indent, &col);
            text++;
            break;

        case ' ':
        case '\t':
            if (col >= line_width) {
                newline_with_indent(indent, &col);
            } else {
                putchar(*text);
                col++;
            }
            text++;
            break;

        default: {
            int len = word_length(text);

            print_word(text, len, line_width, indent, &col);

            text += len;
            break;
        }
        }
    }

    putchar('\n');
}

void print_option(char short_opt, const char* long_opt, const char* arg,
        const char* description_fmt, ...) {
    char option_buf[256] = {0};
    char description_buf[2048] = {0};
    int option_len = 0;

    if (long_opt == NULL) {
        goto print_description;
    }

    if (short_opt != CLI_UTIL_NO_SHORT_OPT) {
        snprintf(option_buf, sizeof(option_buf), " -%c, --%s%s%s:", short_opt,
                long_opt, arg ? "=" : "", arg ? arg : "");
    } else {
        snprintf(option_buf, sizeof(option_buf), "     --%s%s%s:", long_opt,
                arg ? "=" : "", arg ? arg : "");
    }

    printf("%s", option_buf);

print_description:

    option_len = (int)strlen(option_buf);

    if (option_len < HELP_COL_WIDTH) {
        printf("%*s", HELP_COL_WIDTH - option_len, "");
    } else {
        printf("\n%*s", HELP_COL_WIDTH, "");
    }

    va_list args;

    va_start(args, description_fmt);

    vsnprintf(description_buf, sizeof(description_buf), description_fmt, args);

    va_end(args);

    print_wrapped_text(description_buf, HELP_COL_WIDTH, get_terminal_width());
}

/* strdup is no c99 function */
static char* string_clone(const char* const str) {
    if (str == NULL) {
        return NULL;
    }

    size_t len = strlen(str) + 1;  // +1 for null terminator
    char* clone = malloc(len);

    if (clone != NULL) {
        strncpy(clone, str, len);
    }
    return clone;
}

cli_options* cli_options_new(const char* short_opts, size_t len,
        const struct option long_opts[], cli_option_handler on_opt,
        cli_print_usage_handler print_usage) {
    const size_t long_opts_size = sizeof(struct option) * len;
    cli_options* opts = calloc(1, sizeof(cli_options) + long_opts_size);
    if (opts == NULL) {
        return NULL;
    }

    /* replace NULL with empty string to avoid further NULL checks */
    if (short_opts == NULL) {
        short_opts = "";
    }

    opts->short_opts = string_clone(short_opts);
    if (opts->short_opts == NULL) {
        free(opts);
        return NULL;
    }

    opts->on_opt = on_opt;
    opts->print_usage = print_usage;
    opts->len = len;
    memcpy(opts->long_opts, long_opts, long_opts_size);

    return opts;
}

void cli_options_free(cli_options* opts) {
    if (opts == NULL) {
        return;
    }

    free(opts->short_opts);
    free(opts);
}

cli_option_code cli_handle_options(
        const cli_options* opts, int argc, char** argv) {
    bool show_help = false;
    cli_option_code rc = cli_option_code_continue;
    bool result = false;

    /* Parse the options, calling the tool callback if unknown */
    optind = 1;
    int c;
    while (true) {
        c = getopt_long(argc, argv, opts->short_opts, opts->long_opts, NULL);
        switch (c) {
        case CLI_UTIL_HELP:
            show_help = true;
            rc = cli_option_code_stop;
            goto out;
        case '?':
            rc = cli_option_code_error;
            goto out;
        case -1:
            goto out;
        default:
            /* NULL on_opt handler and unknown option specified is an error */
            if (!opts || !opts->on_opt) {
                charra_log_error("Unknown option found: %c", c);
                rc = cli_option_code_error;
                goto out;
            }
            result = opts->on_opt(c, optarg);
            if (!result) {
                rc = cli_option_code_error;
                goto out;
            }
        }
    }

out:
    /* Print usage if help was requested or an error occurred while parsing. */
    if (show_help || rc == cli_option_code_error) {
        if (!opts->print_usage) {
            charra_log_error("no print_usage function provided");
            return cli_option_code_error;
        }
        opts->print_usage();
    }

    return rc;
}
