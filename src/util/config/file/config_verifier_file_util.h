/* SPDX-License-Identifier: BSD-3-Clause */
/*****************************************************************************
 * Copyright 2025, Fraunhofer Institute for Secure Information Technology SIT.
 * All rights reserved.
 ****************************************************************************/

/**
 * @file config_verifier_file_util.h
 * @author Markus Horn (markus.horn@sit.fraunhofer.de)
 * @brief Provides parsing for verifier config files.
 * @version 0.1
 * @date 2025-05-11
 *
 * @copyright Copyright 2024, Fraunhofer Institute for Secure Information
 * Technology SIT. All rights reserved.
 *
 * @license BSD 3-Clause "New" or "Revised" License (SPDX-License-Identifier:
 * BSD-3-Clause).
 */

#ifndef CONFIG_VERIFIER_FILE_UTIL_H
#define CONFIG_VERIFIER_FILE_UTIL_H

#include "../../../common/charra_error.h"
#include "../config_verifier_util.h"

/**
 * @brief Loads the verifier configuration from a YAML file.
 *
 * @param path The path to the YAML file.
 * @param config The verifier configuration structure to populate.
 * @return CHARRA_RC indicating success or failure.
 */
CHARRA_RC load_verifier_yaml_config_file(
        const char* const path, config_verifier* const config);

#endif  // CONFIG_VERIFIER_FILE_UTIL_H
