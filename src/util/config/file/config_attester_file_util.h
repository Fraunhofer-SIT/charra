/* SPDX-License-Identifier: BSD-3-Clause */
/*****************************************************************************
 * Copyright 2025, Fraunhofer Institute for Secure Information Technology SIT.
 * All rights reserved.
 ****************************************************************************/

/**
 * @file config_attester_file_util.h
 * @author Markus Horn (markus.horn@sit.fraunhofer.de)
 * @brief Provides parsing for attester config files.
 * @version 0.1
 * @date 2025-05-11
 *
 * @copyright Copyright 2024, Fraunhofer Institute for Secure Information
 * Technology SIT. All rights reserved.
 *
 * @license BSD 3-Clause "New" or "Revised" License (SPDX-License-Identifier:
 * BSD-3-Clause).
 */

#ifndef CONFIG_ATTESTER_FILE_UTIL_H
#define CONFIG_ATTESTER_FILE_UTIL_H

#include "../../../common/charra_error.h"
#include "../config_attester_util.h"

/**
 * @brief Loads the attester configuration from a YAML file.
 *
 * @param path The path to the YAML file.
 * @param config The attester configuration structure to populate.
 * @return CHARRA_RC indicating success or failure.
 */
CHARRA_RC load_attester_yaml_config_file(
        const char* const path, config_attester* const config);

#endif  // CONFIG_ATTESTER_FILE_UTIL_H
