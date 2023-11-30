#!/usr/bin/python3
# -*- coding: utf-8 -*-

"""
SPDX-License-Identifier: BSD-3-Clause */
********************************************************************************
Copyright 2023, Fraunhofer Institute for Secure Information Technology SIT.
All rights reserved.
********************************************************************************
"""

__doc__ = """
Demonstrates the usage of the tpm2-pytss Enhanced System API (ESAPI).
"""
__author__ = "Michael Eckel"
__email__ = "michael.eckel@sit.fraunhofer.de"
__version__ = "1.0"
__copyright__ = """
Copyright 2023, Fraunhofer Institute for Secure Information Technology SIT.
All rights reserved.
"""
__license__ = """
BSD 3-Clause 'New' or 'Revised' License (SPDX-License-Identifier: BSD-3-Clause)
"""
__date__ = "2023-11-27"

import sys
from tpm2_pytss import TSS2_Exception
from tpm2_pytss.ESAPI import ESAPI

DEFAULT_RANDOM_LEN: int = 20

def main() -> None:
    try:
        # read CLI argument
        random_len: int = get_sysarg_random_len(DEFAULT_RANDOM_LEN)

        # initialize ESAPI
        esapi: ESAPI = ESAPI()

        # produce random numbers
        random_bytes = esapi.get_random(random_len)

        # print random bytes in hex
        random_bytes_hex = random_bytes.buffer.hex()
        #print(f"Random bytes: {random_data}")
        print(f"{random_bytes_hex}")

    except TSS2_Exception as e:
        print(f"Error: {e}")

def get_sysarg_random_len(arg_random_len: int = DEFAULT_RANDOM_LEN) -> bytes:
    random_len = arg_random_len

    if len(sys.argv) > 1:
        try:
            random_len = int(sys.argv[1])
        except ValueError:
            pass

    return random_len

if __name__ == '__main__':
    main()
