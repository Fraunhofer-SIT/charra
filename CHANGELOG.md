<!--
################################################################################
# Copyright 2023, Fraunhofer Institute for Secure Information Technology SIT.  #
# All rights reserved.                                                         #
# ---------------------------------------------------------------------------- #
# Author:        Michael Eckel <michael.eckel@sit.fraunhofer.de>               #
# Date Modified: 2023-11-30T13:37:42+02:00                                     #
# Date Created:  2019-06-26T09:23:15+02:00                                     #
################################################################################
-->

# Changelog

The following lists the changes CHARRA received over time.

## Changelog 2023-11-30

* Adjustments to `Dockerfile`:

  * Updated dependencies to latest stable versions

  * Created necessary systems folders for the tpm2-tss Feature API (FAPI)

  * Added tpm2-pytss

  * Disabled TSS2 log messages that were producing (unnecessary and) confusing error messages and warnings

  * Added Bash configuration including aliases and a history (saves time typing the commands to build and run CHARRA by simply using the up/down arrow keys to cycle through the commands)

* Added TPM2 code examples under `~/code-examples`, showcasing the use of the TSS2 ESAPI and FAPI with tpm2-tss (C programming language) and tpm2-pytss (Python programming language)

* Added a script in `~/./test-charra-and-tpm2-tss.sh` for compiling and running CHARRA as well as all code examples.

## Changelog 2023-05-20

* Fixed `Makefile`

* Fixed Docker Compose

* Externalized building and installation instructions into [`INSTALL.md`](INSTALL.md) and the changelog into [`CHANGELOG.md`](CHANGELOG.md).

* Minor adjustments

## Changelog 2021-03-17

* Dynamic memory allocation for QCBOR encoded data using *malloc()*.
  Thanks, @laurencelundblade.

* Fixed some bugs

* Introduced macros for `free()`'ing heap data.

## Changelog 2021-03-16 (v2)

* Added random nonce generation with mbed TLS in Verifier.
  Made it configurable whether to use the TPM or mbed TLS to generate the nonce.

* Added media type CBOR to attestation request in Verifier.
  Credits go to @mrdeep1.

## Changelog 2021-03-16 (v1)

* Updated `README.md` to include building *tpm2software/tpm2-tss* Docker image which CHARRA uses as a basis
  Reason: recently, the official *tpm2software/tpm2-tss* Docker images were removed from [Docker Hub](https://hub.docker.com/r/tpm2software/tpm2-tss)

* Added Docker Compose file and description on how to use it to `README.md`

* Added `.editorconfig` file

* Using most recent stable versions of *tpm2-tss* and *tpm2-tools*

* Added compressed CHARRA SVG logo (`*.svgz`). See [charra-logo.svgz](./charra-logo.svgz)

## Changelog 2021-03-10

* Added support for CoAP large/block-wise data transfers, utilizing latest features of [libcoap](https://github.com/obgm/libcoap).
  This enables CHARRA to send and receive data of arbitrary size.
  Many thanks to @mrdeep1 for developing and fixing block-wise transfers in *libcoap*!

* Console output/logging can be entirely disabled with the `disable-log` Make switch.
  Colored logging can be disabled with the `disable-log-color` Make switch.
  This allows CHARRA to be used in embedded systems.
  Example:

      make disable-log=1
      make disable-log-color=1

* For debugging purposes a Make flag `address-sanitizer` was introduced. Example:

      make address-sanitizer=1

* For TPM operations a custom TCTI module can be used.
  For this purpose, the Make flag `with-tcti` was introduced.
  If not specified, the default is `mssim`.
  Use it like:

      make with-tcti=device

* To reduce the binary size, a Make flag `strip` was introduced.
  It invokes *strip --strip-unneeded* on the resulting binaries.
  Example:

      make strip=1

* Log levels of CHARRA and *libcoap* can now be specified at runtime, e.g.:

      env LOG_LEVEL_CHARRA=TRACE LOG_LEVEL_COAP=DEBUG bin/verifier

  * Supported CHARRA log levels are: `TRACE`, `DEBUG`, `INFO`, `WARN`, `ERROR`, and `FATAL`.

  * Supported *libcoap* log levels are: `EMERG`, `ALERT`, `CRIT`, `ERR`, `WARNING`, `NOTICE`, `INFO`, and `DEBUG`.

* CHARRA `Dockerfile` now uses Ubuntu 20.04 instead of Ubuntu 18.04 as its base image.

* Added tools for debugging to `Dockerfile` (*tmux*, *gdb*, *cgdb*, and *clang-tools*).

* Graceful exit using SIGINT handlers.

* Simplified CoAP handling by introducing wrapper functions for
*libcoap*.

* Updated `README.md`.

* CHARRA now has a logo, see [charra-logo.svg](./charra-logo.svg), [charra-logo.png](./charra-logo.png), and [charra-logo_small.png](./charra-logo_small.png).

## Changelog 2019-09-19

* Initial version

