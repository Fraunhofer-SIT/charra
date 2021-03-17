# CHARRA: CHAllenge-Response based Remote Attestation with TPM 2.0

![CHARRA Logo](charra-logo_small.png)

This is a proof-of-concept implementation of the "Challenge/Response Remote Attestation" interaction model of the [IETF RATS](https://datatracker.ietf.org/wg/rats/about/) [Reference Interaction Models for Remote Attestation Procedures](https://datatracker.ietf.org/doc/draft-ietf-rats-reference-interaction-models/) using TPM 2.0. The [IETF Remote Attestation Procedures (RATS)](https://datatracker.ietf.org/wg/rats/about/) working group standardizes formats for describing assertions/claims about system components and associated evidence; and procedures and protocols to convey these assertions/claims to relying parties. Given the security and privacy sensitive nature of these assertions/claims, the working group specifies approaches to protect this exchanged data.

This proof-of-concept implementation realizes the Attesting Computing Environment—a Computing Environment capable of monitoring and attesting a target Computing Environment—as well as the target Computing Environment itself, as described in the [RATS Architecture](https://datatracker.ietf.org/doc/draft-ietf-rats-architecture/).

## Changelog 2021-03-17

* Dynamic memory allocation for QCBOR encoded data using *malloc()*.
  Thanks, @laurencelundblade.

* Fixed some bugs.

* Introduced macros for `free()`'ing heap data.

## Changelog 2021-03-16 (v2)

* Added random nonce generation with mbed TLS in Verifier.
  Made it configurable whether to use the TPM or mbed TLS to generate the nonce.

* Added media type CBOR to attestation request in Verifier.
  Credits go to @mrdeep1.

## Changelog 2021-03-16 (v1)

* Updated `README.md` to include building *tpm2software/tpm2-tss* Docker image which CHARRA uses as a basis.
  Reason: recently, the official *tpm2software/tpm2-tss* Docker images were removed from [Docker Hub](https://hub.docker.com/r/tpm2software/tpm2-tss).

* Added Docker Compose file and description on how to use it to `README.md`.

* Added `.editorconfig` file.

* Using most recent stable versions of *tpm2-tss* and *tpm2-tools*.

* Added compressed CHARRA SVG logo (`*.svgz`). See [charra-logo.svgz](./charra-logo.svgz).

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

## Next Steps

* Allow verifier to perform periodic attestations, e.g. perform attestation every 10 seconds.
* Update documentation. Perhaps externalize building and installation into `INSTALL.md`.
* Refactor and implement forward-declared (but not yet implemented) functions.
* Use non-zero reference PCRs.
* "Extended" *TPM Quote* using TPM audit session(s) and *TPM PCR Read* operations.
* Make CHARRA a library (`libcharra`) and make *attester* and *verifier* example code in `example` folder.
* Add `*_free()` functions for all data transfer objects (DTOs).
* Introduce semantic versioning as CHARRA develops along the way to become stable.

*The order of the list is entirely arbitrary and does not reflect any priorities.*

## How it Works: Protocol Flow

The following diagram shows the protocol flow of the CHARRA attestation process.

    .----------.                                    .----------.
    | Attester |                                    | Verifier |
    '----------'                                    '----------'
         |                                                |
         | <----- requestAttestation(nonce, keyID, pcrSelection)
         |                                                |
    tpmQuote(nonce, pcrSelection)                         |
         | => evidence                                    |
         |                                                |
     evidence ------------------------------------------> |
         |                                                |
         |      appraiseEvidence(evidence, nonce, referencePcrs)
         |                           attestationResult <= |
         |                                                |

## Build and Run

CHARRA comes with a Docker test environment and Docker helper scripts to build and run it in Docker.
It is also possible to build and run CHARRA manually.
All commands assume to be executed in [Bash](https://www.gnu.org/software/bash/), the Bourne-again shell.

### Using Docker

Running CHARRA in Docker is the "quickstart" way of running it.
This way, you do not need to install all the dependencies into your system in order to try CHARRA.
All steps to get it up and running are described in the following.

#### Build the Docker Base Image

The CHARRA `Dockerfile` uses on the official [*tpm2software/tpm2-tss* Docker images](https://github.com/tpm2-software/tpm2-software-container.git) as a basis.
Recently, these official images were removed from [Docker Hub](https://hub.docker.com/r/tpm2software/tpm2-tss>).
That is why the Docker base image for CHARRA must now be built manually.

1. Install [Docker](https://docs.docker.com/engine/install/).

2. Install dependencies (*make* and *m4*):

       ## On Ubuntu
       sudo apt install make m4

       ## On Fedora
       sudo dnf install make m4

3. Clone the [TPM2 Software Container](https://github.com/tpm2-software/tpm2-software-container) repository:

       git clone 'https://github.com/tpm2-software/tpm2-software-container.git' \
           'tmp/tpm2-software-container'
       pushd 'tmp/tpm2-software-container'

4. Create `*.docker` files:

       make

5. Build Docker image:

       docker build -t 'tpm2software/tpm2-tss:ubuntu-20.04' -f ubuntu-20.04.docker .
       popd

#### Build the CHARRA Docker Image using Docker Compose

1. Install [Docker Compose](https://docs.docker.com/compose/install/).

2. Build the CHARRA image(s):

       docker-compose build --build-arg uid="$UID" --build-arg gid="$UID"

3. Run the CHARRA container:

       docker-compose run --rm charra-dev-env

<!-- TODO: Uncomment this when verified that it works
### Run CHARRA Apps in Docker Compose

    docker-compose run --rm -T charra-attester &
    docker-compose run --rm -T charra-verifier
-->

#### Build the CHARRA Docker Image using Docker

1. Build CHARRA Docker image:

       ./docker/build.sh

2. Run CHARRA Docker container:

       ./docker/run.sh

#### Compile and Run CHARRA

1. Compile CHARRA (inside container):

       cd charra/
       make -j

2. Run CHARRA (inside container):

       (bin/attester &); sleep .2 ; bin/verifier ; sleep 1 ; pkill -SIGINT attester

If you see "ATTESTATION SUCCESSFUL" you're done. Congratz :-D

### Compile and Run Manually

The provided `Dockerfile` lets you quickly test CHARRA in a Docker environment.
If you want to run CHARRA bare metal, please refer to this guide here.

#### Compile

The `Dockerfile` provides details on installing all dependencies and should be considered authoritative over this.

1. Install all dependencies that are needed for the [TPM2 TSS](https://github.com/tpm2-software/tpm2-tss/blob/master/INSTALL.md).

2. Install *libcoap*:

       git clone --depth=1 --recursive -b 'develop' \
           'https://github.com/obgm/libcoap.git' /tmp/libcoap
       cd /tmp/libcoap
       ./autogen.sh
       ./configure --disable-tests --disable-documentation \
           --disable-manpages --disable-dtls --disable-shared \
           --enable-fast-install
       make -j
       make install

   Make sure that you do not have `libcoap-1-0-dev` installed, as the headers might conflict.

3. Install *mbedtls*:

       git clone --depth=1 --recursive -b 'development' \
           'https://github.com/ARMmbed/mbedtls.git' /tmp/mbedtls
       cd /tmp/mbedtls
       make -j lib SHARED=true
       make install

4. Install *QCBOR*:

       git clone --depth=1 --recursive -b 'master' \
           'https://github.com/laurencelundblade/QCBOR.git' /tmp/qcbor
       cd /tmp/qcbor
       make -j all so
       make install install_so

5. Install *t_cose*:

       git clone --depth=1 --recursive -b 'master' \
           'https://github.com/laurencelundblade/t_cose.git' /tmp/t_cose
       cd /tmp/t_cose
       make -j -f Makefile.psa libt_cose.a libt_cose.so
       make -f Makefile.psa install install_so

6. Compile programs:

       make -j

#### Further Preparation

1. Download and install [IBM's TPM 2.0 Simulator](https://sourceforge.net/projects/ibmswtpm2/).

2. Download and install the [TPM2 Tools](https://github.com/tpm2-software/tpm2-tools).

#### Run

1. Start the TPM Simulator (and remove the state file `NVChip`):

       (cd /tmp ; pkill tpm_server ; rm -f NVChip; /usr/local/bin/tpm_server > /dev/null &)

2. Send TPM *startup* command:

       /usr/local/bin/tpm2_startup -Tmssim --clear

3. Run Attester and Verifier:

       (bin/attester &); sleep .2 ; bin/verifier ; sleep 1 ; pkill -SIGINT -f bin/attester

If you see "ATTESTATION SUCCESSFUL" you're done. Congratz :-D

## Debugging

* Clang `scan-build`:

      make clean ; scan-build make

* Valgrind:

      (valgrind --leak-check=full \
          --show-leak-kinds=all -v \
          bin/attester \
          2> attester-valgrind-stderr.log &); \
      sleep .2 ; \
      (valgrind --leak-check=full \
          --show-leak-kinds=all -v \
          bin/verifier\
          2> verifier-valgrind-stderr.log) ;\
      sleep 1 ; \
      pkill -SIGINT -f bin/attester

* AddressSanitizer:

      make clean ; make address-sanitizer=1
      (bin/attester &); sleep .2 ; bin/verifier ; sleep 1 ; pkill -SIGINT -f bin/attester

  This Make flag is part of the CHARRA `Makefile` and adds the `-fsanitize=address` argument to `CFLAGS` and `LDFLAGS`.

## Run Attester and Verifier on different Devices

The attester and verifier can be used on two different devices.
To do that, you have to provide an external network for the attester Docker container.

1. Create [macvlan network](https://docs.docker.com/network/macvlan/) for attester Docker container (check your gateway address and replace `x` with the correct number):

       docker network create -d macvlan \
           --subnet=192.168.x.0/24 \
           --gateway=192.168.x.1 \
           -o parent=eth0 pub_net

2. Add `--network` parameter to the `docker run` command in the `docker/run.sh` on the attester device:

       ## run (transient) Docker container
       /usr/bin/docker run --rm -it \
           -v "${PWD}/:/home/bob/charra" \
           --network=pub_net \
           "${docker_image_fullname}" \
           "$@"

3. Run the attester Docker container and check the IP address.

4. Put the attester address to the `DST_HOST` in `src/verifier.c` on the verifier device.
   Rebuild verifier script in the verifier docker container:

       cd charra
       make -j

5. Go to `charra` directory and run attester binary in the attester docker container:

       cd charra
       bin/attester

6. Run the verifier binary in the verifier docker container:

       /bin/verifier

If you see "ATTESTATION SUCCESSFUL" you're done. Congratz :-D
