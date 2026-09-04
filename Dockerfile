################################################################################
# Copyright 2023, Fraunhofer Institute for Secure Information Technology SIT.  #
# All rights reserved.                                                         #
# ---------------------------------------------------------------------------- #
# Main Dockerfile for CHARRA.                                                  #
# ---------------------------------------------------------------------------- #
# Author:        Michael Eckel <michael.eckel@sit.fraunhofer.de>               #
# Date Modified: 2023-11-30T13:37:42+02:00                                     #
# Date Created:  2019-06-26T09:23:15+02:00                                     #
# ---------------------------------------------------------------------------- #
# Hint: Check your Dockerfile at https://www.fromlatest.io/                    #
################################################################################


## -----------------------------------------------------------------------------
## --- preamble ----------------------------------------------------------------
## -----------------------------------------------------------------------------

## --- global arguments --------------------------------------------------------

ARG user='bob'
ARG uid=1000
ARG gid=1000

ARG tpm2tss_version='4.2.0'                     # https://github.com/tpm2-software/tpm2-tss
ARG tpm2tools_version='5.8'                     # https://github.com/tpm2-software/tpm2-tools
ARG libcoap_version='release-4.3.5-patches'     # https://github.com/obgm/libcoap
ARG mbedtls_version='v4.2.0'                    # https://github.com/ARMmbed/mbedtls
ARG qcbor_version='v1.6.1'                      # https://github.com/laurencelundblade/QCBOR
ARG tcose_version='v1.2.0'                      # https://github.com/laurencelundblade/t_cose
ARG libyaml_version='0.2.5'                     # https://github.com/yaml/libyaml
ARG pytss_version='3.0.0'                       # https://github.com/tpm2-software/tpm2-pytss
ARG libtpms_version='v0.10.2'                   # https://github.com/stefanberger/libtpms/
ARG swtpm_version='v0.10.2'                     # https://github.com/stefanberger/swtpm/

## -----------------------------------------------------------------------------
## --- base image --------------------------------------------------------------
## -----------------------------------------------------------------------------

FROM ubuntu:24.04 AS base

## --- metadata ----------------------------------------------------------------

LABEL org.opencontainers.image.authors="michael.eckel@sit.fraunhofer.de, markus.horn@sit.fraunhofer.de"

## -----------------------------------------------------------------------------
## --- install dependencies ----------------------------------------------------
## -----------------------------------------------------------------------------

## Basic tools + common build dependencies
RUN apt-get update && apt-get install --no-install-recommends -y \
    bash \
    ca-certificates \
    git \
    automake \
    autoconf \
    libtool \
    build-essential \
    libssl-dev \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*


## -----------------------------------------------------------------------------
## --- library stage -----------------------------------------------------------
## -----------------------------------------------------------------------------

FROM base AS libs

## --- metadata ----------------------------------------------------------------

LABEL org.opencontainers.image.authors="michael.eckel@sit.fraunhofer.de, markus.horn@sit.fraunhofer.de"

## --- image specific arguments ------------------------------------------------

ARG tpm2tss_version
ARG tpm2tools_version
ARG libcoap_version
ARG mbedtls_version
ARG qcbor_version
ARG tcose_version
ARG libyaml_version

ENV LD_LIBRARY_PATH="/usr/local/lib"

# install dependencies for building the libraries
RUN apt-get update && apt-get install --no-install-recommends -y \
    autoconf-archive \
    libcmocka0 \
    libcmocka-dev \
    procps \
    iproute2 \
    uthash-dev \
    doxygen \
    libjson-c-dev \
    libini-config-dev \
    libcurl4-openssl-dev \
    uuid-dev \
    libltdl-dev \
    libusb-1.0-0-dev \
    libftdi-dev \
    cmake \
    python3-pip \
    python3-jinja2 \
    python3-jsonschema \
    && rm -rf /var/lib/apt/lists/*


## TPM2 TSS
RUN git clone --depth=1 --recursive -b "${tpm2tss_version}" \
    'https://github.com/tpm2-software/tpm2-tss.git' /tmp/tpm2-tss \
    && cd /tmp/tpm2-tss \
    && git reset --hard \
    && git clean -xdf \
    && ./bootstrap \
    && ./configure --disable-doxygen-doc \
    && make clean \
    && make -j \
    && make install \
    && ldconfig

## TPM2 tools
RUN git clone --depth=1 --recursive -b "${tpm2tools_version}" \
    'https://github.com/tpm2-software/tpm2-tools.git' /tmp/tpm2-tools \
    && cd /tmp/tpm2-tools \
    && ./bootstrap \
    && ./configure \
    && make -j \
    && make install

## libcoap
RUN git clone --depth=1 --recursive -b "${libcoap_version}" \
    'https://github.com/obgm/libcoap.git' /tmp/libcoap \
    && cd /tmp/libcoap \
    && ./autogen.sh \
    && ./configure \
        CFLAGS="-Du_int32_t=uint32_t -Du_int64_t=uint64_t -Du_int8_t=uint8_t" \
        --disable-tests --disable-documentation --disable-manpages \
        --enable-dtls --with-tinydtls --enable-fast-install \
    && make -j \
    && make install

## Mbed TLS
RUN git clone --depth=1 --recursive -b "${mbedtls_version}" \
    'https://github.com/ARMmbed/mbedtls.git' /tmp/mbedtls \
    && cd /tmp/mbedtls \
    && cmake -DUSE_SHARED_MBEDTLS_LIBRARY=On . \
    && cmake --build . \
    && cmake --install .

## QCBOR
RUN git clone --depth=1 --recursive -b "${qcbor_version}" \
    'https://github.com/laurencelundblade/QCBOR.git' /tmp/qcbor \
    && cd /tmp/qcbor \
    && make -j all so \
    && make install install_so

## t_cose
RUN git clone --depth=1 --recursive -b "${tcose_version}" \
    'https://github.com/laurencelundblade/t_cose.git' /tmp/t_cose \
    && cd /tmp/t_cose \
    && make -j -f Makefile.psa libt_cose.a libt_cose.so \
    && make -f Makefile.psa install install_so

## LibYAML
RUN git clone --depth=1 --recursive -b "${libyaml_version}" \
    'https://github.com/yaml/libyaml.git' /tmp/libyaml \
    && cd /tmp/libyaml \
    && ./bootstrap \
    && ./configure \
    && make -j \
    && make install


## -----------------------------------------------------------------------------
## --- swtpm stage -------------------------------------------------------------
## -----------------------------------------------------------------------------

FROM base AS swtpm

## --- metadata ----------------------------------------------------------------

LABEL org.opencontainers.image.authors="michael.eckel@sit.fraunhofer.de, markus.horn@sit.fraunhofer.de"

## --- image specific arguments ------------------------------------------------

ARG libtpms_version
ARG swtpm_version

ENV LD_LIBRARY_PATH="/usr/local/lib"

## libtpms
RUN git clone --depth=1 --recursive -b "${libtpms_version}" \
    'https://github.com/stefanberger/libtpms.git' /tmp/libtpms \
    && cd /tmp/libtpms \
    && git reset --hard \
    && git clean -xdf \
    && ./autogen.sh --prefix=/usr/local --libdir=/usr/local/lib \
    --with-openssl --with-tpm2 \
    && make -j \
    && make install

# install swtpm dependencies
RUN apt-get update && apt-get install --no-install-recommends -y \
    libtasn1-6-dev \
    libjson-glib-dev \
    iproute2 \
    trousers \
    expect \
    gawk \
    socat \
    libseccomp-dev \
    gnutls-bin \
    gnutls-dev \
    && rm -rf /var/lib/apt/lists/*

# swtpm
RUN git clone --depth=1 --recursive -b "${swtpm_version}" \
    'https://github.com/stefanberger/swtpm.git' \
    /tmp/swtpm \
    && cd /tmp/swtpm \
    && git reset --hard \
    && git clean -xdf \
    && ./autogen.sh --prefix=/usr/local --libdir=/usr/local/lib \
    --with-openssl --with-tpm2 \
    --with-tss-user='tss' --with-tss-group='tss' \
    && make -j \
    && make install


## -----------------------------------------------------------------------------
## --- developer stage ---------------------------------------------------------
## -----------------------------------------------------------------------------

FROM base AS dev


## --- metadata ----------------------------------------------------------------

LABEL org.opencontainers.image.authors="michael.eckel@sit.fraunhofer.de, markus.horn@sit.fraunhofer.de"

## --- image specific arguments ------------------------------------------------

ARG user
ARG uid
ARG gid
ARG pytss_version

ENV LD_LIBRARY_PATH="/usr/local/lib"
ENV PKG_CONFIG_PATH="/usr/local/lib/pkgconfig"
ENV RUSTFLAGS="-C target-feature=-crt-static"

# copy swtpm binaries and libraries from swtpm stage
COPY --from=swtpm "/usr/local" "/usr/local"
# copy compiled libraries an binaries from libs stage
COPY --from=libs "/usr/local" "/usr/local"

## copy configs
COPY "./docker/dist/etc/default/keyboard" "/etc/default/keyboard"

# unminimize the image to get man pages and other documentation
RUN apt-get update && apt-get install --no-install-recommends -y \
    unminimize \
    && rm -rf /var/lib/apt/lists/*
RUN yes | unminimize

## install useful tools (man pages, Bash, debug tools, etc.)
RUN apt-get update && apt-get install --no-install-recommends -y \
    bash \
    bash-doc \
    bash-completion \
    man-db \
    manpages-posix \
    manpages-dev \
    git \
    curl \
    clang \
    python3-pip \
    python3-dev \
    clang-tools \
    cgdb \
    gdb \
    tmux \
    valgrind \
    gosu \
    sudo \
    jq \
    adduser \
    gnutls-bin \
    libjson-glib-1.0-0 \
    libjson-c5 \
    autoconf-archive \
    libcmocka0 \
    libcmocka-dev \
    procps \
    iproute2 \
    uthash-dev \
    doxygen \
    libjson-c-dev \
    libini-config-dev \
    libcurl4-openssl-dev \
    uuid-dev \
    libltdl-dev \
    libusb-1.0-0-dev \
    libftdi-dev \
    && rm -rf /var/lib/apt/lists/*


## -----------------------------------------------------------------------------
## --- install tpm2-pytss ------------------------------------------------------
## -----------------------------------------------------------------------------

ENV PIP_BREAK_SYSTEM_PACKAGES=1

## install tpm2-pytss
RUN python3 -m pip install --no-cache-dir \
    "git+https://github.com/tpm2-software/tpm2-pytss.git@${pytss_version}"


## -----------------------------------------------------------------------------
## --- configuration -----------------------------------------------------------
## -----------------------------------------------------------------------------

## make TPM simulator the default for TCTI loader
RUN ln -sf 'libtss2-tcti-swtpm.so' '/usr/local/lib/libtss2-tcti-default.so'

## add 'tss' user and group
## see: <https://github.com/tpm2-software/tpm2-tss/blob/master/Makefile.am#L841>
RUN bash -c ' \
    if test -z "${DESTDIR}"; then \
    if type -p groupadd > /dev/null; then \
    id -g tss 2>/dev/null || groupadd --system tss; \
    else \
    id -g tss 2>/dev/null || \
    addgroup --system tss; \
    fi && \
    if type -p useradd > /dev/null; then \
    id -u tss 2>/dev/null || \
    useradd --system --home-dir / --shell `type -p nologin` \
    --no-create-home -g tss tss; \
    else \
    id -u tss 2>/dev/null || \
    adduser --system --home / --shell `type -p nologin` \
    --no-create-home --ingroup tss tss; \
    fi; \
    fi \
    '

## create FAPI system folder(s) for
RUN mkdir -p '/usr/local/var/run/tpm2-tss' \
    && chown -R 'root:tss' '/usr/local/var/run/tpm2-tss' \
    && chmod -R g+w '/usr/local/var/run/tpm2-tss'
RUN mkdir -p '/usr/local/var/lib/tpm2-tss' \
    && chown -R 'root:tss' '/usr/local/var/lib/tpm2-tss' \
    && chmod -R g+w '/usr/local/var/lib/tpm2-tss'

## configure TSS FAPI to not check EK certificates since we use a TPM simulator
RUN jq --argjson ekCertLess '{"ek_cert_less":"yes"}' '. += $ekCertLess' \
    '/usr/local/etc/tpm2-tss/fapi-config.json' \
    > '/tmp/fapi-config.json' \
    && cat '/tmp/fapi-config.json' \
    > '/usr/local/etc/tpm2-tss/fapi-config.json' \
    && rm -f '/tmp/fapi-config.json'

## delete default user and create non-root user and grant sudo permission
RUN deluser=$(getent passwd 1000 | cut -d: -f1) \
    && [ -n "$deluser" ] \
    && userdel -r "$deluser" || true \
    && export user="${user}" uid="${uid}" gid="${gid}" \
    && addgroup --gid "${gid}" "${user}" \
    && adduser --home /home/"${user}" --uid "${uid}" --gid "${gid}" \
    --disabled-password --gecos '' "${user}" \
    && mkdir -vp /etc/sudoers.d/ \
    && echo "${user}     ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers.d/"${user}" \
    && chmod 0440 /etc/sudoers.d/"${user}" \
    && chown "${uid}:${gid}" -R /home/"${user}"

## -----------------------------------------------------------------------------
## --- further configuration ---------------------------------------------------
## -----------------------------------------------------------------------------

## configure Bash
COPY "./docker/dist/home/user/.bashrc" "/home/${user}/.bashrc"
COPY "./docker/dist/home/user/.bash_aliases" "/home/${user}/.bash_aliases"
COPY "./docker/dist/home/user/.bash_history" "/home/${user}/.bash_history"

## disable TSS2 logging
ENV TSS2_LOG=all+none
#ENV TSS2_LOGFILE=none

## set TPM2 tools environment variables
ENV TPM2TOOLS_TCTI=swtpm
ENV TPM2TOOLS_TCTI_NAME=socket
ENV TPM2TOOLS_SOCKET_ADDRESS=127.0.0.1
ENV TPM2TOOLS_SOCKET_PORT=2321

## install TPM2 helpers (TPM simulator reset script + TSS compile script)
COPY "./docker/dist/usr/local/bin/tpm-reset" "/usr/local/bin/"
COPY "./docker/dist/usr/local/bin/compile-tss" "/usr/local/bin/"

## add tpm2-tss code examples and test script
COPY "./docker/dist/home/user/code-examples/" "/home/${user}/code-examples/"
COPY "./docker/dist/home/user/test-charra-and-tpm2-tss.sh" "/home/${user}/"
RUN chown -R "${user}:${user}" "/home/${user}"

## Docker entrypoint
COPY "./docker/dist/usr/local/bin/docker-entrypoint.sh" "/usr/local/bin/"
## keep backwards compatibility
RUN ln -s '/usr/local/bin/docker-entrypoint.sh' /

## set environment variables
USER "${uid}:${gid}"
ENV HOME=/home/"${user}"
WORKDIR /home/"${user}"

## -----------------------------------------------------------------------------
## --- user-specific stuff -----------------------------------------------------
## -----------------------------------------------------------------------------

## install Rust toolchain for user
RUN sudo -u "${user}" curl --proto '=https' --tlsv1.2 -sSf \
    'https://sh.rustup.rs' | sh -s -- -y

## -----------------------------------------------------------------------------
## --- postamble ---------------------------------------------------------------
## -----------------------------------------------------------------------------

ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["/bin/bash"]
