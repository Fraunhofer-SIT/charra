##############################################################################
# "Dockerfile"                                                               #
#                                                                            #
# Author: Michael Eckel <michael.eckel@sit.fraunhofer.de>                    #
# Date: 2019-06-26                                                           #
#                                                                            #
# Hint: Check your Dockerfile at https://www.fromlatest.io/                  #
##############################################################################

## -----------------------------------------------------------------------------
## --- preamble ----------------------------------------------------------------
## -----------------------------------------------------------------------------

## --- global arguments --------------------------------------------------------

ARG tpm2tss_version='4.1.3'                     # https://github.com/tpm2-software/tpm2-tss
ARG tpm2tools_version='5.7'                     # https://github.com/tpm2-software/tpm2-tools
ARG libcoap_version='release-4.3.5-patches'     # https://github.com/obgm/libcoap
ARG mbedtls_version='v4.1.0'                    # https://github.com/ARMmbed/mbedtls
ARG qcbor_version='v1.6.1'                      # https://github.com/laurencelundblade/QCBOR
ARG tcose_version='v1.2.0'                      # https://github.com/laurencelundblade/t_cose
ARG libyaml_version='0.2.5'                     # https://github.com/yaml/libyaml
ARG pytss_version='2.3.0'                       # https://github.com/tpm2-software/tpm2-pytss
ARG libtpms_version='v0.10.2'                   # https://github.com/stefanberger/libtpms/
ARG swtpm_version='v0.10.1'                     # https://github.com/stefanberger/swtpm/

## -----------------------------------------------------------------------------
## --- dependency image --------------------------------------------------------
## -----------------------------------------------------------------------------

FROM alpine:3.24 AS dependencies

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
RUN apk add --update --no-cache \
    bash \
    git \
    automake \
    autoconf  \
    libtool \
    build-base \
    openssl-dev \
    pkgconf \
    autoconf-archive \
    json-c-dev \
    curl-dev \
    util-linux-dev \
    linux-headers \
    cmake \
    python3 \
    py3-pip \
    py3-jinja2 \
    py3-jsonschema \
    && rm -rf /var/cache/apk/*

## TPM2 TSS
RUN git clone --depth=1 -b "${tpm2tss_version}" \
    https://github.com/tpm2-software/tpm2-tss.git /tmp/tpm2-tss \
    && cd /tmp/tpm2-tss \
    && ./bootstrap \
    && ./configure --disable-doxygen-doc \
    && make -j$(nproc) \
    && make install

## TPM2 tools
RUN git clone --depth=1 -b "${tpm2tools_version}" \
    https://github.com/tpm2-software/tpm2-tools.git /tmp/tpm2-tools \
    && cd /tmp/tpm2-tools \
    && ./bootstrap \
    && ./configure \
    && make -j$(nproc) \
    && make install

## libcoap
RUN git clone --recursive -b "${libcoap_version}" \
    https://github.com/obgm/libcoap.git /tmp/libcoap \
    && cd /tmp/libcoap \
    && ./autogen.sh \
    && ./configure \
    CFLAGS="-Du_int32_t=uint32_t -Du_int64_t=uint64_t -Du_int8_t=uint8_t" \
    --disable-tests --disable-documentation --disable-manpages \
    --enable-dtls --with-tinydtls --enable-fast-install \
    && make -j$(nproc) \
    && make install

## mbedtls
RUN git clone --recursive -b "${mbedtls_version}" \
    https://github.com/ARMmbed/mbedtls.git /tmp/mbedtls \
    && cd /tmp/mbedtls \
    && cmake -DUSE_SHARED_MBEDTLS_LIBRARY=On . \
    && cmake --build . \
    && cmake --install .

##  QCBOR
RUN git clone --depth=1 -b "${qcbor_version}" \
    https://github.com/laurencelundblade/QCBOR.git /tmp/qcbor \
    && cd /tmp/qcbor \
    && make -j all so \
    && make install install_so

## t_cose
RUN git clone --depth=1 -b "${tcose_version}" \
    https://github.com/laurencelundblade/t_cose.git /tmp/t_cose \
    && cd /tmp/t_cose \
    && make -j -f Makefile.psa libt_cose.a libt_cose.so \
    && make -f Makefile.psa install install_so

## LibYAML
RUN git clone --depth=1 -b "${libyaml_version}" \
    https://github.com/yaml/libyaml.git /tmp/libyaml \
    && cd /tmp/libyaml \
    && ./bootstrap \
    && ./configure \
    && make -j$(nproc) \
    && make install

## -----------------------------------------------------------------------------
## --- charra-build image ------------------------------------------------------
## -----------------------------------------------------------------------------

FROM dependencies AS charra-build

## --- metadata ----------------------------------------------------------------

LABEL org.opencontainers.image.authors="michael.eckel@sit.fraunhofer.de, markus.horn@sit.fraunhofer.de"

## --- image specific arguments ------------------------------------------------

ENV LD_LIBRARY_PATH="/usr/local/lib"

## compile CHARRA
COPY ./ "/charra"
WORKDIR "/charra"
RUN mkdir bin && make -j

## -----------------------------------------------------------------------------
## --- runtime image -----------------------------------------------------------
## -----------------------------------------------------------------------------

FROM alpine:3.24 AS runtime

## --- metadata ----------------------------------------------------------------

LABEL org.opencontainers.image.authors="michael.eckel@sit.fraunhofer.de, markus.horn@sit.fraunhofer.de"

## --- image specific arguments ------------------------------------------------

ENV LD_LIBRARY_PATH="/usr/local/lib"
ENV TPM2TOOLS_TCTI="device:/dev/tpmrm0"

# install necessary runtime libraries and binaries
RUN apk add --update --no-cache \
    bash \
    libcurl \
    && rm -rf /var/cache/apk/*

# make device TPM the default for TCTI loader
RUN ln -sf 'libtss2-tcti-device.so' '/usr/local/lib/libtss2-tcti-default.so'

# copy libraries
COPY --from=dependencies "usr/local/" "/usr/local/"
# copy CHARRA binaries
COPY --from=charra-build --chmod=555 "/charra/bin/attester" "/usr/local/bin/attester"
COPY --from=charra-build --chmod=555 "/charra/bin/verifier" "/usr/local/bin/verifier"
COPY --from=charra-build --chmod=555 "/charra/generate-ak.sh" "/usr/local/bin/generate-ak.sh"

## -----------------------------------------------------------------------------
## --- postamble ---------------------------------------------------------------
## -----------------------------------------------------------------------------

WORKDIR "/charra"
CMD [ "/bin/bash"]
