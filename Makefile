################################################################################
# Copyright 2023, Fraunhofer Institute for Secure Information Technology SIT.  #
# All rights reserved.                                                         #
# ---------------------------------------------------------------------------- #
# Main Makefile for CHARRA.                                                    #
# ---------------------------------------------------------------------------- #
# Author:        Michael Eckel <michael.eckel@sit.fraunhofer.de>               #
# Date Modified: 2023-05-22T13:37:42+02:00                                     #
# Date Created:  2019-06-26T09:23:15+02:00                                     #
################################################################################


# ------------------------------------------------------------------------------
# --- arguments + variables ----------------------------------------------------
# ------------------------------------------------------------------------------

## TCTI module
## (typically, TCTI implementations are stored at /usr/local/lib/libtss2-*.so*)
TCTI_MODULE ?= tctildr
tcti_module := tss2-$(TCTI_MODULE)

## logging
enable_logging := 1
flags_logging :=
ifeq ($(ENABLE_LOGGING),0)
	enable_logging := 0
	flags_logging := -DCHARRA_LOG_DISABLE
endif

## colored logging
enable_logging_color := 1
flags_logging_color :=
ifeq ($(ENABLE_LOGGING_COLOR),0)
	enable_logging_color := 0
	flags_logging_color := -DCHARRA_LOG_DISABLE_COLOR
endif

## AddressSanitizer (ASan)
enable_address_sanitizer := 0
flags_address_sanitizer :=
ifeq ($(ENABLE_ADDRESS_SANITIZER),)
	enable_address_sanitizer := 0
	flags_address_sanitizer :=
else ifneq ($(ENABLE_ADDRESS_SANITIZER),0)
	enable_address_sanitizer := 1
	flags_address_sanitizer := -fsanitize=address
endif

## LeakSanitizer (LSan)
enable_leak_sanitizer := 0
flags_leak_sanitizer :=
ifeq ($(ENABLE_LEAK_SANITIZER),)
	enable_leak_sanitizer := 0
	flags_leak_sanitizer :=
else ifneq ($(ENABLE_LEAK_SANITIZER),0)
	enable_leak_sanitizer := 1
	flags_leak_sanitizer := -fsanitize=leak
endif

## position-independent code (PIC)
enable_pic := 1
flags_pic := -fPIC
ifeq ($(ENABLE_PIC),0)
	enable_pic := 0
	flags_pic :=
endif

## strip unneeded
enable_stripping := 1
ifeq ($(ENABLE_STRIPPING),0)
	enable_stripping := 0
endif

## link mode
LINK_MODE ?= dynamic
link_mode := $(if $(filter static,$(LINK_MODE)), -static)


# ------------------------------------------------------------------------------
# --- directories --------------------------------------------------------------
# ------------------------------------------------------------------------------

SRCDIR = src
INCDIR = include
OBJDIR = obj
BINDIR = bin


# ------------------------------------------------------------------------------
# --- arguments + flags --------------------------------------------------------
# ------------------------------------------------------------------------------

CFLAGS =     -std=c99 -g -pedantic -Wall -Wextra -Wimplicit-fallthrough \
             -Wno-missing-field-initializers -Wl,--gc-sections \
             -fdata-sections -ffunction-sections \
             $(flags_pic) \
             $(flags_address_sanitizer) \
             $(flags_leak_sanitizer) \
             $(flags_logging) \
             $(flags_logging_color)

LIBINCLUDE = -I/usr/include \
             -I/usr/local/include

LDPATH =     -L/usr/local/lib/ \
             -L/usr/lib/x86_64-linux-gnu

LIBS =       coap-3-tinydtls \
			 yaml \
             qcbor m \
             crypto ssl \
             mbedcrypto \
             util \
             tss2-esys tss2-sys tss2-mu tss2-tctildr \
             $(tcti_module)

LDFLAGS =    $(addprefix -l, $(LIBS))


# ------------------------------------------------------------------------------
# --- sources + targets --------------------------------------------------------
# ------------------------------------------------------------------------------

SOURCES = $(shell find $(SRCDIR) -name '*.c')

INCLUDE = -I$(INCDIR)

OBJECTS =  $(addsuffix .o, $(addprefix $(OBJDIR)/common/, charra_log))
OBJECTS += $(addsuffix .o, $(addprefix $(OBJDIR)/core/, charra_helper charra_key_mgr charra_rim_mgr charra_marshaling))
OBJECTS += $(addsuffix .o, $(addprefix $(OBJDIR)/core/charra_tap/, charra_tap_cbor))
OBJECTS += $(addsuffix .o, $(addprefix $(OBJDIR)/util/, charra_util coap_util crypto_util io_util tpm2_util cli_util parser_util))

TARGETS = $(addprefix $(BINDIR)/, attester verifier)

.PHONY: all attester verifier clean

all: $(TARGETS)
attester: $(BINDIR)/attester
verifier: $(BINDIR)/verifier


# ------------------------------------------------------------------------------
# --- productions --------------------------------------------------------------
# ------------------------------------------------------------------------------

## --- apps --------------------------------------------------------------------

$(BINDIR)/attester: $(SRCDIR)/attester.c $(OBJECTS)
	$(CC) $^ $(CFLAGS) $(INCLUDE) $(LIBINCLUDE) $(LDPATH) $(LDFLAGS) -g -o $@ -Wl,--gc-sections $(link_mode)
ifeq ($(enable_stripping),1)
	strip --strip-unneeded $@
endif

$(BINDIR)/verifier: $(SRCDIR)/verifier.c $(OBJECTS)
	$(CC) $^ $(CFLAGS) $(INCLUDE) $(LIBINCLUDE) $(LDPATH) $(LDFLAGS) -g -o $@ -Wl,--gc-sections $(link_mode)
ifeq ($(enable_stripping),1)
	strip --strip-unneeded $@
endif


## --- objects -----------------------------------------------------------------

$(OBJDIR)/common/%.o: $(SRCDIR)/common/%.c
	@mkdir -p $(@D)
	$(CC) $< $(INCLUDE) $(LIBINCLUDE) $(LDPATH) $(LDFLAGS) $(CFLAGS) -g -o $@ -c $(link_mode)

$(OBJDIR)/core/%.o: $(SRCDIR)/core/%.c
	@mkdir -p $(@D)
	$(CC) $< $(INCLUDE) $(LIBINCLUDE) $(LDPATH) $(LDFLAGS) $(CFLAGS) -g -o $@ -c $(link_mode)

$(OBJDIR)/core/charra_tap/%.o: $(SRCDIR)/core/charra_tap/%.c
	@mkdir -p $(@D)
	$(CC) $< $(INCLUDE) $(LIBINCLUDE) $(LDPATH) $(LDFLAGS) $(CFLAGS) -g -o $@ -c $(link_mode)

$(OBJDIR)/util/%.o: $(SRCDIR)/util/%.c
	@mkdir -p $(@D)
	$(CC) $< $(INCLUDE) $(LIBINCLUDE) $(LDPATH) $(LDFLAGS) $(CFLAGS) -g -o $@ -c $(link_mode)


# ------------------------------------------------------------------------------
# --- clean --------------------------------------------------------------------
# ------------------------------------------------------------------------------

clean:
	$(RM) bin/*
	$(RM) obj/common/*.*
	$(RM) obj/core/*.*
	$(RM) obj/util/*.*
	$(RM) obj/*.*
