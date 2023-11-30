################################################################################
# Copyright 2023, Fraunhofer Institute for Secure Information Technology SIT.  #
# All rights reserved.                                                         #
# ---------------------------------------------------------------------------- #
# Makefile tpm2-tss code examples.                                             #
# ---------------------------------------------------------------------------- #
# Author:        Michael Eckel <michael.eckel@sit.fraunhofer.de>               #
# Date Modified: 2023-05-30T13:37:42+02:00                                     #
# Date Created:  2023-05-30T13:37:42+02:00                                     #
################################################################################

CC        = gcc
RM        = rm

CFLAGS    = -std=c99 \
            -pedantic \
            -Wall \
            -fdata-sections \
            -ffunction-sections

LDFLAGS   = -L=/usr/local/lib

LIBS      = -ltss2-fapi \
            -ltss2-esys \
            -ltss2-sys \
            -ltss2-mu \
            -ltss2-tcti-device \
            -ltss2-tcti-mssim

SRC_FILES = $(wildcard *.c)
OBJ_FILES = $(SRC_FILES:.c=.o)
TARGETS   = $(OBJ_FILES:.o=)

all: $(TARGETS)

$(TARGETS): $(OBJ_FILES)
	$(CC) $(CFLAGS) $(LDFLAGS) $@.o $(LIBS) -o $@

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	$(RM) -f $(OBJ_FILES) $(TARGETS)

