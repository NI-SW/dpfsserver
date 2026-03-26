#  DPFS-License-Identifier: BSD-3-Clause
#  Copyright (C) 2025 Libr Corporation.
#  All rights reserved.
#

DPFS_ROOT_DIR := $(abspath $(CURDIR)/..)

SUBDIRS := deepseek dcsystem
# $(DPFS_ROOT_DIR)/include/parser parser

all clean::
	@for subdir in $(SUBDIRS); \
	do \
	echo "making $@ in $$subdir"; \
	( cd $$subdir && $(MAKE) $@ ); \
	done
