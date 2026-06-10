#  DPFS-License-Identifier: Apache-2.0 license
#  Copyright (C) 2025 LBR.
#  All rights reserved.
#

DPFS_ROOT_DIR := $(abspath $(CURDIR)/../..)

include $(DPFS_ROOT_DIR)/mk/dpfs.common.mk


CXXFLAG += -g
CXXHEADER += -I$(DPFS_ROOT_DIR)/thirdparty/dpfs/include
CXXLIB += -L$(DPFS_ROOT_DIR)/thirdparty/dpfs/lib -lodbc
LIB := $(DPFS_ROOT_DIR)/lib/libdcsys.so
include $(DPFS_ROOT_DIR)/mk/dpfs.lib.mk
