
DPFS_ROOT_DIR := $(abspath $(CURDIR)/../..)

include $(DPFS_ROOT_DIR)/mk/dpfs.common.mk

CXXHEADER += -I$(DPFS_ROOT_DIR)/thirdparty/dpfsclient/include -I$(DPFS_ROOT_DIR)/thirdparty/Crow/include
CXXLIB += -L$(DPFS_ROOT_DIR)/thirdparty/dpfsclient/lib
CXXFLAG += -g -std=c++2a
CXXLIB += -ldpfs_log -ldpfs_net -ldpfs_tcp -ldpfs_basic -lmydecimal -ldpfs_collect -ldpfs_client -lgrpc++ -lprotobuf -ldpfs_proto -ldpfs_grpc -lcurl


APP := dserver

include $(DPFS_ROOT_DIR)/mk/dpfs.app.mk
