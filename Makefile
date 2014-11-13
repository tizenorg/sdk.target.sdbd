#
#
# Makefile for sdbd
#

#
HOST_OS := $(shell uname -s | tr A-Z a-z)

# sdb host tool
# =========================================================

SDBD_SRC_FILES := \
	src/sdb.c \
	src/fdevent.c \
	src/transport.c \
	src/transport_local.c \
	src/transport_usb.c \
	src/sockets.c \
	src/services.c \
	src/file_sync_service.c \
	src/usb_linux_client.c \
	src/utils.c \
	src/socket_inaddr_any_server.c \
	src/socket_local_client.c \
	src/socket_local_server.c \
	src/socket_loopback_client.c \
	src/socket_loopback_server.c \
	src/socket_network_client.c \
	src/sdktools.c \
	src/strutils.c \
	src/init.c \
	src/fileutils.c

SDBD_CFLAGS := -O2 -g -DSDB_HOST=0 -Wall -Wno-unused-parameter
SDBD_CFLAGS += -D_XOPEN_SOURCE -D_GNU_SOURCE
SDBD_CFLAGS += -DHAVE_FORKEXEC -fPIE -D_DROP_PRIVILEGE -D_FILE_OFFSET_BITS=64
SDBD_LFLAGS := -lcapi-system-info -lvconf -lsmack
IFLAGS := -Iinclude -Isrc -I/usr/include/system -I/usr/include/vconf
OBJDIR := bin
INSTALLDIR := usr/sbin

UNAME := $(shell uname -sm)
ifneq (,$(findstring 86,$(UNAME)))
	HOST_ARCH := x86
endif

TARGET_ARCH = $(HOST_ARCH)
ifeq ($(TARGET_ARCH),)
	TARGET_ARCH := arm
endif

ifeq ($(TARGET_ARCH),arm)
	MODULE := sdbd
	SDBD_CFLAGS += -DANDROID_GADGET=1
else
ifeq ($(TARGET_HOST),true)
	MODULE := sdb
else
	MODULE := sdbd
endif
endif

all : $(MODULE)

sdbd : $(SDBD_SRC_FILES)
	mkdir -p $(OBJDIR)
	$(CC) -pthread -o $(OBJDIR)/$(MODULE) $(SDBD_CFLAGS) $(IFLAGS) $(SDBD_SRC_FILES) $(SDBD_LFLAGS)

install :
	mkdir -p $(DESTDIR)/$(INSTALLDIR)
	install $(OBJDIR)/$(MODULE) $(DESTDIR)/$(INSTALLDIR)/$(MODULE)

clean :
	rm -rf $(OBJDIR)/*
