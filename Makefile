#
#
# Makefile for sdbd
#

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
	src/properties.c \
	src/sdktools.c \
	src/strutils.c \
	src/libsmack.c \
	src/init.c \
	src/fileutils.c

SDBD_CFLAGS := -O2 -g -DSDB_HOST=0 -Wall -Wno-unused-parameter
SDBD_CFLAGS += -D_XOPEN_SOURCE -D_GNU_SOURCE
SDBD_CFLAGS += -DHAVE_FORKEXEC -fPIE -D_DROP_PRIVILEGE -D_FILE_OFFSET_BITS=64
SDBD_LFLAGS := -lcapi-system-info
IFLAGS := -Iinclude -Isrc -I/usr/include/system
OBJDIR := bin
INSTALLDIR := usr/sbin
INITSCRIPTDIR := etc/init.d

MODULE := sdbd

all : $(MODULE)

sdbd : $(SDBD_SRC_FILES)
	mkdir -p $(OBJDIR)
	$(CC) -pthread -o $(OBJDIR)/$(MODULE) $(SDBD_CFLAGS) $(IFLAGS) $(SDBD_SRC_FILES) $(SDBD_LFLAGS)

install :
	mkdir -p $(DESTDIR)/$(INSTALLDIR)
	install $(OBJDIR)/$(MODULE) $(DESTDIR)/$(INSTALLDIR)/$(MODULE)
	mkdir -p $(DESTDIR)/$(INITSCRIPTDIR)
	install script/sdbd $(DESTDIR)/$(INITSCRIPTDIR)/sdbd

clean :
	rm -rf $(OBJDIR)/*
