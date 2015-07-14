# Copyright (c) 2015 Samsung Electronics Co., Ltd All Rights Reserved
#
#    Licensed under the Apache License, Version 2.0 (the "License");
#    you may not use this file except in compliance with the License.
#    You may obtain a copy of the License at
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS,
#    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    See the License for the specific language governing permissions and
#    limitations under the License.
#
# @file        CMakeLists.txt
# @author
# @brief
#

############################# Check minimum CMake version #####################

CMAKE_MINIMUM_REQUIRED(VERSION 2.6)
PROJECT(sdbd)

############################# cmake packages ##################################

INCLUDE(FindPkgConfig)

############################# compiler flags ##################################

SET(SDBD_SRCS
	src/sdb.c
	src/fdevent.c
	src/transport.c
	src/transport_local.c
	src/transport_usb.c
	src/sockets.c
	src/services.c
	src/file_sync_service.c
	src/usb_linux_client.c
	src/utils.c
	src/socket_inaddr_any_server.c
	src/socket_local_client.c
	src/socket_local_server.c
	src/socket_loopback_client.c
	src/socket_loopback_server.c
	src/socket_network_client.c
	src/sdktools.c
	src/strutils.c
	src/fileutils.c
	)
	
pkg_check_modules(pkgs REQUIRED
    capi-system-info
    vconf
    vasum
    glib-2.0
    dbus-1
    dbus-glib-1
    security-server
 )
 
FOREACH(flag ${pkgs_CFLAGS})
        SET(EXTRA_CFLAGS "${EXTRA_CFLAGS} ${flag}")
ENDFOREACH(flag)

SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${EXTRA_CFLAGS}")

INCLUDE_DIRECTORIES(src)

ADD_DEFINITIONS("-O2 -g -Wall -Wno-unused-parameter -fPIE")
ADD_DEFINITIONS("-DSDB_HOST=0")
ADD_DEFINITIONS("-D_XOPEN_SOURCE")
ADD_DEFINITIONS("-D_GNU_SOURCE")
ADD_DEFINITIONS("-DHAVE_FORKEXEC")
ADD_DEFINITIONS("-D_DROP_PRIVILEGE")
ADD_DEFINITIONS("-D_FILE_OFFSET_BITS=64")

IF (_ARM_TARGET)
    ADD_DEFINITIONS("-DANDROID_GADGET=1")
ENDIF (_ARM_TARGET)

IF(TARGET_ARCH STREQUAL x86)
    ADD_DEFINITIONS("-DTARGET_ARCH_X86")
ELSE()
    ADD_DEFINITIONS("-DTARGET_ARCH_ARM")
ENDIF()

IF(WEARABLE_PROFILE STREQUAL on)
    ADD_DEFINITIONS("-D_WEARABLE")
ENDIF()

find_package(Threads REQUIRED)

ADD_EXECUTABLE(sdbd ${SDBD_SRCS})
TARGET_LINK_LIBRARIES(sdbd -pie -lsmack -lresolv -ldl ${CMAKE_THREAD_LIBS_INIT} ${pkgs_LDFLAGS})

install(TARGETS sdbd DESTINATION /usr/sbin)
