# Copyright (c) 2014 Samsung Electronics Co., Ltd
#
# Licensed under the Apache License, Version 2.0 (the License);
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an AS IS BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


cmake_minimum_required (VERSION 2.8.3)
project (sdbd)

option(USE_FUNCTION_FS "Use FunctionFS" NO)
option(BUILD_UNIT_TESTS "Build unit tests" NO)


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
	src/properties.c
	src/sdktools.c
	src/strutils.c
	src/libsmack.c
	src/init.c
	src/fileutils.c
	src/commandline_sdbd.c
	src/usb_linux_client.c
	src/usb_funcfs_client.c
)

include(FindPkgConfig)

pkg_check_modules(pkgs REQUIRED
    libtzplatform-config
    capi-system-info
    vconf
    glib-2.0
    dbus-1
    dbus-glib-1
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

set_property(
	TARGET sdbd
	PROPERTY COMPILE_DEFINITIONS
	SDB_HOST=0
	_DROP_PRIVILEGE
	_FILE_OFFSET_BITS=64
)

set_property(
	TARGET sdbd
	APPEND PROPERTY COMPILE_DEFINITIONS
	_XOPEN_SOURCE
	_GNU_SOURCE
	HAVE_FORKEXEC
)

if(USE_FUNCTION_FS)
	set_property(
		TARGET sdbd
		APPEND PROPERTY COMPILE_DEFINITIONS
		USB_FUNCFS
	)
endif()

<<<<<<< HEAD
ADD_DEFINITIONS("-fPIE")

include(FindPkgConfig)

# Get capi-system-info
pkg_check_modules(CAPI_SYSTEM_INFO REQUIRED capi-system-info libtzplatform-config)
include_directories(${CAPI_SYSTEM_INFO_INCLUDE_DIRS})

# Get pthreads
find_package(Threads REQUIRED)

# Add libraries (-l...)
target_link_libraries (sdbd -pie ${CMAKE_THREAD_LIBS_INIT} ${CAPI_SYSTEM_INFO_LDFLAGS})

=======
>>>>>>> tizen_2.4_merge
install(TARGETS sdbd DESTINATION /usr/sbin)
install(FILES script/sdbd DESTINATION /etc/init.d)


# Optionally build unit tests binary -- could be helpful during further development
if(BUILD_UNIT_TESTS)
	enable_testing()
	add_subdirectory(test)
endif()
