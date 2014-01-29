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
project (sdbd_tests)

include(FindPkgConfig)
pkg_check_modules(CHECK check>=0.9.8 REQUIRED)

enable_testing()

add_executable(sdbd_tests ../src/commandline_sdbd.c test_commandline_sdbd.c)

set_property(
	TARGET sdbd_tests
	APPEND PROPERTY COMPILE_DEFINITIONS
	_XOPEN_SOURCE
	_GNU_SOURCE
)

include_directories(../src)

include_directories(${CHECK_INCLUDE_DIRS})
target_link_libraries (sdbd_tests ${CHECK_LDFLAGS})

add_test(InternalUnitTests sdbd_tests)
set_tests_properties(InternalUnitTests PROPERTIES
	PASS_REGULAR_EXPRESSION "100%: Checks: [0-9]+, Failures: 0, Errors: 0")
