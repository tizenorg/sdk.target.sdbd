/*
 * Copyright (c) 2014 Samsung Electronics Co., Ltd
 *
 * Licensed under the Apache License, Version 2.0 (the License);
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an AS IS BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "commandline_sdbd.h"
#include "sdb.h"

#include <assert.h>
#include <stdlib.h>
#include <stdio.h>

#include <check.h>

/*!
 * @define print_nullable(s)
 * Takes string (<tt>const char *</tt>) and returns it or "(null)" literal
 * in case \c s is NULL.
 */
#define print_nullable(s) \
	(((s) == NULL) ? "(null)" : (s))


/*!
 * @define ck_hostport(hp, h, p)
 * Check if HostPort contains given host and port
 *
 * Host strings are equal if both point to the same address (including NULL)
 * or, provided none of them is NULL, if strcmp() == 0.
 *
 * @param hp \ref HostPort to be checked (<tt>const HostPort *</tt>)
 * @param h hostname (<tt>const char *</tt>) to be checked against
 * @param p port (\c int) to be checked against
 */
#define _ck_hostport(hp, h, p) \
	( (((hp)->host == (h)) \
			|| (((hp)->host) && (h) && (strcmp((hp)->host, (h)) == 0))) \
		&& (hp)->port == (p) )


/*!
 * @define ck_assert_hostport_eq(hp,h,p)
 * Makes assertion against HostPort containing given host and port
 *
 * @param hp \ref HostPort to be checked (<tt>const HostPort *</tt>)
 * @param h hostname (<tt>const char *</tt>) to be checked against
 * @param p port (\c int) to be checked against
 *
 * @see ck_hostport
 */
#define ck_assert_hostport_eq(hp,h,p) \
	(fail_unless(_ck_hostport(hp,h,p), "Assertion failed (%s,%d) != (%s, %d)", \
			print_nullable((hp)->host), (hp)->port, print_nullable(h), (p)))


#define array_size(a) \
    (sizeof(a) / sizeof((a)[0]))


void setup(void) {

}

void teardown(void) {

}


START_TEST(test_all_opts) {
	char *test_argv[] = {
			"./test",
			"--emulator=tizen:101",
			"--listen-port=101",
			"--sensors=localhost:103",
			"--connect-to=localhost:99"
	};

	SdbdCommandlineArgs sdbd_args = {0};

	apply_sdbd_commandline_defaults(&sdbd_args);
	int parse_res = parse_sdbd_commandline(&sdbd_args, array_size(test_argv), test_argv);

	if (parse_res != SDBD_COMMANDLINE_SUCCESS) {
		ck_abort_msg("parsing commandline failed");
		return;
	}

	ck_assert_hostport_eq(&sdbd_args.emulator, "tizen", 101);
	ck_assert_hostport_eq(&sdbd_args.sensors, "localhost", 103);
	ck_assert_hostport_eq(&sdbd_args.sdb, "localhost", 99);
	ck_assert_int_eq(sdbd_args.sdbd_port, 101);

} END_TEST


START_TEST(test_empty) {
	char *test_argv[] = {
			"./test"
	};

	SdbdCommandlineArgs sdbd_args = {0};

	int parse_res = parse_sdbd_commandline(&sdbd_args, array_size(test_argv), test_argv);

	if (parse_res != SDBD_COMMANDLINE_SUCCESS) {
		ck_abort_msg("parsing commandline failed");
		return;
	}

	/* Now check if sdbd_commandline_args was not tainted */
	SdbdCommandlineArgs zero_args;
	memset(&zero_args, 0, sizeof(SdbdCommandlineArgs));
	if (memcmp(&sdbd_args, &zero_args, sizeof(SdbdCommandlineArgs)) != 0) {
		ck_abort_msg("SdbdCommandlineArgs is tainted");
	}

} END_TEST


START_TEST(test_unknown) {
	char *test_argv[] = {
			"./test",
			"--emulator=tizen:26101",
			"--unknown=true"
	};

	SdbdCommandlineArgs sdbd_args = {0};

	int parse_res = parse_sdbd_commandline(&sdbd_args, array_size(test_argv), test_argv);

	if (parse_res != SDBD_COMMANDLINE_FAILURE_UNKNOWN_OPT) {
		ck_abort_msg("parsing commandline failed");
		return;
	}

} END_TEST


START_TEST(test_clear_args) {
	SdbdCommandlineArgs sdbd_args = {0};

	sdbd_args.emulator.host = strdup("emul_host");
	sdbd_args.emulator.port = 123456;
	sdbd_args.sdb.host = strdup("sdb_host");
	sdbd_args.sdb.port = 623451;
	sdbd_args.sensors.host = strdup("sdb_host");
	sdbd_args.sensors.port = 634512;
	sdbd_args.sdbd_port = 543216;

	clear_sdbd_commandline_args(&sdbd_args);

	ck_assert_hostport_eq(&sdbd_args.emulator, NULL, 0);
	ck_assert_hostport_eq(&sdbd_args.sensors, NULL, 0);
	ck_assert_hostport_eq(&sdbd_args.sdb, NULL, 0);
	ck_assert_int_eq(sdbd_args.sdbd_port, 0);
} END_TEST


START_TEST(test_double_clear) {
    SdbdCommandlineArgs sdbd_args = {0};
    clear_sdbd_commandline_args(&sdbd_args);
} END_TEST


START_TEST(test_default_args) {
	SdbdCommandlineArgs sdbd_args = {0};

	apply_sdbd_commandline_defaults(&sdbd_args);

	ck_assert_hostport_eq(&sdbd_args.emulator, NULL, 0);
	ck_assert_hostport_eq(&sdbd_args.sensors, QEMU_FORWARD_IP, DEFAULT_SENSORS_LOCAL_TRANSPORT_PORT);
	ck_assert_hostport_eq(&sdbd_args.sdb, QEMU_FORWARD_IP, DEFAULT_SDB_PORT);
	ck_assert_int_eq(sdbd_args.sdbd_port, DEFAULT_SDB_LOCAL_TRANSPORT_PORT);
} END_TEST


START_TEST(test_usage_message) {
    FILE *stream;
    char *buffer = NULL;
    size_t buf_len = 0;

    stream = open_memstream(&buffer, &buf_len);
    print_sdbd_usage_message(stream);
    fclose(stream);

    // Just check if all options are mentioned in usage message
    ck_assert(strstr(buffer, "--"ARG_EMULATOR_VM_NAME) != NULL);
    ck_assert(strstr(buffer, "--"ARG_SDBD_LISTEN_PORT) != NULL);
    ck_assert(strstr(buffer, "--"ARG_SDB) != NULL);
    ck_assert(strstr(buffer, "--"ARG_SENSORS) != NULL);
    ck_assert(strstr(buffer, "--"ARG_HELP) != NULL);
    ck_assert(strstr(buffer, "--"ARG_USAGE) != NULL);

    free(buffer);
} END_TEST

START_TEST(test_usage) {
    char *test_argv[] = {
            "./test",
            "--usage"
    };

    SdbdCommandlineArgs sdbd_args = {0};

    int parse_res = parse_sdbd_commandline(&sdbd_args, array_size(test_argv), test_argv);
    ck_assert_int_eq(parse_res, SDBD_COMMANDLINE_USAGE);

} END_TEST


START_TEST(test_help) {
    char *test_argv[] = {
            "./test",
            "--help"
    };

    SdbdCommandlineArgs sdbd_args = {0};

    int parse_res = parse_sdbd_commandline(&sdbd_args, array_size(test_argv), test_argv);
    ck_assert_int_eq(parse_res, SDBD_COMMANDLINE_HELP);

} END_TEST


START_TEST(test_help_other_opt) {
    char *test_argv[] = {
            "./test",
            "--listen-port=1234",
            "--help"
    };

    SdbdCommandlineArgs sdbd_args = {0};

    int parse_res = parse_sdbd_commandline(&sdbd_args, array_size(test_argv), test_argv);
    ck_assert_int_eq(parse_res, SDBD_COMMANDLINE_HELP);

} END_TEST


Suite *sdbd_commandline_suite (void) {
	Suite *s = suite_create ("sdbd commandline");

	TCase *tc_core = tcase_create ("Core");
	tcase_add_checked_fixture(tc_core, setup, teardown);
	tcase_add_test (tc_core, test_all_opts);
	tcase_add_test (tc_core, test_empty);
	tcase_add_test (tc_core, test_unknown);
	tcase_add_test (tc_core, test_clear_args);
	tcase_add_test (tc_core, test_double_clear);
	tcase_add_test (tc_core, test_default_args);
	tcase_add_test (tc_core, test_usage_message);
	tcase_add_test (tc_core, test_usage);
	tcase_add_test (tc_core, test_help);
	tcase_add_test (tc_core, test_help_other_opt);
	suite_add_tcase (s, tc_core);

	return s;
}


int run_tests(int print_output) {
	int number_failed;
	Suite *s = sdbd_commandline_suite();
	SRunner *sr = srunner_create (s);
	srunner_run_all (sr, print_output);
	number_failed = srunner_ntests_failed (sr);
	srunner_free (sr);
	return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}


#ifndef COMMANDLINE_SDBD_TESTS_NO_MAIN
int main(int argc, char *argv[]) {
	return run_tests(CK_NORMAL);
}
#endif /* COMMANDLINE_SDBD_TESTS_NO_MAIN */
