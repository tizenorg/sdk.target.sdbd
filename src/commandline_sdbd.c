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

#include <stdio.h>
#include <string.h>
#include <getopt.h>


/*!
 * @fn int split_host_port(const char *optarg, char **host, int *port)
 * @brief Splits string of form \c "localhost:22" into \c host (string)
 *        and \c port (int) parts.
 *
 * @param optarg optarg from getopt
 * @param host Where to put host part string
 * @param port Where to put port part int
 *
 * @returns \ref SDBD_COMMANDLINE_SUCCESS on success
 *          or \ref SDBD_COMMANDLINE_FAILURE otherwise
 */
int split_host_port(const char *optarg, char **host, int *port);

/*!
 * @define print_nullable(s)
 * Takes string (<tt>const char *</tt>) and returns it or "(null)" literal
 * in case \c s is NULL.
 */
#define print_nullable(s) \
    (((s) == NULL) ? "(NULL)" : (s))


static void print_sdbd_command(FILE *stream, SdbdCommandlineArgs *sdbd_args) {
    fprintf(stream, "sdbd_port [%d] \n", sdbd_args->sdbd_port);
    fprintf(stream, "emulator  [%s:%d] \n", print_nullable(sdbd_args->emulator.host), sdbd_args->emulator.port);
    fprintf(stream, "sdb       [%s:%d] \n", print_nullable(sdbd_args->sdb.host), sdbd_args->sdb.port);
    fprintf(stream, "sensors   [%s:%d] \n", print_nullable(sdbd_args->sensors.host), sdbd_args->sensors.port);
}

int parse_sdbd_commandline(SdbdCommandlineArgs *sdbd_args, int argc, char *argv[]) {
	int split_retval;

	int opt;
	int long_index = 0;

	static struct option long_options[] = {
		{ ARG_EMULATOR_VM_NAME, required_argument, NULL, ARG_S_EMULATOR_VM_NAME },
		{ ARG_SENSORS, required_argument, NULL, ARG_S_SENSORS },
		{ ARG_SDB, required_argument, NULL, ARG_S_SDB },
		{ ARG_SDBD_LISTEN_PORT, required_argument, NULL, ARG_S_SDBD_LISTEN_PORT },
		{ ARG_HELP, no_argument, NULL, ARG_S_HELP },
		{ ARG_USAGE, no_argument, NULL, ARG_S_USAGE },
		{ NULL, 0, NULL, 0 }
	};

	optind = 1;	/* the index of the next element to be processed in argv */

	while ((opt = getopt_long(argc, argv, "", long_options, &long_index)) != -1) {
		switch (opt) {
		case ARG_S_EMULATOR_VM_NAME:
			split_retval = split_host_port(optarg,
					&sdbd_args->emulator.host,
					&sdbd_args->emulator.port);
			if (split_retval != SDBD_COMMANDLINE_SUCCESS) {
				return split_retval;
			}
			/* if we are on emulator we listen using local transport
			 * so we should set port to default value but this can
			 * be overwritten by command line options */
			if (sdbd_args->sdbd_port < 0) {
				sdbd_args->sdbd_port = DEFAULT_SDB_LOCAL_TRANSPORT_PORT;
			}
			print_sdbd_command(stdout, sdbd_args);
			break;
		case ARG_S_SENSORS:
			split_retval = split_host_port(optarg,
					&sdbd_args->sensors.host,
					&sdbd_args->sensors.port);
			if (split_retval != SDBD_COMMANDLINE_SUCCESS) {
				return split_retval;
			}
			print_sdbd_command(stdout, sdbd_args);
			break;
		case ARG_S_SDB:
			split_retval = split_host_port(optarg,
					&sdbd_args->sdb.host,
					&sdbd_args->sdb.port);
			if (split_retval != SDBD_COMMANDLINE_SUCCESS) {
				return split_retval;
			}
			print_sdbd_command(stdout, sdbd_args);
			break;
		case ARG_S_SDBD_LISTEN_PORT:
			if (sscanf(optarg, "%d", &sdbd_args->sdbd_port) < 1) {
				return SDBD_COMMANDLINE_FAILURE;
			}
			print_sdbd_command(stdout, sdbd_args);
			break;
		case ARG_S_HELP:
		    return SDBD_COMMANDLINE_HELP;
		case ARG_S_USAGE:
		    return SDBD_COMMANDLINE_USAGE;
		case 1:
			return SDBD_COMMANDLINE_FAILURE_UNKNOWN_OPT;
		case '?':
			return SDBD_COMMANDLINE_FAILURE_UNKNOWN_OPT;
		default:
			return SDBD_COMMANDLINE_FAILURE;
		}
	}

	print_sdbd_command(stdout, sdbd_args);

	return SDBD_COMMANDLINE_SUCCESS;
}


void apply_sdbd_commandline_defaults(SdbdCommandlineArgs *sdbd_args) {
	sdbd_args->emulator.port = -1;

	sdbd_args->sensors.host = strdup(QEMU_FORWARD_IP);
	sdbd_args->sensors.port = DEFAULT_SENSORS_LOCAL_TRANSPORT_PORT;

	sdbd_args->sdb.host = strdup(QEMU_FORWARD_IP);
	sdbd_args->sdb.port = DEFAULT_SDB_PORT;

	// by default don't listen on local transport
	sdbd_args->sdbd_port = -1;
}


int split_host_port(const char *optarg, char **host, int *port) {
	const char *colon = strchr(optarg, ':');
	char *old_val = NULL;

	if (colon) {
		old_val = *host;
		*host = strndup(optarg, colon - optarg);
		if (sscanf(colon + 1, "%d", port) < 1) {
			return SDBD_COMMANDLINE_FAILURE;
		}
	} else {
		return SDBD_COMMANDLINE_FAILURE;
	}

	if (old_val) {
		free(old_val);
	}
	return SDBD_COMMANDLINE_SUCCESS;
}


void clear_sdbd_commandline_args(SdbdCommandlineArgs *sdbd_args) {
    free(sdbd_args->emulator.host);
    sdbd_args->emulator.host = NULL;

    free(sdbd_args->sdb.host);
    sdbd_args->sdb.host = NULL;

    free(sdbd_args->sensors.host);
    sdbd_args->sensors.host = NULL;

	memset(sdbd_args, 0, sizeof(SdbdCommandlineArgs));
}


void print_sdbd_usage_message(FILE *stream) {
    const char *format = "Usage sdbd [OPTION]...\n"
            "\t-%c, --%s=HOST:PORT\temulator's name and forward port\n"
            "\t-%c, --%s=HOST:PORT\thostname or IP and port of sdb listening on host\n"
            "\t-%c, --%s=HOST:PORT \thostname or IP and port of sensors daemon\n"
            "\t-%c, --%s=PORT     \tport on which sdbd shall be listening on\n"
            "\t-%c, --%s              \tprint help message\n"
            "\t-%c, --%s             \tprint this usage message\n"
            ;

    fprintf(stream, format,
            ARG_S_EMULATOR_VM_NAME, ARG_EMULATOR_VM_NAME,
            ARG_S_SDB, ARG_SDB,
            ARG_S_SENSORS, ARG_SENSORS,
            ARG_S_SDBD_LISTEN_PORT, ARG_SDBD_LISTEN_PORT,
            ARG_S_HELP, ARG_HELP,
            ARG_S_USAGE, ARG_USAGE
            );
}
