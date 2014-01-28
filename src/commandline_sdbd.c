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
 * @arg \c optarg optarg from getopt
 * @arg \c host Where to put host part string
 * @arg \c port Where to put port part int
 *
 * @returns \ref SDBD_COMMANDLINE_SUCCESS on success
 *          or \ref SDBD_COMMANDLINE_FAILURE otherwise
 */
int split_host_port(const char *optarg, char **host, int *port);

int parse_sdbd_commandline(SdbdCommandlineArgs *sdbd_args, int argc, char *argv[]) {
	int split_retval;

	int opt;
	int long_index = 0;

	static struct option long_options[] = {
		{ ARG_EMULATOR_VM_NAME, required_argument, NULL, ARG_S_EMULATOR_VM_NAME },
		{ ARG_SENSORS, required_argument, NULL, ARG_S_SENSORS },
		{ ARG_SDB, required_argument, NULL, ARG_S_SDB },
		{ ARG_SDBD_LISTEN_PORT, required_argument, NULL, ARG_S_SDBD_LISTEN_PORT },
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
			break;
		case ARG_S_SENSORS:
			split_retval = split_host_port(optarg,
					&sdbd_args->sensors.host,
					&sdbd_args->sensors.port);
			if (split_retval != SDBD_COMMANDLINE_SUCCESS) {
				return split_retval;
			}
			break;
		case ARG_S_SDB:
			split_retval = split_host_port(optarg,
					&sdbd_args->sdb.host,
					&sdbd_args->sdb.port);
			if (split_retval != SDBD_COMMANDLINE_SUCCESS) {
				return split_retval;
			}
			break;
		case ARG_S_SDBD_LISTEN_PORT:
			if (sscanf(optarg, "%d", &sdbd_args->sdbd_port) < 1) {
				return SDBD_COMMANDLINE_FAILURE;
			}
			break;
		case 1:
			return SDBD_COMMANDLINE_FAILURE_UNKNOWN_OPT;
		case '?':
			return SDBD_COMMANDLINE_FAILURE_UNKNOWN_OPT;
		default:
			return SDBD_COMMANDLINE_FAILURE;
		}
	}

	return SDBD_COMMANDLINE_SUCCESS;
}


void apply_sdbd_commandline_defaults(SdbdCommandlineArgs *sdbd_args) {
	sdbd_args->sensors.host = strdup(QEMU_FORWARD_IP);
	sdbd_args->sensors.port = DEFAULT_SENSORS_LOCAL_TRANSPORT_PORT;

	sdbd_args->sdb.host = strdup(QEMU_FORWARD_IP);
	sdbd_args->sdb.port = DEFAULT_SDB_PORT;

	sdbd_args->sdbd_port = DEFAULT_SDB_LOCAL_TRANSPORT_PORT;
}


int split_host_port(const char *optarg, char **host, int *port) {
	const char *colon = strchr(optarg, ':');
	char *old_val = NULL;

	if (colon) {
		old_val = *host;
		*host = strndup(optarg, colon - optarg);
		if (sscanf(colon, ":%d", port) < 1) {
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
	if (sdbd_args->emulator.host != NULL) {
		free(sdbd_args->emulator.host);
		sdbd_args->emulator.host = NULL;
	}

	if (sdbd_args->sdb.host != NULL) {
		free(sdbd_args->sdb.host);
		sdbd_args->sdb.host = NULL;
	}

	if (sdbd_args->sensors.host != NULL) {
		free(sdbd_args->sensors.host);
		sdbd_args->sensors.host = NULL;
	}

	memset(sdbd_args, 0, sizeof(SdbdCommandlineArgs));
}
