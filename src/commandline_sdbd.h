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

#ifndef COMMANDLINE_SDBD_H
#define COMMANDLINE_SDBD_H

#define ARG_EMULATOR_VM_NAME "emulator"
#define ARG_S_EMULATOR_VM_NAME 'e'

#define ARG_SDBD_LISTEN_PORT "listen-port"
#define ARG_S_SDBD_LISTEN_PORT 'l'

#define ARG_SDB "connect-to"
#define ARG_S_SDB 'c'

#define ARG_SENSORS "sensors"
#define ARG_S_SENSORS 's'

#define ARG_HELP "help"
#define ARG_S_HELP 'h'

#define ARG_USAGE "usage"
#define ARG_S_USAGE 'u'

#define SDBD_COMMANDLINE_SUCCESS 0 ///< Success
#define SDBD_COMMANDLINE_FAILURE -1 ///< Generic failure
#define SDBD_COMMANDLINE_FAILURE_UNKNOWN_OPT -2 ///< Unknown option
#define SDBD_COMMANDLINE_HELP 1 ///< Help request
#define SDBD_COMMANDLINE_USAGE 2 ///< Usage message request

/*!
 * @struct HostPort
 * @brief A simple host:port tuple
 */
typedef struct {
	char *host;
	int port;
} HostPort;

/*!
 * @struct SdbdCommandlineArgs
 * @brief Contains all values, which are read from commandline.
 */
typedef struct {
	HostPort emulator; ///< emulator name and forward port
	HostPort sdb; ///< sdb address
	HostPort sensors; ///< sensors address
	int sdbd_port; ///< Port to listen on in tcp mode
} SdbdCommandlineArgs;

#include <stdio.h>

/*!
 * @fn int parse_sdbd_commandline(SdbdCommandlineArgs *sdbd_args, int argc, char *argv[])
 * @brief Parses commandline and stores result in sdbd_args.
 *
 * @note \c argc and \c argv must be the ones passed to main() function,
 * e.g. have program name as the first value.
 *
 * @param sdbd_args SdbdCommandlineArgs where arguments shall be put
 * @param argc Count of arguments passed to the program (from main())
 * @param argv Array of pointers to the strings, which are program arguments (from main())
 *
 * @returns \ref SDBD_COMMANDLINE_SUCCESS on success. On failure one of:
 *  - \ref SDBD_COMMANDLINE_FAILURE
 *  - \ref SDBD_COMMANDLINE_FAILURE_UNKNOWN_OPT
 */
int parse_sdbd_commandline(SdbdCommandlineArgs *sdbd_args, int argc, char **argv);


/*!
 * @fn void apply_sdbd_commandline_defaults(SdbdCommandlineArgs *sdbd_args)
 * @brief Applies default values to \c sdbd_args.
 *
 * @param sdbd_args SdbdCommandlineArgs where values shall be put
 *
 * @note It won't free old values.
 * @see \ref clear_sdbd_commandline_args
 */
void apply_sdbd_commandline_defaults(SdbdCommandlineArgs *sdbd_args);


/*!
 * @fn void clear_sdbd_commandline_args(SdbdCommandlineArgs *sdbd_args)
 * @brief Frees and clears \c sdbd_args 's members.
 *
 * @param sdbd_args SdbdCommandlineArgs to be cleared
 *
 * @note This function will generate segmentation fault,
 * if string pointers are not allocated and not NULL-ed.
 */
void clear_sdbd_commandline_args(SdbdCommandlineArgs *sdbd_args);

/*!
 * @fn void print_usage_message(FILE *stream)
 * @brief Prints usage message to specified \stream
 *
 * @param stream Stream to print to
 */
void print_sdbd_usage_message(FILE *stream);

#endif /* COMMANDLINE_SDBD_H */
