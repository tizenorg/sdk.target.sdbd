#ifndef COMMANDLINE_SDBD_H
#define COMMANDLINE_SDBD_H

#define ARG_EMULATOR_VM_NAME "emulator"
#define ARG_S_EMULATOR_VM_NAME 'e'

#define ARG_SDBD_LISTEN_PORT "sdbd-port"
#define ARG_S_SDBD_LISTEN_PORT 'p'

#define ARG_SDB "sdb"
#define ARG_S_SDB 's'

#define ARG_SENSORS "sensors"
#define ARG_S_SENSORS 'c'

#define SDBD_COMMANDLINE_SUCCESS 0 ///< Success
#define SDBD_COMMANDLINE_FAILURE -1 ///< Generic failure
#define SDBD_COMMANDLINE_FAILURE_UNKNOWN_OPT -2 ///< Unknown option

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


/*!
 * @fn int parse_sdbd_commandline(SdbdCommandlineArgs *sdbd_args, int argc, char *argv[])
 * @brief Parses commandline and stores result in sdbd_args.
 *
 * @note \c argc and \c argv must be the ones passed to main() function,
 * e.g. have program name as the first value.
 *
 * @arg \c sdbd_args SdbdCommandlineArgs where arguments shall be put
 * @arg \c argc Count of arguments passed to the program (from main())
 * @arg \c argv Array of pointers to the strings, which are program arguments (from main())
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
 * @arg \c sdbd_args SdbdCommandlineArgs where values shall be put
 *
 * @note It won't free old values.
 * @see \ref clear_sdbd_commandline_args
 */
void apply_sdbd_commandline_defaults(SdbdCommandlineArgs *sdbd_args);


/*!
 * @fn void clear_sdbd_commandline_args(SdbdCommandlineArgs *sdbd_args)
 * @brief Frees and clears \c sdbd_args 's members.
 *
 * @arg \c sdbd_args SdbdCommandlineArgs to be cleared
 *
 * @note This function will generate segmentation fault,
 * if string pointers are not allocated and not NULL-ed.
 */
void clear_sdbd_commandline_args(SdbdCommandlineArgs *sdbd_args);

#endif /* COMMANDLINE_SDBD_H */
