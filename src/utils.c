/*
 * Copyright (c) 2011 Samsung Electronics Co., Ltd All Rights Reserved
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

#include "utils.h"
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/wait.h>
#include <errno.h>

#define STRING_MAXLEN 1024
char*
buff_addc (char*  buff, char*  buffEnd, int  c)
{
    int  avail = buffEnd - buff;

    if (avail <= 0)  /* already in overflow mode */
        return buff;

    if (avail == 1) {  /* overflowing, the last byte is reserved for zero */
        buff[0] = 0;
        return buff + 1;
    }

    buff[0] = (char) c;  /* add char and terminating zero */
    buff[1] = 0;
    return buff + 1;
}

char*
buff_adds (char*  buff, char*  buffEnd, const char*  s)
{
    int  slen = strlen(s);

    return buff_addb(buff, buffEnd, s, slen);
}

char*
buff_addb (char*  buff, char*  buffEnd, const void*  data, int  len)
{
    int  avail = (buffEnd - buff);

    if (avail <= 0 || len <= 0)  /* already overflowing */
        return buff;

    if (len > avail)
        len = avail;

    memcpy(buff, data, len);

    buff += len;

    /* ensure there is a terminating zero */
    if (buff >= buffEnd) {  /* overflow */
        buff[-1] = 0;
    } else
        buff[0] = 0;

    return buff;
}

char*
buff_add  (char*  buff, char*  buffEnd, const char*  format, ... )
{
    int      avail;

    avail = (buffEnd - buff);

    if (avail > 0) {
        va_list  args;
        int      nn;

        va_start(args, format);
        nn = vsnprintf( buff, avail, format, args);
        va_end(args);

        if (nn < 0) {
            /* some C libraries return -1 in case of overflow,
             * but they will also do that if the format spec is
             * invalid. We assume SDB is not buggy enough to
             * trigger that last case. */
            nn = avail;
        }
        else if (nn > avail) {
            nn = avail;
        }

        buff += nn;

        /* ensure that there is a terminating zero */
        if (buff >= buffEnd)
            buff[-1] = 0;
        else
            buff[0] = 0;
    }
    return buff;
}

char *str_trim(const char* string)
{
    const char* s = string;
    const char* e = string + (strlen(string) - 1);
    char* ret;

    while(*s == ' ' || *s == '\t') // ltrim
        s++;
    while(*e == ' ' || *e == '\t') // rtrim
        e--;

    ret = strdup(s);
    if(ret == NULL) {
        return NULL;
    }
    ret[e - s + 1] = 0;

    return  ret;
}

int spawn(char* program, char** arg_list)
{
    pid_t pid;
    int ret;

    if ((pid = fork()) < 0) {
        fprintf(stderr, "couldn't fork: %d\n", errno);
        exit(1);
    } else if (pid == 0) {
            if ((pid = fork()) < 0) {
                fprintf(stderr, "couldn't fork: %d\n", errno);
                exit(1);
            } else if (pid > 0) {
                // init takes the process, and the process is not able to be zombie
                exit(0);
            }
            execvp (program, arg_list);
            fprintf(stderr, "failed to spawn: never reach here!:%s\n", program);
            exit(0);
    }
    if (waitpid(pid, &ret, 0) != pid) {
        fprintf(stderr, "failed to wait pid\n");
    }

    return pid;
}

char** str_split(char* a_str, const char a_delim) {
	char** result = 0;
	size_t count = 0;
	char* tmp = a_str;
	char* last_comma = 0;
	char delim[2];
	delim[0] = a_delim;
	delim[1] = 0;
	char *ptr;

	/* Count how many elements will be extracted. */
	while (*tmp) {
		if (a_delim == *tmp) {
			count++;
			last_comma = tmp;
		}
		tmp++;
	}

	/* Add space for trailing token. */
	count += last_comma < (a_str + strlen(a_str) - 1);

	/* Add space for terminating null string so caller
	 knows where the list of returned strings ends. */
	count++;

	result = malloc(sizeof(char*) * count);

	if (result) {
		size_t idx = 0;
		char* token = strtok_r(a_str, delim, &ptr);

		while (token) {
			//assert(idx < count);
			*(result + idx++) = strdup(token);
			token = strtok_r(0, delim, &ptr);
		}
		//assert(idx == count - 1);
		*(result + idx) = 0;
	}

	return result;
}

