#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sysdeps.h"
#include "strutils.h"

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif


size_t tokenize(const char *str, const char *delim, char *tokens[], size_t max_tokens ) {
    int cnt = 0;

    char tmp[PATH_MAX];

    strncpy(tmp, str, PATH_MAX);
    char *p = strtok(tmp, delim);
    if (max_tokens < 1 || max_tokens > MAX_TOKENS) {
        max_tokens = 1;
    }

    if (p != NULL) {
        tokens[cnt++] = strdup(p);
        while(cnt < max_tokens && p != NULL) {
            p = strtok(NULL, delim);
            if (p != NULL) {
                tokens[cnt++] = strdup(p);
            }
        }
    }
    return cnt;
}

void free_strings(char **array, int n)
{
    int i;

    for(i = 0; i < n; i++) {
        if (array[i] != NULL) {
            free(array[i]);
        }
    }
}


int read_line(const int fd, char* ptr, const unsigned int maxlen)
{
    unsigned int n = 0;
    char c[2];
    int rc;

    while(n != maxlen) {
        if((rc = sdb_read(fd, c, 1)) != 1)
            return -1; // eof or read err

        if(*c == '\n') {
            ptr[n] = 0;
            return n;
        }
        ptr[n++] = *c;
    }
    return -1; // no space
}
