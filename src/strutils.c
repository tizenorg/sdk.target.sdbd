#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sysdeps.h"
#include "strutils.h"

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

size_t tokenize(const char *str, const char *delim, char *tokens[], size_t max_tokens ) {
    return tokenize_2(str, delim, tokens, max_tokens, 0);
}

size_t tokenize_2(const char *str, const char *delim, char *tokens[], size_t max_tokens, int position) {
    int cnt = position;

    char tmp[PATH_MAX+1];
    char *ptr;

    strncpy(tmp, str, PATH_MAX);
    tmp[PATH_MAX] = '\0';

    char *p = strtok_r(tmp, delim, &ptr);
    if (max_tokens < 1 || max_tokens > MAX_TOKENS) {
        max_tokens = 1;
    }

    if (p != NULL) {
        tokens[cnt++] = strdup(p);
        while(cnt < max_tokens && p != NULL) {
            p = strtok_r(NULL, delim, &ptr);
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

/**
 * The standard strncpy() function does not guarantee that the resulting string is null terminated.
 * char ntbs[NTBS_SIZE];
 * strncpy(ntbs, source, sizeof(ntbs)-1);
 * ntbs[sizeof(ntbs)-1] = '\0'
 */

char *s_strncpy(char *dest, const char *source, size_t n) {

    char *start = dest;

    while(n && (*dest++ = *source++)) {
        n--;
    }

    if (n) {
        while (--n) {
            *dest++ = '\0';
        }
    }
    return start;
}
