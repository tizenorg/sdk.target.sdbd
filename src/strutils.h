#ifndef _STRUTILS_H_
#define _STRUTILS_H_

#define MAX_TOKENS 10

size_t tokenize(const char *str, const char *delim, char *tokens[], size_t max_tokens);
void free_strings(char **array, int n);
int read_line(const int fd, char* ptr, const unsigned int maxlen);

#endif

