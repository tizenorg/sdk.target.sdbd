#ifndef _STRUTILS_H_
#define _STRUTILS_H_

#define MAX_TOKENS 100

size_t tokenize(const char *str, const char *delim, char *tokens[], size_t max_tokens);
size_t tokenize_append(const char *str, const char *delim, char *tokens[], size_t max_tokens, int append_position);
void free_strings(char **array, int n);
int read_line(const int fd, char* ptr, const unsigned int maxlen);
char *s_strncpy(char *dest, const char *source, size_t n);
#endif

