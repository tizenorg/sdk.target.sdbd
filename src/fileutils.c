#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <limits.h>

static int recurse(const char *path, mode_t mode, int (*fn)(const char *,mode_t, int)) {
    struct stat st;
    char dir[PATH_MAX];

    if (path == NULL) {
        return -1;
    }
    if (lstat (path, &st) == -1) {
        return -1;
    }
    if (strrchr(path, '/') != NULL) {
        int n = strlen(path)-strlen(strrchr(path, '/'));
        if (n >= PATH_MAX) {
            return -1;
        }
        strncpy(dir, path, n);
        dir[n] = '\0';
        fn(dir, mode,1);
        return 1;
    }
    return -1;
}

int sdb_chmod(const char *path, mode_t mode, int recursive) {
#ifdef HAVE_WIN32_PROC
    fprintf(stderr, "error: sdb_chmod not implemented on Win32 (%s)\n", path);
    return -1;
#else
    struct stat st;

    if (stat (path, &st) == -1)
        return -1;

    if (chmod (path, mode) == -1) {
        return -1;
    }
    if (recursive) {
        return recurse(path, mode, sdb_chmod);
    }
    return 1;
#endif
}
