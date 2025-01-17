#ifndef UTIL_XSTDIO_H
#define UTIL_XSTDIO_H

#include <errno.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include "debug.h"
#include "macros.h"
#include "xreadwrite.h"

static inline FILE *xfopen(const char *path, const char *mode, int flags, mode_t mask)
{
    BUG_ON(mode[0] == '\0');
    bool plus = (mode[1] == '+');
    BUG_ON(mode[plus ? 2 : 1] != '\0');

    switch (mode[0]) {
    case 'a':
        flags |= (plus ? O_RDWR : O_WRONLY) | O_CREAT | O_APPEND;
        break;
    case 'r':
        flags |= (plus ? O_RDWR : O_RDONLY);
        break;
    case 'w':
        flags |= (plus ? O_RDWR : O_WRONLY) | O_CREAT | O_TRUNC;
        break;
    default:
        BUG("Unknown fopen() mode string: '%s'", mode);
    }

    int fd = xopen(path, flags, mask);
    if (fd < 0) {
        return NULL;
    }

    FILE *file = fdopen(fd, mode);
    if (unlikely(!file)) {
        int e = errno;
        xclose(fd);
        errno = e;
    }
    return file;
}

char *xfgets(char *restrict buf, int bufsize, FILE *restrict stream);
int xfputs(const char *restrict str, FILE *restrict stream);
int xfputc(int c, FILE *stream);
int xvfprintf(FILE *restrict stream, const char *restrict fmt, va_list ap) VPRINTF(2);
int xfprintf(FILE *restrict stream, const char *restrict fmt, ...) PRINTF(2);
int xfflush(FILE *stream);

#endif
