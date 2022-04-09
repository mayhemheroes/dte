#include "../../build/feature.h"
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include "winsize.h"
#include "util/log.h"

#if defined(HAVE_TIOCGWINSZ)

#include <sys/ioctl.h>

bool term_get_size(unsigned int *w, unsigned int *h)
{
    struct winsize ws;
    if (unlikely(ioctl(STDIN_FILENO, TIOCGWINSZ, &ws) == -1)) {
        LOG_ERROR("TIOCGWINSZ ioctl failed: %s", strerror(errno));
        return false;
    }
    *w = ws.ws_col;
    *h = ws.ws_row;
    return true;
}

#elif defined(HAVE_TCGETWINSIZE)

#include <termios.h>

bool term_get_size(unsigned int *w, unsigned int *h)
{
    struct winsize ws;
    if (unlikely(tcgetwinsize(STDIN_FILENO, &ws) != 0)) {
        LOG_ERROR("tcgetwinsize() failed: %s", strerror(errno));
        return false;
    }
    *w = ws.ws_col;
    *h = ws.ws_row;
    return true;
}

#else

bool term_get_size(unsigned int* UNUSED_ARG(w), unsigned int* UNUSED_ARG(h))
{
    return false;
}

#endif
