#include <stdint.h>
#include <stdio.h>
#include "util/ascii.h"
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 100) {
        return 0;
    }
    char* buf = (char*) malloc(size);
    memcpy(buf, data, size);
    buf[50] = '\0';
    buf[99] = '\0';

    ascii_strcmp_icase(buf, buf + 51);

    free(buf);
    return 0;
}
