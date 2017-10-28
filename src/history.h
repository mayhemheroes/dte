#ifndef HISTORY_H
#define HISTORY_H

#include <stdbool.h>
#include "ptr-array.h"

#define search_history_size 100
#define command_history_size 500

void history_add(PointerArray *history, const char *text, int max_entries);
bool history_search_forward(const PointerArray *history, int *pos, const char *text);
bool history_search_backward(const PointerArray *history, int *pos, const char *text);
void history_load(PointerArray *history, const char *filename, int max_entries);
void history_save(PointerArray *history, const char *filename);

#endif
