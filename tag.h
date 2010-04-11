#ifndef TAG_H
#define TAG_H

#include "ctags.h"

extern struct ptr_array current_tags;

int find_tags(const char *name);
void move_to_tag(const struct tag *t, int save_location);
void pop_location(void);

#endif
