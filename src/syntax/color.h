#ifndef SYNTAX_COLOR_H
#define SYNTAX_COLOR_H

#include "terminal/style.h"
#include "util/hashmap.h"
#include "util/macros.h"
#include "util/ptr-array.h"
#include "util/string.h"

typedef enum {
    BC_ACTIVETAB,
    BC_COMMANDLINE,
    BC_CURRENTLINE,
    BC_DEFAULT,
    BC_DIALOG,
    BC_ERRORMSG,
    BC_INACTIVETAB,
    BC_INFOMSG,
    BC_LINENUMBER,
    BC_NOLINE,
    BC_NONTEXT,
    BC_SELECTION,
    BC_STATUSLINE,
    BC_TABBAR,
    BC_WSERROR,
    NR_BC
} BuiltinColorEnum;

typedef struct {
    TermColor builtin[NR_BC];
    HashMap other;
} ColorScheme;

void set_highlight_color(ColorScheme *colors, const char *name, const TermColor *color) NONNULL_ARGS;
const TermColor *find_color(const ColorScheme *colors, const char *name) NONNULL_ARGS;
void clear_hl_colors(ColorScheme *colors) NONNULL_ARGS;
void collect_builtin_colors(PointerArray *a, const char *prefix) NONNULL_ARGS;
void string_append_hl_color(String *s, const char *name, const TermColor *color) NONNULL_ARGS;
String dump_hl_colors(const ColorScheme *colors) NONNULL_ARGS;

#endif
