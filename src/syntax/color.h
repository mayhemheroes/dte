#ifndef SYNTAX_COLOR_H
#define SYNTAX_COLOR_H

#include "terminal/color.h"
#include "util/hashmap.h"
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

extern const char builtin_color_names[NR_BC][16];

void set_highlight_color(ColorScheme *colors, const char *name, const TermColor *color);
const TermColor *find_color(ColorScheme *colors, const char *name);
void clear_hl_colors(ColorScheme *colors);
void string_append_hl_color(String *s, const char *name, const TermColor *color);
String dump_hl_colors(const ColorScheme *colors);

#endif
