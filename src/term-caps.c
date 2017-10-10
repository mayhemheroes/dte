#include "term.h"
#include "cursed.h"
#include "xmalloc.h"

static const char *const string_cap_map[NR_STR_CAPS] = {
    "acsc", // acs_chars,
    "rmacs", // exit_alt_charset_mode,
    "smacs", // enter_alt_charset_mode,
    "el", // clr_eol,
    "rmkx", // keypad_local,
    "smkx", // keypad_xmit,
    "rmcup", // exit_ca_mode,
    "smcup", // enter_ca_mode,
    "cnorm", // cursor_normal,
    "civis", // cursor_invisible,
};

static const char *const key_cap_map[NR_SPECIAL_KEYS] = {
    "kich1", // key_ic,
    "kdch1", // key_dc,
    "khome", // key_home,
    "kend", // key_end,
    "kpp", // key_ppage,
    "knp", // key_npage,
    "kcub1", // key_left,
    "kcuf1", // key_right,
    "kcuu1", // key_up,
    "kcud1", // key_down,
    "kf1", // key_f1,
    "kf2", // key_f2,
    "kf3", // key_f3,
    "kf4", // key_f4,
    "kf5", // key_f5,
    "kf6", // key_f6,
    "kf7", // key_f7,
    "kf8", // key_f8,
    "kf9", // key_f9,
    "kf10", // key_f10,
    "kf11", // key_f11,
    "kf12", // key_f12,
};

void term_read_caps(void)
{
    term_cap.ut = curses_bool_cap("bce"); // back_color_erase
    term_cap.colors = curses_int_cap("colors"); // max_colors
    for (size_t i = 0; i < NR_STR_CAPS; i++) {
        term_cap.strings[i] = curses_str_cap(string_cap_map[i]);
    }

    for (size_t i = 0; i < NR_SPECIAL_KEYS; i++) {
        term_cap.keymap[i] = (struct term_keymap) {
            .key = KEY_SPECIAL_MIN + i,
            .code = curses_str_cap(key_cap_map[i])
        };
    }

    term_cap.keymap[NR_SPECIAL_KEYS] = (struct term_keymap) {
        .key = MOD_SHIFT | KEY_LEFT,
        .code = curses_str_cap("kLFT") // key_sleft
    };

    term_cap.keymap[NR_SPECIAL_KEYS + 1] = (struct term_keymap) {
        .key = MOD_SHIFT | KEY_RIGHT,
        .code = curses_str_cap("kRIT") // key_sright
    };
}
