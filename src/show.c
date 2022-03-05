#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include "show.h"
#include "bind.h"
#include "block.h"
#include "buffer.h"
#include "change.h"
#include "cmdline.h"
#include "command/alias.h"
#include "command/macro.h"
#include "command/serialize.h"
#include "commands.h"
#include "compiler.h"
#include "completion.h"
#include "config.h"
#include "edit.h"
#include "encoding.h"
#include "error.h"
#include "file-option.h"
#include "filetype.h"
#include "frame.h"
#include "msg.h"
#include "options.h"
#include "syntax/color.h"
#include "terminal/color.h"
#include "terminal/key.h"
#include "util/bsearch.h"
#include "util/hashset.h"
#include "util/str-util.h"
#include "util/unicode.h"
#include "util/xmalloc.h"
#include "util/xsnprintf.h"
#include "view.h"
#include "window.h"

extern char **environ;

typedef enum {
    DTERC = 0x1, // Use "dte" filetype (and syntax highlighter)
    LASTLINE = 0x2, // Move cursor to last line (e.g. most recent history entry)
} ShowHandlerFlags;

typedef struct {
    const char name[11];
    uint8_t flags; // ShowHandlerFlags
    void (*show)(EditorState *e, const char *name, bool cmdline);
    String (*dump)(EditorState *e);
    void (*complete_arg)(PointerArray *a, const char *prefix);
} ShowHandler;

static void open_temporary_buffer (
    const char *text,
    size_t text_len,
    const char *cmd,
    const char *cmd_arg,
    ShowHandlerFlags flags
) {
    View *v = window_open_new_file(editor.window);
    v->buffer->temporary = true;
    do_insert(v, text, text_len);
    set_display_filename(v->buffer, xasprintf("(%s %s)", cmd, cmd_arg));
    buffer_set_encoding(v->buffer, encoding_from_type(UTF8));
    if (flags & LASTLINE) {
        block_iter_eof(&v->cursor);
        block_iter_prev_line(&v->cursor);
    }
    if (flags & DTERC) {
        v->buffer->options.filetype = str_intern("dte");
        set_file_options(&editor.file_options, v->buffer);
        buffer_update_syntax(v->buffer);
    }
}

static void show_normal_alias(EditorState *e, const char *alias_name, bool cflag)
{
    const char *cmd_str = find_alias(&normal_commands.aliases, alias_name);
    if (!cmd_str) {
        if (find_normal_command(alias_name)) {
            info_msg("%s is a built-in command, not an alias", alias_name);
        } else {
            info_msg("%s is not a known alias", alias_name);
        }
        return;
    }

    if (cflag) {
        set_input_mode(e, INPUT_COMMAND);
        cmdline_set_text(&e->cmdline, cmd_str);
    } else {
        info_msg("%s is aliased to: %s", alias_name, cmd_str);
    }
}

static void show_binding(EditorState *e, const char *keystr, bool cflag)
{
    KeyCode key;
    if (!parse_key_string(&key, keystr)) {
        error_msg("invalid key string: %s", keystr);
        return;
    }

    if (u_is_unicode(key)) {
        info_msg("%s is not a bindable key", keystr);
        return;
    }

    const CachedCommand *b = lookup_binding(&e->bindings[INPUT_NORMAL], key);
    if (!b) {
        info_msg("%s is not bound to a command", keystr);
        return;
    }

    if (cflag) {
        set_input_mode(e, INPUT_COMMAND);
        cmdline_set_text(&e->cmdline, b->cmd_str);
    } else {
        info_msg("%s is bound to: %s", keystr, b->cmd_str);
    }
}

static void show_color(EditorState *e, const char *color_name, bool cflag)
{
    const TermColor *hl = find_color(&e->colors, color_name);
    if (!hl) {
        error_msg("no color entry with name '%s'", color_name);
        return;
    }

    const char *color_str = term_color_to_string(hl);
    if (cflag) {
        set_input_mode(e, INPUT_COMMAND);
        cmdline_set_text(&e->cmdline, color_str);
    } else {
        info_msg("color '%s' is set to: %s", color_name, color_str);
    }
}

static void show_env(EditorState *e, const char *name, bool cflag)
{
    const char *value = getenv(name);
    if (!value) {
        error_msg("no environment variable with name '%s'", name);
        return;
    }

    if (cflag) {
        set_input_mode(e, INPUT_COMMAND);
        cmdline_set_text(&e->cmdline, value);
    } else {
        info_msg("$%s is set to: %s", name, value);
    }
}

static String dump_env(EditorState* UNUSED_ARG(e))
{
    String buf = string_new(4096);
    for (size_t i = 0; environ[i]; i++) {
        string_append_cstring(&buf, environ[i]);
        string_append_byte(&buf, '\n');
    }
    return buf;
}

void collect_env(PointerArray *a, const char *prefix)
{
    for (size_t i = 0; environ[i]; i++) {
        const char *var = environ[i];
        if (str_has_prefix(var, prefix)) {
            const char *delim = strchr(var, '=');
            if (likely(delim)) {
                ptr_array_append(a, xstrcut(var, delim - var));
            }
        }
    }
}

static void show_include(EditorState *e, const char *name, bool cflag)
{
    const BuiltinConfig *cfg = get_builtin_config(name);
    if (!cfg) {
        error_msg("no built-in config with name '%s'", name);
        return;
    }

    const StringView sv = cfg->text;
    if (cflag) {
        buffer_insert_bytes(e->view, sv.data, sv.length);
    } else {
        open_temporary_buffer(sv.data, sv.length, "builtin", name, true);
    }
}

static void show_compiler(EditorState *e, const char *name, bool cflag)
{
    const Compiler *compiler = find_compiler(&e->compilers, name);
    if (!compiler) {
        error_msg("no errorfmt entry found for '%s'", name);
        return;
    }

    String str = string_new(512);
    dump_compiler(compiler, name, &str);
    if (cflag) {
        buffer_insert_bytes(e->view, str.buffer, str.len);
    } else {
        open_temporary_buffer(str.buffer, str.len, "errorfmt", name, true);
    }
    string_free(&str);
}

static void show_option(EditorState *e, const char *name, bool cflag)
{
    const char *value = get_option_value_string(name);
    if (!value) {
        error_msg("invalid option name: %s", name);
        return;
    }
    if (cflag) {
        set_input_mode(e, INPUT_COMMAND);
        cmdline_set_text(&e->cmdline, value);
    } else {
        info_msg("%s is set to: %s", name, value);
    }
}

static void collect_all_options(PointerArray *a, const char *prefix)
{
    collect_options(a, prefix, false, false);
}

static void show_wsplit(EditorState *e, const char *name, bool cflag)
{
    if (!streq(name, "this")) {
        error_msg("invalid window: %s", name);
        return;
    }

    const Window *w = e->window;
    char buf[(4 * DECIMAL_STR_MAX(w->x)) + 4];
    xsnprintf(buf, sizeof buf, "%d,%d %dx%d", w->x, w->y, w->w, w->h);

    if (cflag) {
        set_input_mode(e, INPUT_COMMAND);
        cmdline_set_text(&e->cmdline, buf);
    } else {
        info_msg("current window dimensions: %s", buf);
    }
}

static String do_history_dump(const History *history)
{
    const size_t nr_entries = history->entries.count;
    const size_t size = round_size_to_next_multiple(16 * nr_entries, 4096);
    String buf = string_new(size);
    size_t n = 0;
    for (HistoryEntry *e = history->first; e; e = e->next, n++) {
        string_append_cstring(&buf, e->text);
        string_append_byte(&buf, '\n');
    }
    BUG_ON(n != nr_entries);
    return buf;
}

static String dump_command_history(EditorState *e)
{
    return do_history_dump(&e->command_history);
}

static String dump_search_history(EditorState *e)
{
    return do_history_dump(&e->search_history);
}

typedef struct {
    const char *name;
    const char *value;
} CommandAlias;

static int alias_cmp(const void *ap, const void *bp)
{
    const CommandAlias *a = ap;
    const CommandAlias *b = bp;
    return strcmp(a->name, b->name);
}

String dump_normal_aliases(EditorState* UNUSED_ARG(e))
{
    const HashMap *aliases = &normal_commands.aliases;
    const size_t count = aliases->count;
    if (unlikely(count == 0)) {
        return string_new(0);
    }

    // Clone the contents of the HashMap as an array of name/value pairs
    CommandAlias *array = xnew(CommandAlias, count);
    size_t n = 0;
    for (HashMapIter it = hashmap_iter(aliases); hashmap_next(&it); ) {
        array[n++] = (CommandAlias) {
            .name = it.entry->key,
            .value = it.entry->value,
        };
    }

    // Sort the array
    BUG_ON(n != count);
    qsort(array, count, sizeof(array[0]), alias_cmp);

    // Serialize the aliases in sorted order
    String buf = string_new(4096);
    for (size_t i = 0; i < count; i++) {
        const char *name = array[i].name;
        string_append_literal(&buf, "alias ");
        if (unlikely(name[0] == '-')) {
            string_append_literal(&buf, "-- ");
        }
        string_append_escaped_arg(&buf, name, true);
        string_append_byte(&buf, ' ');
        string_append_escaped_arg(&buf, array[i].value, true);
        string_append_byte(&buf, '\n');
    }

    free(array);
    return buf;
}

void collect_normal_aliases(PointerArray *a, const char *prefix)
{
    collect_hashmap_keys(&normal_commands.aliases, a, prefix);
}

String dump_bindings(EditorState *e)
{
    static const char flags[][4] = {
        [INPUT_NORMAL] = "",
        [INPUT_COMMAND] = "-c ",
        [INPUT_SEARCH] = "-s ",
    };

    static_assert(ARRAY_COUNT(flags) == ARRAY_COUNT(e->bindings));
    String buf = string_new(4096);
    for (InputMode i = 0, n = ARRAY_COUNT(e->bindings); i < n; i++) {
        if (dump_binding_group(&e->bindings[i], flags[i], &buf) && i != n - 1) {
            string_append_byte(&buf, '\n');
        }
    }
    return buf;
}

String dump_frames(EditorState *e)
{
    String str = string_new(4096);
    dump_frame(e->root_frame, 0, &str);
    return str;
}

String dump_compilers(EditorState *e)
{
    String buf = string_new(4096);
    for (HashMapIter it = hashmap_iter(&e->compilers); hashmap_next(&it); ) {
        const char *name = it.entry->key;
        const Compiler *c = it.entry->value;
        dump_compiler(c, name, &buf);
        string_append_byte(&buf, '\n');
    }
    return buf;
}

String do_dump_options(EditorState* UNUSED_ARG(e))
{
    return dump_options();
}

String do_dump_builtin_configs(EditorState* UNUSED_ARG(e))
{
    return dump_builtin_configs();
}

String do_dump_hl_colors(EditorState *e)
{
    return dump_hl_colors(&e->colors);
}

String do_dump_filetypes(EditorState *e)
{
    return dump_filetypes(&e->filetypes);
}

static String do_dump_messages(EditorState *e)
{
    return dump_messages(&e->messages);
}

static String do_dump_macro(EditorState* UNUSED_ARG(e))
{
    return dump_macro();
}

static const ShowHandler handlers[] = {
    {"alias", DTERC, show_normal_alias, dump_normal_aliases, collect_normal_aliases},
    {"bind", DTERC, show_binding, dump_bindings, collect_bound_keys},
    {"color", DTERC, show_color, do_dump_hl_colors, collect_hl_colors},
    {"command", DTERC | LASTLINE, NULL, dump_command_history, NULL},
    {"env", 0, show_env, dump_env, collect_env},
    {"errorfmt", DTERC, show_compiler, dump_compilers, collect_compilers},
    {"ft", DTERC, NULL, do_dump_filetypes, NULL},
    {"include", 0, show_include, do_dump_builtin_configs, collect_builtin_configs},
    {"macro", DTERC, NULL, do_dump_macro, NULL},
    {"msg", 0, NULL, do_dump_messages, NULL},
    {"option", DTERC, show_option, do_dump_options, collect_all_options},
    {"search", LASTLINE, NULL, dump_search_history, NULL},
    {"wsplit", 0, show_wsplit, dump_frames, NULL},
};

UNITTEST {
    CHECK_BSEARCH_ARRAY(handlers, name, strcmp);
}

void show(EditorState *e, const char *type, const char *key, bool cflag)
{
    const ShowHandler *handler = BSEARCH(type, handlers, (CompareFunction)strcmp);
    if (!handler) {
        error_msg("invalid argument: '%s'", type);
        return;
    }

    if (key) {
        if (handler->show) {
            handler->show(e, key, cflag);
        } else {
            error_msg("'show %s' doesn't take extra arguments", type);
        }
        return;
    }

    String str = handler->dump(e);
    open_temporary_buffer(str.buffer, str.len, "show", type, handler->flags);
    string_free(&str);
}

void collect_show_subcommands(PointerArray *a, const char *prefix)
{
    for (size_t i = 0; i < ARRAY_COUNT(handlers); i++) {
        if (str_has_prefix(handlers[i].name, prefix)) {
            ptr_array_append(a, xstrdup(handlers[i].name));
        }
    }
}

void collect_show_subcommand_args(PointerArray *a, const char *name, const char *arg_prefix)
{
    const ShowHandler *handler = BSEARCH(name, handlers, (CompareFunction)strcmp);
    if (handler && handler->complete_arg) {
        handler->complete_arg(a, arg_prefix);
    }
}
