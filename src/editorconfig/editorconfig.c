#include <stddef.h>
#include <string.h>
#include "editorconfig.h"
#include "ini.h"
#include "match.h"
#include "util/debug.h"
#include "util/path.h"
#include "util/readfile.h"
#include "util/string.h"
#include "util/string-view.h"
#include "util/strtonum.h"
#include "util/str-util.h"

typedef struct {
    const char *const pathname;
    StringView config_file_dir;
    EditorConfigOptions options;
    bool match;
} UserData;

typedef enum {
    EC_CHARSET,
    EC_END_OF_LINE,
    EC_INDENT_SIZE,
    EC_INDENT_STYLE,
    EC_INSERT_FINAL_NL,
    EC_MAX_LINE_LENGTH,
    EC_TAB_WIDTH,
    EC_TRIM_TRAILING_WS,
    EC_UNKNOWN_PROPERTY,
} PropertyType;

#define CMP(s, val) if (mem_equal(name->data, s, STRLEN(s))) return val;

static PropertyType lookup_property(const StringView *name)
{
    switch (name->length) {
    case  7: CMP("charset", EC_CHARSET); break;
    case  9: CMP("tab_width", EC_TAB_WIDTH); break;
    case 11:
        CMP("indent_size", EC_INDENT_SIZE);
        CMP("end_of_line", EC_END_OF_LINE);
        break;
    case 12: CMP("indent_style", EC_INDENT_STYLE); break;
    case 15: CMP("max_line_length", EC_MAX_LINE_LENGTH); break;
    case 20: CMP("insert_final_newline", EC_INSERT_FINAL_NL); break;
    case 24: CMP("trim_trailing_whitespace", EC_TRIM_TRAILING_WS); break;
    }
    return EC_UNKNOWN_PROPERTY;
}

static void editorconfig_option_set (
    EditorConfigOptions *options,
    const StringView *name,
    const StringView *val
) {
    unsigned int n = 0;
    switch (lookup_property(name)) {
    case EC_INDENT_STYLE:
        if (strview_equal_cstring_icase(val, "space")) {
            options->indent_style = INDENT_STYLE_SPACE;
        } else if (strview_equal_cstring_icase(val, "tab")) {
            options->indent_style = INDENT_STYLE_TAB;
        } else {
            options->indent_style = INDENT_STYLE_UNSPECIFIED;
        }
        break;
    case EC_INDENT_SIZE:
        if (strview_equal_cstring_icase(val, "tab")) {
            options->indent_size_is_tab = true;
            options->indent_size = 0;
        } else {
            buf_parse_uint(val->data, val->length, &n);
            // If buf_parse_uint() failed, n is zero, which is deliberately
            // used to "reset" the option due to an invalid value
            options->indent_size = n;
            options->indent_size_is_tab = false;
        }
        break;
    case EC_TAB_WIDTH:
        buf_parse_uint(val->data, val->length, &n);
        options->tab_width = n;
        break;
    case EC_MAX_LINE_LENGTH:
        buf_parse_uint(val->data, val->length, &n);
        options->max_line_length = n;
        break;
    case EC_CHARSET:
    case EC_END_OF_LINE:
    case EC_INSERT_FINAL_NL:
    case EC_TRIM_TRAILING_WS:
    case EC_UNKNOWN_PROPERTY:
        break;
    default:
        BUG("unhandled property type");
    }
}

static void editorconfig_parse(const char *buf, size_t size, UserData *data)
{
    IniParser ini = {
        .input = buf,
        .input_len = size,
    };

    if (size >= 3 && mem_equal(buf, "\xEF\xBB\xBF", 3)) {
        // Skip past UTF-8 BOM
        ini.pos += 3;
    }

    while (ini_parse(&ini)) {
        if (ini.section.length == 0) {
            if (
                strview_equal_cstring_icase(&ini.name, "root")
                && strview_equal_cstring_icase(&ini.value, "true")
            ) {
                // root=true, clear all previous values
                data->options = editorconfig_options_init();
            }
            continue;
        }

        if (ini.name_count == 1) {
            // If name_count is 1, it indicates that the name/value pair is
            // the first in the section and therefore requires a new pattern
            // to be built and tested for a match
            const StringView ecdir = data->config_file_dir;
            String pattern = string_new(ecdir.length + ini.section.length + 16);

            // Escape editorconfig special chars in path
            for (size_t i = 0, n = ecdir.length; i < n; i++) {
                const char ch = ecdir.data[i];
                switch (ch) {
                case '*': case ',': case '-':
                case '?': case '[': case '\\':
                case ']': case '{': case '}':
                    string_append_byte(&pattern, '\\');
                    // Fallthrough
                default:
                    string_append_byte(&pattern, ch);
                }
            }

            if (!strview_memchr(&ini.section, '/')) {
                // No slash in pattern, append "**/"
                string_append_literal(&pattern, "**/");
            } else if (ini.section.data[0] != '/') {
                // Pattern contains at least one slash but not at the start, add one
                string_append_byte(&pattern, '/');
            }

            string_append_strview(&pattern, &ini.section);
            data->match = ec_pattern_match (
                pattern.buffer,
                pattern.len,
                data->pathname
            );
            string_free(&pattern);
        } else {
            // Otherwise, the section is the same as was passed for the first
            // name/value pair in the section and the value of data->match
            // can just be reused
        }

        if (data->match) {
            editorconfig_option_set(&data->options, &ini.name, &ini.value);
        }
    }
}

int get_editorconfig_options(const char *pathname, EditorConfigOptions *opts)
{
    BUG_ON(!path_is_absolute(pathname));
    UserData data = {
        .pathname = pathname,
        .config_file_dir = STRING_VIEW_INIT,
        .match = false
    };

    static const char ecfilename[16] = "/.editorconfig";
    char buf[8192];
    memcpy(buf, ecfilename, sizeof ecfilename);

    const char *ptr = pathname + 1;
    size_t dir_len = 1;

    // Iterate up directory tree, looking for ".editorconfig" at each level
    while (1) {
        char *text;
        ssize_t len = read_file_with_limit(buf, &text, 32u << 20);
        if (len >= 0) {
            data.config_file_dir = string_view(buf, dir_len);
            editorconfig_parse(text, len, &data);
            free(text);
        }

        const char *slash = strchr(ptr, '/');
        if (!slash) {
            break;
        }

        dir_len = slash - pathname;
        memcpy(buf, pathname, dir_len);
        memcpy(buf + dir_len, ecfilename, sizeof ecfilename);
        ptr = slash + 1;
    }

    // Set indent_size to "tab" if indent_size is not specified and
    // indent_style is set to "tab"
    if (
        data.options.indent_size == 0
        && data.options.indent_style == INDENT_STYLE_TAB
    ) {
        data.options.indent_size_is_tab = true;
    }

    // Set indent_size to tab_width if indent_size is "tab" and
    // tab_width is specified
    if (data.options.indent_size_is_tab && data.options.tab_width > 0) {
        data.options.indent_size = data.options.tab_width;
    }

    // Set tab_width to indent_size if indent_size is specified as
    // something other than "tab" and tab_width is unspecified
    if (
        data.options.indent_size != 0
        && data.options.tab_width == 0
        && !data.options.indent_size_is_tab
    ) {
        data.options.tab_width = data.options.indent_size;
    }

    *opts = data.options;
    return 0;
}
