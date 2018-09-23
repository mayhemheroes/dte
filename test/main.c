#include <langinfo.h>
#include <locale.h>
#include <string.h>
#include "test.h"
#include "../src/command.h"
#include "../src/editor.h"
#include "../src/encoding/bom.h"
#include "../src/util/path.h"
#include "../src/util/xmalloc.h"

void test_filetype(void);
void test_terminal(void);
void test_util(void);
void init_headless_mode(void);
void test_exec_config(void);

static void test_relative_filename(void)
{
    static const struct rel_test {
        const char *cwd, *path, *result;
    } tests[] = { // NOTE: at most 2 ".." components allowed in relative name
        { "/", "/", "/" },
        { "/", "/file", "file" },
        { "/a/b/c/d", "/a/b/file", "../../file" },
        { "/a/b/c/d/e", "/a/b/file", "/a/b/file" },
        { "/a/foobar", "/a/foo/file", "../foo/file" },
    };
    FOR_EACH_I(i, tests) {
        const struct rel_test *t = &tests[i];
        char *result = relative_filename(t->path, t->cwd);
        EXPECT_STREQ(t->result, result);
        free(result);
    }
}

static void test_detect_encoding_from_bom(void)
{
    static const struct bom_test {
        const char *encoding;
        const unsigned char *text;
        size_t size;
    } tests[] = {
        {"UTF-8", "\xef\xbb\xbfHello", 8},
        {"UTF-32BE", "\x00\x00\xfe\xffHello", 9},
        {"UTF-32LE", "\xff\xfe\x00\x00Hello", 9},
        {"UTF-16BE", "\xfe\xffHello", 7},
        {"UTF-16LE", "\xff\xfeHello", 7},
        {NULL, "\x00\xef\xbb\xbfHello", 9},
        {NULL, "\xef\xbb", 2},
    };
    FOR_EACH_I(i, tests) {
        const struct bom_test *t = &tests[i];
        const char *result = detect_encoding_from_bom(t->text, t->size);
        EXPECT_STREQ(result, t->encoding);
    }
}

static int command_cmp(const void *p1, const void *p2)
{
    const Command *c1 = p1, *c2 = p2;
    return strcmp(c1->name, c2->name);
}

// Checks that `commands` array is sorted in binary searchable order
static void test_commands_sort(void)
{
    size_t n = 0;
    while (commands[n].name) {
        n++;
        BUG_ON(n > 500);
    }

    const size_t size = n * sizeof(Command);
    Command *commands_copy = xmalloc(size);
    memcpy(commands_copy, commands, size);
    qsort(commands_copy, n, sizeof(Command), command_cmp);

    for (size_t i = 0; i < n; i++) {
        EXPECT_STREQ(commands[i].name, commands_copy[i].name);
    }

    free(commands_copy);
}

int main(void)
{
    init_editor_state();

    test_relative_filename();
    test_detect_encoding_from_bom();
    test_commands_sort();

    test_filetype();
    test_util();
    test_terminal();

    init_headless_mode();
    test_exec_config();

    return failed ? 1 : 0;
}
