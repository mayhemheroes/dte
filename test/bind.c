#include "test.h"
#include "bind.h"
#include "block.h"
#include "buffer.h"
#include "change.h"
#include "command/args.h"
#include "commands.h"
#include "editor.h"
#include "util/str-util.h"

static void test_add_binding(TestContext *ctx)
{
    EditorState *e = ctx->userdata;
    IntMap *bindings = &e->modes[INPUT_NORMAL].key_bindings;
    KeyCode key = MOD_CTRL | MOD_SHIFT | KEY_F12;
    const CachedCommand *bind = lookup_binding(bindings, key);
    EXPECT_NULL(bind);

    const Command *insert_cmd = find_normal_command("insert");
    ASSERT_NONNULL(insert_cmd);

    static const char cmd_str[] = "insert xyz";
    CommandRunner runner = cmdrunner_for_mode(e, INPUT_NORMAL, false);
    CachedCommand *cc = cached_command_new(&runner, cmd_str);
    ASSERT_NONNULL(cc);

    add_binding(bindings, key, cc);
    bind = lookup_binding(bindings, key);
    ASSERT_NONNULL(bind);
    EXPECT_PTREQ(bind->cmd, insert_cmd);
    EXPECT_EQ(bind->a.nr_args, 1);
    EXPECT_EQ(bind->a.nr_flags, 0);
    EXPECT_STREQ(bind->cmd_str, cmd_str);

    remove_binding(bindings, key);
    EXPECT_NULL(lookup_binding(bindings, key));
}

static void test_handle_binding(TestContext *ctx)
{
    const Command *insert = find_normal_command("insert");
    ASSERT_NONNULL(insert);

    EditorState *e = ctx->userdata;
    EXPECT_TRUE(handle_normal_command(e, "open; bind C-S-F11 'insert -m zzz'", false));

    // Bound command should be cached
    InputMode mode = INPUT_NORMAL;
    const IntMap *bindings = &e->modes[mode].key_bindings;
    KeyCode key = MOD_CTRL | MOD_SHIFT | KEY_F11;
    const CachedCommand *binding = lookup_binding(bindings, key);
    ASSERT_NONNULL(binding);
    EXPECT_PTREQ(binding->cmd, insert);
    EXPECT_EQ(binding->a.nr_flags, 1);
    EXPECT_EQ(binding->a.nr_args, 1);
    EXPECT_STREQ(binding->a.args[0], "zzz");
    EXPECT_NULL(binding->a.args[1]);
    EXPECT_EQ(binding->a.flags[0], 'm');
    EXPECT_EQ(binding->a.flags[1], '\0');
    EXPECT_TRUE(cmdargs_has_flag(&binding->a, 'm'));

    ASSERT_TRUE(handle_binding(e, mode, key));
    const Block *block = BLOCK(e->buffer->blocks.next);
    ASSERT_NONNULL(block);
    ASSERT_EQ(block->size, 4);
    EXPECT_EQ(block->nl, 1);
    EXPECT_MEMEQ(block->data, "zzz\n", 4);

    ASSERT_TRUE(handle_binding(e, mode, MOD_CTRL | '?'));
    ASSERT_EQ(block->size, 3);
    EXPECT_EQ(block->nl, 1);
    EXPECT_MEMEQ(block->data, "zz\n", 3);

    ASSERT_TRUE(handle_binding(e, mode, MOD_CTRL | MOD_META | '?'));
    ASSERT_EQ(block->size, 1);
    EXPECT_EQ(block->nl, 1);
    EXPECT_MEMEQ(block->data, "\n", 1);

    View *view = e->view;
    ASSERT_NONNULL(view);
    EXPECT_TRUE(undo(view));
    ASSERT_EQ(block->size, 3);
    EXPECT_TRUE(undo(view));
    ASSERT_EQ(block->size, 4);
    EXPECT_TRUE(undo(view));
    EXPECT_EQ(block->size, 0);
    EXPECT_EQ(block->nl, 0);
    EXPECT_FALSE(undo(view));
    EXPECT_TRUE(handle_normal_command(e, "close", false));
}

static const TestEntry tests[] = {
    TEST(test_add_binding),
    TEST(test_handle_binding),
};

const TestGroup bind_tests = TEST_GROUP(tests);
