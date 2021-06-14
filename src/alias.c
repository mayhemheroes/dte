#include <stdlib.h>
#include <string.h>
#include "alias.h"
#include "command/serialize.h"
#include "commands.h"
#include "completion.h"
#include "util/xmalloc.h"

void add_alias(HashMap *aliases, const char *name, const char *value)
{
    free(hashmap_insert_or_replace(aliases, xstrdup(name), xstrdup(value)));
}

void remove_alias(HashMap *aliases, const char *name)
{
    free(hashmap_remove(aliases, name));
}

const char *find_alias(const HashMap *aliases, const char *name)
{
    return hashmap_get(aliases, name);
}

void collect_aliases(const char *const prefix)
{
    collect_hashmap_keys(normal_commands.aliases, prefix);
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

String dump_aliases(void)
{
    const HashMap *aliases = normal_commands.aliases;
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
