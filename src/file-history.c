#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include "file-history.h"
#include "error.h"
#include "util/path.h"
#include "util/readfile.h"
#include "util/str-util.h"
#include "util/strtonum.h"
#include "util/xmalloc.h"
#include "util/xstdio.h"

enum {
    MAX_ENTRIES = 512
};

void file_history_add(FileHistory *history, unsigned long row, unsigned long col, const char *filename)
{
    HashMap *map = &history->entries;
    FileHistoryEntry *e = hashmap_get(map, filename);
    if (e) {
        if (e == history->last) {
            e->row = row;
            e->col = col;
            return;
        }
        e->next->prev = e->prev;
        if (unlikely(e == history->first)) {
            history->first = e->next;
        } else {
            e->prev->next = e->next;
        }
    } else {
        if (map->count == MAX_ENTRIES) {
            // History is full; recycle the oldest entry
            FileHistoryEntry *old_first = history->first;
            FileHistoryEntry *new_first = old_first->next;
            new_first->prev = NULL;
            history->first = new_first;
            e = hashmap_remove(map, old_first->filename);
            BUG_ON(e != old_first);
        } else {
            e = xnew(FileHistoryEntry, 1);
        }
        e->filename = xstrdup(filename);
        hashmap_insert(map, e->filename, e);
    }

    // Insert the entry at the end of the list
    FileHistoryEntry *old_last = history->last;
    e->next = NULL;
    e->prev = old_last;
    e->row = row;
    e->col = col;
    history->last = e;
    if (likely(old_last)) {
        old_last->next = e;
    } else {
        history->first = e;
    }
}

static bool parse_ulong(const char **strp, unsigned long *valp)
{
    const char *str = *strp;
    const size_t len = strlen(str);
    const size_t ndigits = buf_parse_ulong(str, len, valp);
    if (ndigits > 0) {
        *strp = str + ndigits;
        return true;
    }
    return false;
}

void file_history_load(FileHistory *history, const char *filename)
{
    BUG_ON(!history);
    BUG_ON(!filename);
    BUG_ON(history->filename);

    char *buf;
    const ssize_t ssize = read_file(filename, &buf);
    if (ssize < 0) {
        if (errno != ENOENT) {
            error_msg("Error reading %s: %s", filename, strerror(errno));
        }
        return;
    }

    hashmap_init(&history->entries, MAX_ENTRIES);
    history->filename = filename;
    for (size_t pos = 0, size = ssize; pos < size; ) {
        const char *line = buf_next_line(buf, &pos, size);
        unsigned long row, col;
        if (!parse_ulong(&line, &row) || row == 0 || *line++ != ' ') {
            continue;
        }
        if (!parse_ulong(&line, &col) || col == 0 || *line++ != ' ') {
            continue;
        }
        const char *path = line;
        if (!path_is_absolute(path)) {
            continue;
        }
        file_history_add(history, row, col, path);
    }

    free(buf);
}

void file_history_save(const FileHistory *history)
{
    const char *filename = history->filename;
    if (!filename) {
        return;
    }

    FILE *f = xfopen(filename, "w", O_CLOEXEC, 0666);
    if (!f) {
        error_msg("Error creating %s: %s", filename, strerror(errno));
        return;
    }

    for (const FileHistoryEntry *e = history->first; e; e = e->next) {
        fprintf(f, "%lu %lu %s\n", e->row, e->col, e->filename);
    }

    fclose(f);
}

bool file_history_find(const FileHistory *history, const char *filename, unsigned long *row, unsigned long *col)
{
    const FileHistoryEntry *e = hashmap_get(&history->entries, filename);
    if (!e) {
        return false;
    }
    *row = e->row;
    *col = e->col;
    return true;
}

void file_history_free(FileHistory *history)
{
    hashmap_free(&history->entries, free);
    history->first = NULL;
    history->last = NULL;
}
