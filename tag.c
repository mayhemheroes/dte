#include "tag.h"
#include "ctags.h"
#include "editor.h"
#include "window.h"
#include "move.h"
#include "search.h"
#include "list.h"
#include "ptr-array.h"

struct file_location {
	struct list_head node;
	char *filename;
	unsigned int buffer_id;
	int x, y;
};

struct ptr_array current_tags;

static struct tag_file *tag_file;
static const char *current_filename; // for sorting tags
static LIST_HEAD(location_head);

static int visibility_cmp(const struct tag *a, const struct tag *b)
{
	int a_this_file = 0;
	int b_this_file = 0;

	if (!a->local && !b->local)
		return 0;

	// Is tag visibility limited to the current file?
	if (a->local)
		a_this_file = current_filename && !strcmp(current_filename, a->filename);
	if (b->local)
		b_this_file = current_filename && !strcmp(current_filename, b->filename);

	// Tags local to other file than current are not interesting.
	if (a->local && !a_this_file) {
		// a is not interesting
		if (b->local && !b_this_file) {
			// b is equally uninteresting
			return 0;
		}
		// b is more interesting, sort it before a
		return 1;
	}
	if (b->local && !b_this_file) {
		// b is not interesting
		return -1;
	}

	// both are NOT UNinteresting

	if (a->local && a_this_file) {
		if (b->local && b_this_file)
			return 0;
		// a is more interesting bacause it is local symbol
		return -1;
	}
	if (b->local && b_this_file) {
		// b is more interesting bacause it is local symbol
		return 1;
	}
	return 0;
}

static int kind_cmp(const struct tag *a, const struct tag *b)
{
	if (a->kind == b->kind)
		return 0;

	// Struct member (m) is not very interesting.
	if (a->kind == 'm')
		return 1;
	if (b->kind == 'm')
		return -1;

	// Global variable (v) is not very interesting.
	if (a->kind == 'v')
		return 1;
	if (b->kind == 'v')
		return -1;

	// Struct (s), union (u)
	return 0;
}

static int tag_cmp(const void *ap, const void *bp)
{
	const struct tag *a = *(const struct tag **)ap;
	const struct tag *b = *(const struct tag **)bp;
	int ret;

	ret = visibility_cmp(a, b);
	if (ret)
		return ret;

	return kind_cmp(a, b);
}

static void sort_tags(struct ptr_array *tags)
{
	current_filename = NULL;
	if (buffer->abs_filename)
		current_filename = strrchr(buffer->abs_filename, '/') + 1;

	qsort(tags->ptrs, tags->count, sizeof(tags->ptrs[0]), tag_cmp);
}

static struct file_location *create_location(void)
{
	struct file_location *loc;

	loc = xnew(struct file_location, 1);
	loc->filename = buffer->abs_filename ? xstrdup(buffer->abs_filename) : NULL;
	loc->buffer_id = buffer->id;
	loc->x = view->cx_display;
	loc->y = view->cy;
	return loc;
}

void pop_location(void)
{
	struct file_location *loc;
	struct view *v;

	if (list_empty(&location_head))
		return;
	loc = container_of(location_head.next, struct file_location, node);
	list_del(&loc->node);
	v = find_view_by_buffer_id(loc->buffer_id);
	if (!v) {
		if (loc->filename) {
			v = open_buffer(loc->filename, 1);
		} else {
			// Can't restore closed buffer which had no filename.
			free(loc->filename);
			free(loc);
			pop_location();
			return;
		}
	}
	if (v) {
		set_view(v);
		move_to_line(loc->y + 1);
		move_to_column(loc->x + 1);
	}
	free(loc->filename);
	free(loc);
}

void move_to_tag(const struct tag *t, int save_location)
{
	struct file_location *loc = NULL;
	struct view *v;

	if (save_location)
		loc = create_location();

	v = open_buffer(t->filename, 1);
	if (!v) {
		if (loc) {
			free(loc->filename);
			free(loc);
		}
		return;
	}
	if (loc)
		list_add_after(&loc->node, &location_head);

	if (view != v) {
		set_view(v);
		/* force centering view to the cursor because file changed */
		view->force_center = 1;
	}

	if (t->pattern) {
		search_tag(t->pattern);
	} else {
		move_to_line(t->line);
	}
}

static int tag_file_changed(struct tag_file *tf)
{
	struct stat st;
	fstat(tf->fd, &st);
	return st.st_mtime != tf->mtime;
}

static int load_tag_file(void)
{
	if (tag_file && tag_file_changed(tag_file)) {
		close_tag_file(tag_file);
		tag_file = NULL;
	}
	if (tag_file)
		return 1;

	tag_file = open_tag_file("tags");
	return !!tag_file;
}

static void free_tags(struct ptr_array *tags)
{
	int i;
	for (i = 0; i < tags->count; i++) {
		struct tag *t = tags->ptrs[i];
		free(t->name);
		free(t->filename);
		free(t->pattern);
		free(t->member);
		free(t->typeref);
		free(t);
	}
	free(tags->ptrs);
	memset(tags, 0, sizeof(*tags));
}

int find_tags(const char *name)
{
	struct tag *t;
	size_t pos = 0;

	if (!load_tag_file())
		return 0;

	free_tags(&current_tags);
	t = xnew(struct tag, 1);
	while (next_tag(tag_file, &pos, name, 1, t)) {
		ptr_array_add(&current_tags, t);
		t = xnew(struct tag, 1);
	}
	free(t);
	sort_tags(&current_tags);
	return 1;
}
