#include "ctags.h"
#include "common.h"
#include "util.h"

struct tag_file *open_tag_file(const char *filename)
{
	struct tag_file *tf = xnew0(struct tag_file, 1);
	struct stat st;

	tf->fd = open(filename, O_RDONLY);
	if (tf->fd < 0) {
		free(tf);
		return NULL;
	}

	// don't leak file descriptor to parent processes
	fcntl(tf->fd, F_SETFD, FD_CLOEXEC);

	fstat(tf->fd, &st);
	tf->size = st.st_size;
	tf->mtime = st.st_mtime;
	tf->map = xmmap(tf->fd, 0, tf->size);
	if (!tf->map) {
		close(tf->fd);
		free(tf);
		return NULL;
	}
	return tf;
}

void close_tag_file(struct tag_file *tf)
{
	xmunmap(tf->map, tf->size);
	close(tf->fd);
}

static int parse_excmd(struct tag *t, const char *buf, int size)
{
	char ch = *buf;
	int i, line;

	if (ch == '/' || ch == '?') {
		// the search pattern is not real regular expression
		// need to escape special characters
		char *pattern = xnew(char, size * 2);
		int j = 0;

		for (i = 1; i < size; i++) {
			if (buf[i] == '\\' && i + i < size) {
				i++;
				if (buf[i] == '\\')
					pattern[j++] = '\\';
				pattern[j++] = buf[i];
				continue;
			}
			if (buf[i] == ch) {
				if (i + 2 < size && buf[i + 1] == ';' && buf[i + 2] == '"')
					i += 2;
				pattern[j] = 0;
				t->pattern = pattern;
				return i + 1;
			}
			switch (buf[i]) {
			case '*':
			case '[':
			case ']':
				pattern[j++] = '\\';
				break;
			}
			pattern[j++] = buf[i];
		}
		free(pattern);
		return 0;
	}

	line = 0;
	for (i = 0; i < size && isdigit(buf[i]); i++) {
		line *= 10;
		line += buf[i] - '0';
	}

	if (!i)
		return 0;

	if (i + 1 < size && buf[i] == ';' && buf[i + 1] == '"')
		i += 2;

	t->line = line;
	return i;
}

static int parse_line(struct tag *t, const char *buf, int size)
{
	const char *end;
	int len, si = 0;

	end = memchr(buf, '\t', size);
	if (!end)
		goto error;

	len = end - buf;
	t->name = xstrndup(buf, len);

	si = len + 1;
	if (si >= size)
		goto error;

	end = memchr(buf + si, '\t', size - si);
	len = end - buf - si;
	t->filename = xstrndup(buf + si, len);

	si += len + 1;
	if (si >= size)
		goto error;

	// excmd can contain tabs
	len = parse_excmd(t, buf + si, size - si);
	if (!len)
		goto error;

	si += len;
	if (si == size)
		return 1;

	/*
	 * Extension fields (key:[value]):
	 *
	 * file:                              visibility limited to this file
	 * struct:NAME                        tag is member of struct NAME
	 * union:NAME                         tag is member of union NAME
	 * typeref:struct:NAME::MEMBER_TYPE   MEMBER_TYPE is type of the tag
	 */
	if (buf[si] != '\t')
		goto error;

	si++;
	while (si < size) {
		int ei = si;

		while (ei < size && buf[ei] != '\t')
			ei++;

		len = ei - si;
		if (len == 1) {
			t->kind = buf[si];
		} else if (len == 5 && !memcmp(buf + si, "file:", 5)) {
			t->local = 1;
		}
		// FIXME: struct/union/typeref
		si = ei + 1;
	}
	return 1;
error:
	free(t->name);
	free(t->filename);
	return 0;
}

int next_tag(struct tag_file *tf, size_t *posp, const char *prefix, int exact, struct tag *t)
{
	size_t prefix_len = strlen(prefix);
	size_t pos = *posp;

	while (pos < tf->size) {
		size_t len = tf->size - pos;
		char *line = tf->map + pos;
		char *end = memchr(line, '\n', len);

		if (end)
			len = end - line;
		pos += len + 1;

		if (!len || line[0] == '!')
			continue;

		if (len <= prefix_len || memcmp(line, prefix, prefix_len))
			continue;

		if (exact && line[prefix_len] != '\t')
			continue;

		memset(t, 0, sizeof(*t));
		if (!parse_line(t, line, len))
			continue;

		*posp = pos;
		return 1;
	}
	return 0;
}
