#include "iter.h"

void block_iter_normalize(struct block_iter *bi)
{
	struct block *blk = bi->blk;

	if (bi->offset == blk->size && blk->node.next != bi->head) {
		bi->blk = BLOCK(blk->node.next);
		bi->offset = 0;
	}
}

// analogous to *ptr++
unsigned int block_iter_next_byte(struct block_iter *i, uchar *byte)
{
	if (i->offset == i->blk->size) {
		if (i->blk->node.next == i->head)
			return 0;
		i->blk = BLOCK(i->blk->node.next);
		i->offset = 0;
	}
	*byte = (unsigned char)i->blk->data[i->offset];
	i->offset++;
	return 1;
}

// analogous to *--ptr
unsigned int block_iter_prev_byte(struct block_iter *i, uchar *byte)
{
	if (!i->offset) {
		if (i->blk->node.prev == i->head)
			return 0;
		i->blk = BLOCK(i->blk->node.prev);
		i->offset = i->blk->size;
	}
	i->offset--;
	*byte = (unsigned char)i->blk->data[i->offset];
	return 1;
}

unsigned int block_iter_next_line(struct block_iter *bi)
{
	struct block *blk;
	unsigned int offset;
	unsigned int new_offset;
	const char *end;

	block_iter_normalize(bi);

	blk = bi->blk;
	offset = bi->offset;

	end = memchr(blk->data + offset, '\n', blk->size - offset);
	if (!end) {
		bi->offset = blk->size;
		return 0;
	}
	new_offset = end + 1 - blk->data;
	if (new_offset == blk->size && blk->node.next == bi->head) {
		bi->offset = new_offset;
		return 0;
	}

	bi->offset = new_offset;
	return bi->offset - offset;
}

/*
 * Move to beginning of previous line.
 * Returns number of bytes moved which is zero if there's no previous line.
 */
unsigned int block_iter_prev_line(struct block_iter *bi)
{
	struct block *blk = bi->blk;
	unsigned int offset = bi->offset;
	unsigned int start = offset;

	while (offset && blk->data[offset - 1] != '\n')
		offset--;

	if (!offset) {
		if (blk->node.prev == bi->head)
			return 0;
		bi->blk = blk = BLOCK(blk->node.prev);
		offset = blk->size;
		start += offset;
	}

	offset--;
	while (offset && blk->data[offset - 1] != '\n')
		offset--;
	bi->offset = offset;
	return start - offset;
}

unsigned int block_iter_bol(struct block_iter *bi)
{
	unsigned int offset, ret;

	block_iter_normalize(bi);

	offset = bi->offset;
	if (!offset)
		return 0;

	while (offset && bi->blk->data[offset - 1] != '\n')
		offset--;

	ret = bi->offset - offset;
	bi->offset = offset;
	return ret;
}

unsigned int block_iter_eol(struct block_iter *bi)
{
	struct block *blk;
	unsigned int offset;
	const char *end;

	block_iter_normalize(bi);

	blk = bi->blk;
	offset = bi->offset;

	end = memchr(blk->data + offset, '\n', blk->size - offset);
	bi->offset = end - blk->data;
	if (!end)
		bi->offset = blk->size;
	return bi->offset - offset;
}

void block_iter_skip_bytes(struct block_iter *bi, unsigned int count)
{
	struct block *blk = bi->blk;
	unsigned int offset = bi->offset;

	while (1) {
		unsigned int avail = blk->size - offset;

		if (count <= avail) {
			bi->blk = blk;
			bi->offset = offset + count;
			return;
		}
		blk = BLOCK(blk->node.next);
		count -= avail;
		offset = 0;
	}
}

void block_iter_goto_offset(struct block_iter *bi, unsigned int offset)
{
	struct block *blk;

	list_for_each_entry(blk, bi->head, node) {
		if (offset <= blk->size) {
			bi->blk = blk;
			bi->offset = offset;
			return;
		}
		offset -= blk->size;
	}
}

unsigned int block_iter_get_offset(struct block_iter *bi)
{
	struct block *blk;
	unsigned int offset = 0;

	list_for_each_entry(blk, bi->head, node) {
		if (blk == bi->blk)
			break;
		offset += blk->size;
	}
	return offset + bi->offset;
}

// bi should be at bol
void fill_line_ref(struct block_iter *bi, struct lineref *lr)
{
	unsigned int max;
	const char *ptr, *nl;

	block_iter_normalize(bi);

	max = bi->blk->size - bi->offset;
	ptr = bi->blk->data + bi->offset;
	nl = memchr(ptr, '\n', max);

	lr->line = ptr;
	lr->size = nl ? nl - ptr : max;
}

void fill_line_nl_ref(struct block_iter *bi, struct lineref *lr)
{
	unsigned int max;
	const char *ptr, *nl;

	block_iter_normalize(bi);

	max = bi->blk->size - bi->offset;
	ptr = bi->blk->data + bi->offset;
	nl = memchr(ptr, '\n', max);

	lr->line = ptr;
	lr->size = nl ? nl - ptr + 1 : max;
}

unsigned int fetch_this_line(const struct block_iter *bi, struct lineref *lr)
{
	struct block_iter tmp = *bi;
	unsigned int count = block_iter_bol(&tmp);

	fill_line_ref(&tmp, lr);
	return count;
}
