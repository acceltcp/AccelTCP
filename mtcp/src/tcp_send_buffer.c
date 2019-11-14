#include <string.h>

#include "memory_mgt.h"
#include "debug.h"
#include "tcp_send_buffer.h"
#include "tcp_sb_queue.h"

#define MAX(a, b) ((a)>(b)?(a):(b))
#define MIN(a, b) ((a)<(b)?(a):(b))

/*----------------------------------------------------------------------------*/
struct sb_manager
{
	size_t chunk_size;
	uint32_t cur_num;
	uint32_t cnum;
	mem_pool_t mp;
	sb_queue_t freeq;

} sb_manager;
/*----------------------------------------------------------------------------*/
uint32_t 
SBGetCurnum(sb_manager_t sbm)
{
	return sbm->cur_num;
}
/*----------------------------------------------------------------------------*/
sb_manager_t 
SBManagerCreate(size_t chunk_size, uint32_t cnum)
{
	sb_manager_t sbm = (sb_manager_t)calloc(1, sizeof(sb_manager));
	if (!sbm) {
		TRACE_ERROR("SBManagerCreate() failed. %s\n", strerror(errno));
		return NULL;
	}

	sbm->chunk_size = chunk_size;
	sbm->cnum = cnum;
	sbm->mp = (mem_pool_t)MPCreate(chunk_size, (uint64_t)chunk_size * cnum, 0);
	if (!sbm->mp) {
		TRACE_ERROR("Failed to create mem pool for sb.\n");
		free(sbm);
		return NULL;
	}

	sbm->freeq = CreateSBQueue(cnum);
	if (!sbm->freeq) {
		TRACE_ERROR("Failed to create free buffer queue.\n");
		MPDestroy(sbm->mp);
		free(sbm);
		return NULL;
	}

	return sbm;
}
/*----------------------------------------------------------------------------*/
struct tcp_send_buffer *
SBInit(sb_manager_t sbm, uint32_t init_seq)
{
	struct tcp_send_buffer *buf;

	/* first try dequeue from free buffer queue */
	buf = SBDequeue(sbm->freeq);
	if (!buf) {
		buf = (struct tcp_send_buffer *)malloc(sizeof(struct tcp_send_buffer));
		if (!buf) {
			perror("malloc() for buf");
			return NULL;
		}
		buf->data = MPAllocateChunk(sbm->mp);
		if (!buf->data) {
			TRACE_ERROR("Failed to fetch memory chunk for data.\n");
			free(buf);
			return NULL;
		}
		sbm->cur_num++;
	}

	buf->head = buf->data;
	buf->init_seq = buf->head_seq = init_seq;
	buf->head_off = buf->tail_off = 0;
	buf->size = sbm->chunk_size;
#ifdef ENABLE_LOGGER
	buf->len = buf->cum_len = 0;
#else
	buf->len = 0;
#endif /* ENABLE_LOGGER*/

	
	return buf;
}
/*----------------------------------------------------------------------------*/
#if 0
static void 
SBFreeInternal(sb_manager_t sbm, struct tcp_send_buffer *buf)
{
	if (!buf)
		return;

	if (buf->data) {
		MPFreeChunk(sbm->mp, buf->data);
		buf->data = NULL;
	}

	sbm->cur_num--;
	free(buf);
}
#endif
/*----------------------------------------------------------------------------*/
void 
SBFree(sb_manager_t sbm, struct tcp_send_buffer *buf)
{
	if (!buf)
		return;

	SBEnqueue(sbm->freeq, buf);
}
/*----------------------------------------------------------------------------*/
size_t 
SBPut(sb_manager_t sbm, struct tcp_send_buffer *buf, const void *data, size_t len)
{
	size_t to_put;

	if (len <= 0)
		return 0;

	/* if no space, return -2 */
	to_put = MIN(len, buf->size - buf->len);
	if (to_put <= 0) {
		return -2;
	}
	
#if NEW_SB
	if (buf->head_off < buf->tail_off) {
		if (buf->tail_off + to_put <= buf->size) {
			/* copy to the contiguous memory region */
			memcpy(buf->data + buf->tail_off, data, to_put);
			buf->tail_off += to_put;			
		}
		else {
			/* copy twice for wrap-around cases */
			memcpy(buf->data + buf->tail_off, data, (buf->size - buf->tail_off));
			memcpy(buf->data, data + (buf->size - buf->tail_off),
				   to_put - (buf->size - buf->tail_off));
			buf->tail_off = to_put - (buf->size - buf->tail_off);
		}
	}
	else {
		/* copy to the contiguous memory region */
		memcpy(buf->data + buf->tail_off, data, to_put);
		buf->tail_off += to_put;		
	}
#else
	if (buf->tail_off + to_put < buf->size) {
		/* if the data fit into the buffer, copy it */
		memcpy(buf->data + buf->tail_off, data, to_put);
		buf->tail_off += to_put;
	} else {
		/* if buffer overflows, move the existing payload and merge */
		memmove(buf->data, buf->head, buf->len);
		buf->head = buf->data;
		buf->head_off = 0;
		memcpy(buf->head + buf->len, data, to_put);
		buf->tail_off = buf->len + to_put;
	}
#endif
	
	buf->len += to_put;
#ifdef ENABLE_LOGGER
	buf->cum_len += to_put;
#endif

	return to_put;
}
/*----------------------------------------------------------------------------*/
size_t 
SBRemove(sb_manager_t sbm, struct tcp_send_buffer *buf, size_t len)
{
	size_t to_remove;

	if (len <= 0)
		return 0;

	to_remove = MIN(len, buf->len);
	if (to_remove <= 0) {
		return -2;
	}
	
#if NEW_SB
	if (buf->head_off < buf->tail_off) {
		buf->head_off += to_remove;
		buf->head = buf->data + buf->head_off;
		buf->head_seq += to_remove;
		buf->len -= to_remove;
	}
	else {
		if (buf->head_off + to_remove < buf->size) {
			buf->head_off += to_remove;
			buf->head = buf->data + buf->head_off;
			buf->head_seq += to_remove;
			buf->len -= to_remove;			
		}
		else {
			/* handle the wrap-around case */
			buf->head_off = buf->head_off + to_remove - buf->size;
			buf->head = buf->data + buf->head_off;
			buf->head_seq += to_remove;
			buf->len -= to_remove;
		}
	}
	
#else
	buf->head_off += to_remove;
	buf->head = buf->data + buf->head_off;
	buf->head_seq += to_remove;
	buf->len -= to_remove;
#endif
	
	/* if buffer is empty, move the head to 0 */
	if (buf->len == 0 && buf->head_off > 0) {
		buf->head = buf->data;
		buf->head_off = buf->tail_off = 0;
	}

	return to_remove;
}
/*---------------------------------------------------------------------------*/
