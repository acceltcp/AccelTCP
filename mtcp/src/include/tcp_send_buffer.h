#ifndef __TCP_SEND_BUFFER_H_
#define __TCP_SEND_BUFFER_H_

#include <stdlib.h>
#include <stdint.h>

#define NEW_SB 0 /* a new tcp_send_buffer implementation w/o memmove() */

/*----------------------------------------------------------------------------*/
typedef struct sb_manager* sb_manager_t;
/*----------------------------------------------------------------------------*/
struct tcp_send_buffer
{
	unsigned char *data;
	unsigned char *head;

	uint32_t head_off;
	uint32_t tail_off;
	uint32_t len;
#ifdef ENABLE_LOGGER
	uint64_t cum_len;
#endif
	uint32_t size;

	uint32_t head_seq;
	uint32_t init_seq;
};
/*----------------------------------------------------------------------------*/
uint32_t 
SBGetCurnum(sb_manager_t sbm);
/*----------------------------------------------------------------------------*/
sb_manager_t 
SBManagerCreate(size_t chunk_size, uint32_t cnum);
/*----------------------------------------------------------------------------*/
struct tcp_send_buffer *
SBInit(sb_manager_t sbm, uint32_t init_seq);
/*----------------------------------------------------------------------------*/
void 
SBFree(sb_manager_t sbm, struct tcp_send_buffer *buf);
/*----------------------------------------------------------------------------*/
size_t 
SBPut(sb_manager_t sbm, struct tcp_send_buffer *buf, const void *data, size_t len);
/*----------------------------------------------------------------------------*/
size_t 
SBRemove(sb_manager_t sbm, struct tcp_send_buffer *buf, size_t len);
/*----------------------------------------------------------------------------*/

#endif /* __TCP_SEND_BUFFER_H_ */
