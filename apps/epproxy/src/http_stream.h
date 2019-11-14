#include <sys/queue.h>
#include "backend_pool.h"
#ifndef HTTP_STREAM_H 
#define HTTP_STREAM_H 
/*----------------------------------------------------------------------------*/
typedef struct http_buf {
	int   cnt_refs;			/* number of references by http_stream */
	char *data;			    /* payload buffer */
	int   data_len;			/* bytes used in the payload buffer */

	TAILQ_ENTRY (http_buf) link;

} http_buf;
/*----------------------------------------------------------------------------*/
typedef struct http_stream {
	int sock;               /* socket of itself */
	int peer_sock;	        /* socket to its peer (frontend <-> backend) */
	int write_blocked;      /* whether its socket is blocked to write */
	int keep_alive;         /* (frontend) whether it is a keep-alive connection */
	int wait_header;	    /* true if waiting for header */
	char* uri;

	int is_front;
	int64_t bytes_to_write; /* (frontend) bytes to write */

	http_buf *rbuf;	        /* read buffer for its http payload */
	http_buf *wbuf;         /* write buffer for its http payload */

	struct backend_info* backend;

	int is_spare;            /* connections that can be reused */
	int is_health_check;     /* connections used for health check */
	int is_connecting;       /* try connecting to backend server */

	int nif_out;


	TAILQ_ENTRY (http_stream) link;

} http_stream;
/*----------------------------------------------------------------------------*/
#endif
