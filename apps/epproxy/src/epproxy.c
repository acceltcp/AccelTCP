/*********************************************************************
 * epproxy.(c/h)
 * - a sample event-driven HTTP proxy & load balancing application
 * - supports HTTP GET only (no support for PUT, POST, CONNECT)
 ********************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>
#include <sys/epoll.h>
#include <sys/queue.h>
#include <sys/resource.h>
#include "util.h"
#include "config.h"
#include "http_parser.h"
#include "http_stream.h"
#include "mtcp_epoll.h"
#include "balance.h"
#include "hash.h"
#include "epproxy.h"
/*----------------------------------------------------------------------------*/
#ifndef TRUE
#define TRUE (1)
#endif
#ifndef FALSE
#define FALSE (0)
#endif
/*----------------------------------------------------------------------------*/
#define MAX_CPUS      (64)
#define MAX_FLOW_NUM  (1000000)
#define MAX_EVENTS    (MAX_FLOW_NUM * 3)
/*----------------------------------------------------------------------------*/
static pthread_t mtcp_thread[MAX_CPUS];
static int num_cores_used;
static int max_concurrency;
static int num_cores;
static int g_conf_splice = 1;
static struct mtcp_conf g_mcfg;
/*----------------------------------------------------------------------------*/
struct route_table
{
	uint32_t daddr;
	uint32_t mask;
	uint32_t masked;
	int prefix;
	int nif;
};
/*----------------------------------------------------------------------------*/
#define HTTPRespFormat "HTTP/%s %s\r\nContent-Type: text/html\r\n\r\n"
const char* const HTTPStatusMsg[] = {"",
									 "",
									 "",									 
									 "400 Bad Request",
									 "501 Not Implemented",
									 "505 HTTP Version Not Supported"};
/*----------------------------------------------------------------------------*/
static inline void
RegisterEvent(struct thread_context *ctx, int sock, uint32_t events)
{
	int ret;
#if USE_MTCP
    struct mtcp_epoll_event ev;
	switch (events) {
	case EPOLLIN:
		ev.events = MTCP_EPOLLIN;
		break;
	case EPOLLOUT:
		ev.events = MTCP_EPOLLOUT;
		break;
	default:
		TRACE_ERROR("This should not happen!\n");
		exit(-1);
	}
    ev.data.sockid = sock;
#else
	struct epoll_event ev;
    ev.events = events;
    ev.data.fd = sock;
#endif

#if USE_MTCP
    ret = mtcp_epoll_ctl(ctx->mctx, ctx->ep, EPOLL_CTL_ADD, sock, &ev);
#else
	ret = epoll_ctl(ctx->ep, EPOLL_CTL_ADD, sock, &ev);
#endif
	if (ret < 0 && errno != EEXIST) {
		TRACE_ERROR("epoll_ctl() with EPOLL_CTL_ADD error\n");
		exit(-1);
	}	
}
/*---------------------------------------------------------------------------*/
static inline void
ModifyEvent(struct thread_context *ctx, int sock, uint32_t events)
{
	int ret;
#if USE_MTCP
	struct mtcp_epoll_event ev;
	switch (events) {
	case EPOLLIN:
		ev.events = MTCP_EPOLLIN;
		break;
	case EPOLLOUT:
		ev.events = MTCP_EPOLLOUT;
		break;
	default:
		TRACE_ERROR("This should not happen!\n");
		exit(-1);
	}
	ev.data.sockid = sock;
#else
	struct epoll_event ev;
	ev.events = events;
	ev.data.fd = sock;
#endif
	
#if USE_MTCP
	ret = mtcp_epoll_ctl(ctx->mctx, ctx->ep, EPOLL_CTL_MOD, sock, &ev);
#else
	ret = epoll_ctl(ctx->ep, EPOLL_CTL_MOD, sock, &ev);
#endif
	if (ret < 0 && errno != EEXIST) {
		TRACE_ERROR("epoll_ctl() with EPOLL_CTL_MOD error (errno = %d)\n", errno);
		exit(-1);
	}	
}
/*---------------------------------------------------------------------------*/
static inline void
UnregisterEvent(struct thread_context *ctx, int sock)
{
	int ret;
#if USE_MTCP
	ret = mtcp_epoll_ctl(ctx->mctx, ctx->ep, EPOLL_CTL_DEL, sock, NULL);
#else
	ret = epoll_ctl(ctx->ep, EPOLL_CTL_DEL, sock, NULL);
#endif
	if (ret < 0 && errno != EEXIST) {
		//		TRACE_ERROR("epoll_ctl() with EPOLL_CTL_DEL error\n");
		//		exit(-1);
	}
}
/*-----------------------------------------------------------------*/
static void
FreeBuffer(struct thread_context *ctx, http_buf *buf, int is_splice)
{
	if (buf == NULL)
		return;	

	/* add it to the free list, only if nobody uses this buffer */
	if (is_splice)
		buf->cnt_refs = 0;
	else
		buf->cnt_refs--;
	if (buf->cnt_refs == 0) {
		TAILQ_INSERT_TAIL(&ctx->free_hbmap, buf, link);
		buf->data_len = 0;
	}
}
/*-----------------------------------------------------------------*/
static void
CloseHTTPStream(struct thread_context *ctx, int fd)
{	
	struct http_stream* hs = &ctx->stream[fd];

	/* unregister from any event before closing it */
	UnregisterEvent(ctx, fd);

	if (hs->is_spare) {
		/* returning back the idle connection to reuse */
		/* (put back to the idle connection pool) */
		TAILQ_INSERT_TAIL(&(hs->backend->idle_conns[ctx->cpu]),
						  &ctx->stream[fd], link);
	}
	else {
#if USE_MTCP
		mtcp_close(ctx->mctx, fd);
#else
		close(fd);
#endif
	}
	
	FreeBuffer(ctx, hs->rbuf, 0);
	FreeBuffer(ctx, hs->wbuf, 0);
	
	if (hs->peer_sock >= 0) {
		ctx->stream[hs->peer_sock].peer_sock = -1;
	}

}
/*-----------------------------------------------------------------*/
static int 
CreateListeningSocket(struct thread_context *ctx)
{
	int listener;
	int ret;

	/* create socket and set it as nonblocking */
#if USE_MTCP
	listener = mtcp_socket(ctx->mctx, AF_INET, SOCK_STREAM, 0);
#else
	listener = socket(AF_INET, SOCK_STREAM, 0);
#endif
	if (listener < 0) {
		TRACE_ERROR("Failed to create listening socket!\n");
		return -1;
	}

#if !USE_MTCP
	/* we won't linger on close (as mTCP does) */
	struct linger linger_opt;
	linger_opt.l_onoff = 0;
	linger_opt.l_linger = 0;
	if (setsockopt(listener, SOL_SOCKET, SO_LINGER,
				   &linger_opt, sizeof(linger_opt)) < 0) {
		TRACE_ERROR("Failed to turn off linger option\n");
		return -1;
	}
	
	/* reuse address */
	int reuse_opt = 1;
	if (setsockopt(listener, SOL_SOCKET, SO_REUSEADDR,
				   &reuse_opt, sizeof(reuse_opt)) < 0) {
		TRACE_ERROR("Failed to turn on reuse option\n");
		return -1;
	}
#endif

#if USE_MTCP
	ret = mtcp_setsock_nonblock(ctx->mctx, listener);
#else
	ret = fcntl(listener, F_SETFL, O_NONBLOCK);
#endif
	if (ret < 0) {
		TRACE_ERROR("Failed to set socket in nonblocking mode.\n");
		return -1;
	}

	/* bind to a listening port */
#if USE_MTCP
	ret = mtcp_bind(ctx->mctx, listener,
					(struct sockaddr *)&(g_prx_ctx->listen_addr),
					sizeof(struct sockaddr_in));
#else
	ret = bind(listener,
			   (struct sockaddr *)&(g_prx_ctx->listen_addr),
			   sizeof(struct sockaddr_in));
#endif
	if (ret < 0) {
		TRACE_ERROR("Failed to bind to the listening socket!\n");
		return -1;
	}

	/* listening backlog = 4096 */
#if USE_MTCP
	ret = mtcp_listen(ctx->mctx, listener, 4096);
#else
	ret = listen(listener, 4096);
#endif
	if (ret < 0) {
		TRACE_ERROR("Listening to a socket failed!\n");
		return -1;
	}
	
	/* wait for incoming accept events */
	RegisterEvent(ctx, listener, EPOLLIN);

	return listener;
}
/*----------------------------------------------------------------------------*/
inline int
GetOutputNetworkInterface(uint32_t daddr)
{
	int nif = -1;
	int i;
	int prefix = 0;

	/* Longest prefix matching */
	for (i = 0; i < g_mcfg.routes; i++) {
		if ((daddr & g_mcfg.rtable[i].mask) == g_mcfg.rtable[i].masked) {
			if (g_mcfg.rtable[i].prefix > prefix) {
				nif = g_mcfg.rtable[i].nif;
				prefix = g_mcfg.rtable[i].prefix;
			}
			break;
		}
	}
	
	return nif;
}
/*------------------------------------------------------------------------*/
static int 
AcceptHTTPSession(struct thread_context *ctx, int listener)
{
	int c, ret;
	struct http_stream *hs;
	struct sockaddr addr;
	socklen_t addrlen;
	
#if USE_MTCP
	c = mtcp_accept(ctx->mctx, listener, &addr, &addrlen);
#else
	c = accept(listener, &addr, &addrlen);
#endif
	if (c < 0) {
		if (errno == EAGAIN)
			return -1;
		TRACE_ERROR("Failed to accept incoming connection.\n");
		exit(-1);
	}
	if (c >= max_concurrency) {
		TRACE_ERROR("sock id (%d) exceeds the max concurrency (%d).\n",
					c, max_concurrency);
		exit(-1);
	}

	struct sockaddr_in *addr_in = (struct sockaddr_in *)&addr;
	int nif_out = GetOutputNetworkInterface(addr_in->sin_addr.s_addr);
	if (nif_out < 0) {
		TRACE_ERROR("No interface for output!\n");
		exit(-1);
	}

#if USE_MTCP
	ret = mtcp_setsock_nonblock(ctx->mctx, c);
#else
	ret = fcntl(c, F_SETFL, O_NONBLOCK);
#endif
	if (ret < 0)
		TRACE_ERROR("setting socket %d nonblocking returns error\n", c);
		
	/* initialize HTTP stream structure */
	hs = &ctx->stream[c];
	memset(hs, 0, sizeof(http_stream));
	hs->sock = c;
	hs->wait_header = 1;
	hs->peer_sock = -1;  /* no backend server on startup */
	hs->is_front = 1;
	hs->backend = NULL;
	hs->nif_out = nif_out;
	
	RegisterEvent(ctx, c, EPOLLIN);

	return c;
}
/*-----------------------------------------------------------------*/
static void
test_cb(nsplice_meta_t* meta) {
	printf("A spliced connection finished\n"
			"close_reason:	%X\n"
			"ip_addr:	%x\n"
			"port:		%u\n"
			"dst_addr:	%x\n"
			"dst_port:	%u\n"
			"\n",
			ntohs(meta->close_reason),
			ntohl(meta->ip_addr),
			ntohs(meta->port),
			ntohl(meta->dst_addr),
			ntohs(meta->dst_port));
}
/*-----------------------------------------------------------------*/
static int
WriteAvailData(struct thread_context *ctx, int fd)
{
	http_stream *hs = &ctx->stream[fd];
	http_buf *fb = hs->wbuf;
	int res;

	/* it should be the spare connections just established */
	if (hs->is_spare && hs->is_connecting) {
		assert(hs->sock == fd);

		hs->is_connecting = 0;
		TAILQ_INSERT_TAIL(&(hs->backend->idle_conns[ctx->cpu]),
						  hs, link);
		return 0;
	}

	if (hs->is_health_check && hs->is_connecting) {
		TRACE_ERROR("established a connection for health check\n");
		assert(hs->sock == fd);
		hs->is_connecting = 0;
		hs->backend->hc_conn = hs;
		return 0;
	}

	if (fb->data_len < 1 || hs->write_blocked == 1) {
		return 0;
	}

#if USE_MTCP
	res = mtcp_write(ctx->mctx, fd, fb->data, fb->data_len);
#else
	res = write(fd, fb->data, fb->data_len);
#endif
	if (res < 0) {
		/* we might have been full but didn't realize it */
		if (errno == EAGAIN) {
			hs->write_blocked = 1;
			ModifyEvent(ctx, fd, EPOLLOUT);
			return 0;
		}
		
		/* error occured while writing to remote host */
		return -1;
	}

	if (g_conf_splice) {
		UnregisterEvent(ctx, fd);
		if (mtcp_splice(ctx->mctx, hs->peer_sock, fd, test_cb) < 0) {
			fprintf(stderr, "mtcp_splice() returns an error\n");
			exit(-1);
		}
		/* forget about sockets (for now) */
		FreeBuffer(ctx, hs->rbuf, 1);
		FreeBuffer(ctx, hs->wbuf, 1);
		return 0;
	}
	
	/* if (res > 0) */
	fb->data_len -= res;

	if (hs->is_front && hs->keep_alive) {
		hs->bytes_to_write -= res;
		
		/* mismatch cases (exit for debugging purposes now) */
		if (hs->bytes_to_write < 0 ||
			(hs->bytes_to_write == 0 && fb->data_len > 0)) {
			fprintf(stderr, "content-length mismatch (bytes_to_write: %d, data_len: %d)\n",
					(int) hs->bytes_to_write, fb->data_len);
			exit(-1);				
		}
		
		/* finished a HTTP GET, so wait for the next connection */
		if (hs->bytes_to_write == 0) {
			if (hs->wbuf->data_len > 0 || hs->rbuf->data_len > 0) {
				fprintf(stderr, "hs->wbuf->data_len = %d, hs->rbuf->data_len = %d\n",
						hs->wbuf->data_len, hs->rbuf->data_len);
				exit(-1);
			}

			/* backend connection is already closed */
			if (hs->peer_sock < 0) {
				CloseHTTPStream(ctx, fd);
				return 0;
			}
			
			/* if (hs->peer_sock >= 0) */
			/* backend server may close the connection */
			ModifyEvent(ctx, fd, EPOLLIN);
			ModifyEvent(ctx, hs->peer_sock, EPOLLIN);

			hs->wait_header = 1;
			ctx->stream[hs->peer_sock].wait_header = 1;

		}
	}

	/* since we could not write all, assume that it's blocked */
	if (fb->data_len > 0) {
		memmove(fb->data, &fb->data[res], fb->data_len);
		hs->write_blocked = 1;
		ModifyEvent(ctx, fd, EPOLLOUT);
	}

	return 0;
}
/*-----------------------------------------------------------------*/
static int
ConnectToBackend(struct thread_context *ctx,
				 struct sockaddr_in* backend_addr)
{
	int ret, backend_fd;

	/* create a connection (no connection in the list) */
#if USE_MTCP
	backend_fd = mtcp_socket(ctx->mctx, AF_INET, SOCK_STREAM, 0);
#else
	backend_fd = socket(AF_INET, SOCK_STREAM, 0);
#endif
	if (backend_fd < 0) {
		TRACE_ERROR("error when creating a socket");
		return -1;
	}
	if (backend_fd >= max_concurrency) {
		TRACE_ERROR("invalid socket id %d.\n", backend_fd);
		return -1;
	}
#if USE_MTCP
	ret = mtcp_setsock_nonblock(ctx->mctx, backend_fd);
#else
	ret = fcntl(backend_fd, F_SETFL, O_NONBLOCK);
#endif
	if (ret < 0) {
		TRACE_ERROR("failed to set socket in nonblocking mode.\n");
		return -1;
	}
		
	/* connect to a backend server */
#if USE_MTCP
	ret = mtcp_connect(ctx->mctx,
					   backend_fd,
					   (struct sockaddr*) backend_addr,
					   sizeof(struct sockaddr_in));
#else
	ret = connect(backend_fd,
				  (struct sockaddr*) backend_addr,
				  sizeof(struct sockaddr_in));
#endif
	if (ret < 0 && errno != EINPROGRESS) {

		//		TRACE_ERROR("failed to connect to a backend server\n");
#if USE_MTCP
		mtcp_close(ctx->mctx, backend_fd);
#else
		close(backend_fd);
#endif

		return -1;
	}
	
	return backend_fd;
}
/*-----------------------------------------------------------------*/
static void
CreateBackendConn(struct thread_context *ctx, int front_fd)
{
	int backend_fd;
	http_stream *backend_hs;	
	struct sockaddr_in* backend_addr;
	int is_spare = 0;
	struct backend_info* backend;

	backend = ctx->stream[front_fd].backend;		
	backend_addr = &(backend->addr);

	/* find for any idle persistent connection to backend */
	backend_hs = TAILQ_FIRST(&(backend->idle_conns[ctx->cpu]));
	if (backend_hs) {
		/* if there is, reuse the connection */
		TAILQ_REMOVE(&(backend->idle_conns[ctx->cpu]),
					 backend_hs, link);
		backend_fd = backend_hs->sock;
		assert(backend_hs->is_spare == 1);
		is_spare = 1;
	}
	else {
		if ((backend_fd = ConnectToBackend(ctx, backend_addr)) < 0) {
			// TRACE_ERROR("ConnectToBackend() error\n");
			CloseHTTPStream(ctx, front_fd);
			return;
			//			exit(-1);
		}
		backend_hs = &ctx->stream[backend_fd];
	}

	/* record the socket number of peer HTTP stream */
	ctx->stream[front_fd].peer_sock = backend_fd;

	/* initialize HTTP stream structure */
	memset(backend_hs, 0, sizeof(http_stream));
	backend_hs->sock = backend_fd;
	backend_hs->peer_sock = front_fd;
	backend_hs->backend = ctx->stream[front_fd].backend;
	backend_hs->is_spare = is_spare;
	
	/* forward from front's read buf to backend write buf */
	backend_hs->wbuf = ctx->stream[front_fd].rbuf; 
	ctx->stream[front_fd].rbuf->cnt_refs++;

	if (is_spare) {
		/* try writing available data in the buffer including that we read */
		if (WriteAvailData(ctx, backend_fd) < 0) {
			TRACE_ERROR("WriteAvailData() error\n");
			/* close both side of HTTP stream */
			CloseHTTPStream(ctx, backend_fd);
			if (backend_hs->peer_sock >= 0) {
				CloseHTTPStream(ctx, backend_hs->peer_sock);
				backend_hs->peer_sock = -1;
			}
		}
		ModifyEvent(ctx, backend_fd, EPOLLIN);
	}
	else { 
		/* use nonblocking mode, so wait until it's ready to write */
		backend_hs->write_blocked = 1;
		RegisterEvent(ctx, backend_fd, EPOLLOUT);
	}

	backend_hs->wait_header = 1;

}
/*----------------------------------------------------------------------------*/
inline void
RewriteHostField(struct http_stream *hs, char *host_pos)
{
	char *end;
	char *temp = host_pos;
	char temp_char;
	int removeLen;

	if ((end = strstr(hs->rbuf->data, CRLFCRLF)))
		end += (sizeof(CRLFCRLF) - 1);
	else if ((end = strstr(hs->rbuf->data, LFLF))) 
		end += (sizeof(LFLF) - 1);
	
	for (; (*temp) != '\r' && (*temp) != '\n'; temp++) {
		if ((*temp) == 0) {
			TRACE_ERROR("wrong host field (should not happen)\n");
			exit(-1);
		}
	}
	
	temp_char = (*temp);
	(*temp) = 0;
	//	TRACE_ERROR("host_pos: [%s]\n", host_pos);
	removeLen = strlen(host_pos);
	(*temp) = temp_char;
	
	char* ip = inet_ntoa(hs->backend->addr.sin_addr);

    /* memmove the fields coming after Host to the right position */
	if (strlen(ip) != removeLen)
	    memmove(host_pos + strlen(ip),
				host_pos + removeLen,
				(end - host_pos) - removeLen);

    /* overwrite the Host field with insert */
	memcpy(host_pos, ip, strlen(ip));
	
	hs->rbuf->data_len += (strlen(ip) - removeLen);
	
}
/*----------------------------------------------------------------------------*/
static void 
HandleReadEvent(struct thread_context *ctx, int fd)
{
	int space_left, res;
	http_stream *hs;
	char err_http_resp[PB_ALLOCSIZE];
	char* host_pos = NULL;
	struct sticky_ent *st_ent;

	/* if peer is closed, close ourselves */
	hs = &ctx->stream[fd];
	if (hs->peer_sock < 0 && (!hs->wait_header)) {
		CloseHTTPStream(ctx, fd);
		return;
	}

	/* if there is no read buffer in this stream, bring one from free list */
	if (hs->rbuf == NULL) {
		hs->rbuf = TAILQ_FIRST(&ctx->free_hbmap);
		if (!hs->rbuf) {
			fprintf(stderr, "alloc from free_hbmap fails\n");
			exit(-1);
		}
		TAILQ_REMOVE(&ctx->free_hbmap, hs->rbuf, link);

		/* (for safety) check if the given buffer is being used or has data */
		if (hs->rbuf->cnt_refs > 0) {
			fprintf(stderr, "(should not happen) there are still some refs.\n");
			exit(-1);
		}
		if (hs->rbuf->data_len > 0) {
			fprintf(stderr, "(should not happen) there are still some data.\n");
			exit(-1);
		}

		/* if there is no peer stream, it is referenced by one HTTP stream */
		if (hs->peer_sock < 0) {
			hs->rbuf->cnt_refs = 1;
		}
		/* if there is a peer stream, it is referenced by two HTTP streams */
		else {
			ctx->stream[hs->peer_sock].wbuf = hs->rbuf;
			hs->rbuf->cnt_refs = 2;
		}
	}
	/* make sure that it has payload buffer which is allocated during init */
	if (!hs->rbuf->data) {
		fprintf(stderr, "hs->rbuf holds a NULL buffer\n");
		exit(-1);
	}

	/* check if there is any remaining space in read buffer 
	 * (reserve the last byte of read buffer to allow putting null 
	 * for strstr in buffer full case) */
	if ((space_left = PB_READSIZE - hs->rbuf->data_len - 1) <= 0) {
		/* if buffer is full but header could not be parsed, raise an error */
		if (hs->wait_header) {
			TRACE_ERROR("[sock %d] header length is larger than read buffer "
						"(buf_size: %d, is_front: %d) [%s]\n",
						fd, PB_READSIZE - 1, hs->is_front, hs->rbuf->data);
			fprintf(stderr, "\n");
			exit(-1);

			CloseHTTPStream(ctx, fd);
			return;
		}
		/* for HTTP body part, it can unregister from read event for a while */
		else {
			UnregisterEvent(ctx, fd);
			return;
		}
	} 
  
#if	USE_MTCP
	res = mtcp_read(ctx->mctx, fd, &hs->rbuf->data[hs->rbuf->data_len], space_left);
#else
	res = read(fd, &hs->rbuf->data[hs->rbuf->data_len], space_left);
#endif
	/* when a connection closed by remote host */	
	if (res == 0) {
		CloseHTTPStream(ctx, fd);
		if (hs->rbuf->data_len == 0 && hs->peer_sock >= 0) {
			CloseHTTPStream(ctx, hs->peer_sock);
			hs->peer_sock = -1;
		}
		return;
	}

	/* read is unavailable or an error occured */	
	if (res == -1) {
		if (errno != EAGAIN) {
			TRACE_ERROR("mtcp_read() error\n");
			CloseHTTPStream(ctx, fd);
			if (hs->rbuf->data_len == 0 && hs->peer_sock >= 0) {
				CloseHTTPStream(ctx, hs->peer_sock);
				hs->peer_sock = -1;
			}
		}
		return;
	}

	/* res > 0 */
	hs->rbuf->data_len += res;
	hs->rbuf->data[hs->rbuf->data_len] = 0;
	
	/* try parsing the header after reading some payload */
	if (hs->wait_header && hs->is_front) {

		/* add/remove backend server via REST API */
		/*
		if (!strncmp(hs->rbuf->data, "PUT ", sizeof("PUT ") - 1)) {
			char ip[MAX_IPADDR_STRLEN];
			uint16_t port;
			struct sockaddr_in baddr;		
			if (sscanf(hs->rbuf->data + (sizeof("PUT ") - 1), "%[0-9.]:%hu", ip, &port) == 2) {
				TRACE_INFO("adding %s:%d to backend server pool..\n", ip, port);
				baddr.sin_family = AF_INET;
				baddr.sin_addr.s_addr = inet_addr(ip);
				baddr.sin_port = htons(port);
				int ret = add_to_bpool(&g_prx_ctx->bpool[x], &baddr, "", 1);
				printf("add_to_bpool() returns %d\n", ret);
			}
			CloseHTTPStream(ctx, fd);
			return;
		}

		if (!strncmp(hs->rbuf->data, "DELETE ", sizeof("DELETE ") - 1)) {
			char ip[MAX_IPADDR_STRLEN];
			uint16_t port;
			struct sockaddr_in baddr;
			if (sscanf(hs->rbuf->data + (sizeof("DELETE ") - 1), "%[0-9.]:%hu", ip, &port) == 2) {				
				TRACE_INFO("removing %s:%d from backend server pool..\n", ip, port);
				baddr.sin_family = AF_INET;
				baddr.sin_addr.s_addr = inet_addr(ip);
				baddr.sin_port = htons(port);
				int ret = remove_from_bpool_by_addr(&g_prx_ctx->bpool[x], &baddr);
				printf("remove_from_bpool_by_addr() returns %d\n", ret);
			}
			CloseHTTPStream(ctx, fd);
			return;
		}
		*/
		
		/* try parsing the HTTP request from incoming payload */
		if ((res = ParseHTTPRequest(hs, &host_pos)) != RR_DONE) {
			/* we should wait for the remaining header */
			if (res == RR_MORE)
				return;

			/* this is only for ParseHTTPResponse */
			assert(res != RR_ERROR_RESPONSE);
			
			/* unless, we have to write error message to client */
			sprintf(err_http_resp, HTTPRespFormat,
					HTTP_DEFAULT_VER,
					HTTPStatusMsg[res]);
#if USE_MTCP
			mtcp_write(ctx->mctx, fd, err_http_resp, strlen(err_http_resp));
#else
			if (write(fd, err_http_resp, strlen(err_http_resp)) < 0)
				TRACE_ERROR("write() error\n");			
#endif
			CloseHTTPStream(ctx, fd);
			return;
		}

		/* now we have parsed the header (RR_DONE) */
		hs->wait_header = 0;
		
		/* Handle persistent session */	
		if (HandleRequestPersistence(&ctx->sticky_map, hs)
			!= RES_FOUND_PERSIST) {
			/* if it does not meet the condition for persistent session,
			   run load balancing algorithm */
			DecideBackendServer(&(ctx->sticky_map), &(ctx->rr_count), hs);
		}

		/* so let's connect to the backend server */
		if (hs->peer_sock < 0) {
			/* case 1: create a new connection (or bring one from pool) */
			CreateBackendConn(ctx, fd);
			return;
		}
		else {	/* hs->peer_sock >= 0 */
			/* case 2: keep-alive connection is still going on */
			assert(hs->keep_alive);

			/* proceed and write available data (= request) to server */
			/* (you already have a backend connetion, go ahead) */		
			ModifyEvent(ctx, hs->peer_sock, EPOLLIN);
		}
	}
	else if (hs->wait_header && !hs->is_front) {
		assert(hs->peer_sock >= 0);

		if ((res = ParseHTTPResponse(hs, &ctx->stream[hs->peer_sock])) != RR_DONE) {
			/* we should wait for the remaining payload */
			if (res == RR_MORE)
				return;

			/* unless, server sent me a malformed or invalid header */
			assert(res == RR_ERROR_RESPONSE);
			TRACE_ERROR("RR_ERROR_RESPONSE\n");
			CloseHTTPStream(ctx, fd);
			if (hs->peer_sock >= 0) {
				CloseHTTPStream(ctx, hs->peer_sock);
				hs->peer_sock = -1;
			}
			return;
		}
		
		st_ent = calloc(1, sizeof(struct sticky_ent));
		if (!st_ent) {
			TRACE_ERROR("calloc() error\n");
			exit(-1);
		}

		HandleResponsePersistence(&(ctx->sticky_map),
								  hs,
								  &(ctx->stream[hs->peer_sock]),
								  st_ent->value);

		/* RR_DONE */
		hs->wait_header = 0;
	}
	
	/* try writing available data in the buffer including that we read */
	if (WriteAvailData(ctx, hs->peer_sock) < 0) {
		TRACE_ERROR("WriteAvailData() error\n");
		/* close both side of HTTP stream */
		CloseHTTPStream(ctx, fd);
		if (hs->peer_sock >= 0) {
			CloseHTTPStream(ctx, hs->peer_sock);
			hs->peer_sock = -1;
		}
	}
}
/*----------------------------------------------------------------------------*/
static void 
HandleWriteEvent(struct thread_context *ctx, int fd)
{
	http_stream *hs = &ctx->stream[fd];
	
	/* unblock it and read what it has */
	hs->write_blocked = 0;
	ModifyEvent(ctx, fd, EPOLLIN);
	
	/* enable reading on peer just in case it was off */
	if (hs->peer_sock >= 0) {
		RegisterEvent(ctx, hs->peer_sock, EPOLLIN);
	}
	
	/* if we have data, write it */
	if (WriteAvailData(ctx, fd) < 0) {
		/* if write fails, close the HTTP stream */
		CloseHTTPStream(ctx, fd);
		if (hs->peer_sock >= 0) {
			CloseHTTPStream(ctx, hs->peer_sock);
			hs->peer_sock = -1;
		}
		return;
	}	

	/* if peer is closed and we're done writing, we should close */
	if (hs->peer_sock < 0 && hs->wbuf->data_len == 0) {
		CloseHTTPStream(ctx, fd);
	}
}
/*----------------------------------------------------------------------------*/
/*
static void
cb_on_timer(mctx_t mctx, int msock, int side, event_t events, struct filter_arg *arg)
{
	TRACE_ERROR("[CPU %d] timer test\n", mctx->cpu);

	// TEST: set the next timer
	struct timeval tv;
	tv.tv_sec = 1;
	tv.tv_usec = 0;
	int res_st;
	res_st = mtcp_settimer(mctx, msock, &tv, cb_on_timer);
	if (res_st < 0) {
		TRACE_ERROR("mtcp_settimer() failed\n");
		exit(-1);
	}
}
*/
/*----------------------------------------------------------------------------*/
/* Main application logic */
void 
RunMainLoop(void *arg_ctx)
{
	struct thread_context *ctx;
	int nevents, i, do_accept, ret;
	int err;
	socklen_t len = sizeof(err);
	struct backend_pool* bpool;
	// int j;
	struct backend_info* binfo;
#if USE_MTCP
	struct mtcp_epoll_event *events;
	ctx = (struct thread_context *) arg_ctx;
	mctx_t mctx = ctx->mctx;
#else
	struct epoll_event *events;
	if (arg_ctx) {
		fprintf(stderr, "should not happen!");
		exit(-1);
	}
#endif


#if USE_MTCP
	TRACE_INFO("Run application on core %d\n", ctx->cpu);
	ctx->mctx = mctx;
#endif

	srand(time(NULL));

#if USE_MTCP
	for (i = 0; i < g_prx_ctx->backend_num; i++) {
		bpool = &(g_prx_ctx->bpool[g_prx_ctx->backend_num]);
		TAILQ_FOREACH(binfo, &bpool->bi_list, link){
			mtcp_init_rss(mctx, g_prx_ctx->listen_addr.sin_addr.s_addr, 1,
					binfo->addr.sin_addr.s_addr, binfo->addr.sin_port);
		}
	}
#endif

	ctx->rr_count = 0;

	/* create epoll descriptor */
#if USE_MTCP
	ctx->ep = mtcp_epoll_create(mctx, MAX_EVENTS);
#else
	ctx->ep = epoll_create(MAX_EVENTS);
#endif
	if (ctx->ep < 0) {
		TRACE_ERROR("Failed to create epoll descriptor!\n");
		exit(-1);
	}

	/* allocate memory for server variables */
	ctx->stream = (struct http_stream*)calloc(max_concurrency,
											  sizeof(struct http_stream));
	if (!ctx->stream) {
		TRACE_ERROR("Failed to create server_vars struct!\n");
		exit(-1);
	}

	/* initialize memory pool for flow buffers */
	ctx->hbmap = (http_buf*) calloc(max_concurrency,
									sizeof(struct http_buf));
	if (!ctx->hbmap) {
		TRACE_ERROR("Failed to allocate memory for flow buffer map.\n");
		exit(-1);
	}
	for (i = 0; i < max_concurrency; i++) {
		ctx->hbmap[i].data = (char*) calloc(1, PB_ALLOCSIZE);
		if (!ctx->hbmap[i].data) {
			TRACE_ERROR("Failed to allocate memory for flow buffer.\n");
			exit(-1);
		}
	}
	TAILQ_INIT(&ctx->free_hbmap);
	for (i = 0; i < max_concurrency; i++)
		TAILQ_INSERT_TAIL(&ctx->free_hbmap, &ctx->hbmap[i], link);
	
	TAILQ_INIT(&ctx->sticky_map);

	ctx->listener = CreateListeningSocket(ctx);
	if (ctx->listener < 0) {
		TRACE_ERROR("Failed to create listening socket.\n");
		exit(-1);
	}

#if USE_MTCP
	events = (struct mtcp_epoll_event *)
		calloc(MAX_EVENTS, sizeof(struct mtcp_epoll_event));
#else
	events = (struct epoll_event *)
		calloc(MAX_EVENTS, sizeof(struct epoll_event));
#endif
	if (!events) {
		TRACE_ERROR("Failed to create event struct!\n");
		exit(-1);
	}

	/* create spare persistent connections to backend servers */
	/*
	int backend_num;
	backend_num = get_backend_poolsize(&g_prx_ctx->bpool[x]);
	fprintf(stderr, "creating %d connections "
			"(%d conns/server * %d servers / %d cores)\n",
			(backend_num * g_prx_ctx->conn_per_backend / num_cores_used),
			g_prx_ctx->conn_per_backend,
			backend_num,
			num_cores_used);
	
	for (i = 0; i < backend_num; i++) {
		binfo = get_server_from_bpool_by_pos(&g_prx_ctx->bpool[x], i);	
		
		TRACE_ERROR("[cpu %d] backend name: %s\n", ctx->cpu, binfo->name);

		// initialize tailq for free backend connections
		TAILQ_INIT(&(binfo->idle_conns[ctx->cpu]));

		struct sockaddr_in* backend_addr;
		struct http_stream* backend_hs;
		backend_addr = &(binfo->addr);

		// create spare persistent connections
		for (j = 0; j < g_prx_ctx->conn_per_backend / num_cores_used; j++) {

			// try connecting here
			int backend_fd;
			if ((backend_fd = ConnectToBackend(ctx, backend_addr)) < 0) {
				TRACE_ERROR("ConnectToBackend() error\n");
				exit(-1);
				
			}		

			// initialize stream parameters
			backend_hs = &ctx->stream[backend_fd];
			memset(backend_hs, 0, sizeof(http_stream));
			backend_hs->sock = backend_fd;
			backend_hs->is_spare = 1;
			backend_hs->is_connecting = 1;
			backend_hs->backend = binfo;
			RegisterEvent(ctx, backend_fd, EPOLLOUT);
		}
	}
    */

	/* create health check connections to backend servers */
	/*
	if (ctx->cpu == 0) {
		for (i = 0; i < backend_num; i++) {
			binfo = get_server_from_bpool_by_pos(&g_prx_ctx->bpool, i);	
		
			struct sockaddr_in* backend_addr;
			struct http_stream* backend_hs;
			backend_addr = &(binfo->addr);

			// create a connection for health check
			int backend_fd;
			if ((backend_fd = ConnectToBackend(ctx, backend_addr)) < 0) {
				TRACE_ERROR("ConnectToBackend() error\n");
				exit(-1);
			}

			// initialize stream parameters
			backend_hs = &ctx->stream[backend_fd];
			memset(backend_hs, 0, sizeof(http_stream));
			backend_hs->sock = backend_fd;
			backend_hs->is_health_check = 1;
			backend_hs->is_connecting = 1;
			backend_hs->backend = binfo;
			RegisterEvent(ctx, backend_fd, EPOLLOUT);
		}	

	}
	*/

	/*
	struct timeval tv;
	tv.tv_sec = 1;
	tv.tv_usec = 0;
	int res_st;

	// timer for health-check the backend connections
	res_st = mtcp_settimer(mctx, ctx->ep, &tv, cb_on_timer);
	if (res_st < 0) {
		TRACE_ERROR("mtcp_settimer() failed\n");
		exit(-1);
	}
	*/

	while (1) {
#if USE_MTCP
		nevents = mtcp_epoll_wait(mctx, ctx->ep, events, MAX_EVENTS, 1000);
#else
		nevents = epoll_wait(ctx->ep, events, MAX_EVENTS, 1000);
#endif
		if (nevents < 0 && errno != EINTR) {
			if (errno == EPERM)
				break;
			TRACE_ERROR("mtcp_epoll_wait() error\n");
			exit(-1);
		}

		do_accept = FALSE;
		for (i = 0; i < nevents; i++) {
#if USE_MTCP
			/* if the event is for the listener, accept connection */
			if (events[i].data.sockid == ctx->listener)
				do_accept = TRUE;
			/* when read becomes available, handle read event */
			else if (events[i].events & MTCP_EPOLLIN)
				HandleReadEvent(ctx, events[i].data.sockid);
			/* when write becomes available handle write event */
			else if (events[i].events & MTCP_EPOLLOUT)
				HandleWriteEvent(ctx, events[i].data.sockid);
            /* Handling an error on the connection */
			else if (events[i].events & MTCP_EPOLLERR) {
				ret = mtcp_getsockopt(mctx, events[i].data.sockid, 
									  SOL_SOCKET, SO_ERROR,
									  (void *)&err, &len);
				if (ret == 0) {
					if (err == ETIMEDOUT)
						continue; /* continue for epoll timeout case */
					else {
						TRACE_ERROR("epoll error: %s\n", strerror(err));
						exit(-1);
					}
				} else {
					TRACE_ERROR("getsockopt error: %s\n", strerror(errno));
					exit(-1);  /* for debugging now */
				}
			}
			else if (events[i].events & MTCP_EPOLLHUP) {
				fprintf(stderr, "MTCP_EPOLLHUP\n");
				exit(-1); /* for debugging now */
			}
			else if (events[i].events & MTCP_EPOLLRDHUP) {
				fprintf(stderr, "MTCP_EPOLLRDHUP\n");
				exit(-1); /* for debugging now */
			}
#else
			if (events[i].data.fd == ctx->listener)
				do_accept = TRUE;
			else if (events[i].events & EPOLLIN)
				HandleReadEvent(ctx, events[i].data.fd);
			else if (events[i].events & EPOLLOUT)
				HandleWriteEvent(ctx, events[i].data.fd);
			else if (events[i].events & EPOLLERR) {
				ret = getsockopt(events[i].data.fd,
								 SOL_SOCKET, SO_ERROR,
								 (void *)&err, &len);
				if (ret == 0) {
					if (err == ETIMEDOUT)
						continue; /* continue for epoll timeout case */
					else {
						TRACE_ERROR("epoll error: %s\n", strerror(err));
						exit(-1);
					}
				} else {
					TRACE_ERROR("getsockopt error: %s\n", strerror(errno));
					exit(-1);  /* for debugging now */
				}
			}
			else if (events[i].events & EPOLLHUP) {
				fprintf(stderr, "EPOLLHUP\n");
				exit(-1); /* for debugging now */
			}
			else if (events[i].events & EPOLLRDHUP) {
				fprintf(stderr, "EPOLLRDHUP\n");
				exit(-1); /* for debugging now */
			}
#endif		
			else {
				/* Unknown epoll flag */
				fprintf(stderr, "unknown epoll flag\n");
				exit(-1);
			}
		}

		/* if do_accept flag is set, accept connections */
		if (do_accept) {
			while (AcceptHTTPSession(ctx, ctx->listener) >= 0);
		}
		
	}
	
	free(ctx->stream);
	free(events);
}
/*----------------------------------------------------------------------------*/
void * 
RunMTCP(void *arg) 
{
#if USE_MTCP
	int core = *(int *)arg;
	mctx_t mctx;
	
	/* affinitize CPU cores to mTCP threads */
	mtcp_core_affinitize(core);
	
	/* initialize mTCP threads */	
	if (!(mctx = mtcp_create_context(core))) {
		TRACE_ERROR("Failed to craete mtcp context.\n");
		pthread_exit(NULL);
		return NULL;
	}

	struct thread_context *ctx = (struct thread_context *) calloc(1, sizeof(struct thread_context));
	if (!ctx) {
		TRACE_ERROR("Failed to create thread context!\n");
		exit(-1);
	}

	ctx->cpu = core;
	ctx->mctx = mctx;
#ifdef ENABLE_UCTX
        mtcp_create_app_context(mctx, (mtcp_app_func_t) RunMainLoop, (void *) ctx);
        mtcp_run_app();
#else
	/* run main application loop */
	RunMainLoop((void *)ctx);
#endif	
	/* destroy mTCP-related contexts after main loop */
	mtcp_destroy_context(ctx->mctx);
	free(ctx);
#else
	RunMainLoop(NULL);
#endif
	
	pthread_exit(NULL);
	return NULL;
}
/*----------------------------------------------------------------------------*/
int 
main(int argc, char **argv)
{
	int i, o, p;
	int cores[MAX_CPUS];
	
#if USE_MTCP	
	/* read mTCP configuration from config/mos.conf */
	if (mtcp_init("config/mtcp.conf")) {
		TRACE_ERROR("Failed to initialize mtcp.\n");
		exit(EXIT_FAILURE);
	}
	if (mtcp_getconf(&g_mcfg) < 0) {
		TRACE_ERROR("mtcp_getconf() error\n");
		exit(-1);
	}
	max_concurrency = g_mcfg.max_concurrency;
	num_cores = g_mcfg.num_cores;

	while (-1 != (o = getopt(argc, argv, "s"))) {
		switch (o) {
		case 's':
			TRACE_INFO("enabled mtcp_splice()\n");
			g_conf_splice = 1;
			break;
		}
	}
#else
	/* soft limit for sockets */
	struct rlimit limit;
	max_concurrency = MAX_CONCURRENCY_LIMIT;
	limit.rlim_cur = max_concurrency;
	limit.rlim_max = max_concurrency;
	if (setrlimit(RLIMIT_NOFILE, &limit) < 0) {
		TRACE_ERROR("failed to increase number of fds\n");
		exit(-1);
	}
	
	num_cores = sysconf(_SC_NPROCESSORS_ONLN);
#endif
	
	/* read epproxy configuration from config/epproxy.yaml */
	g_prx_ctx = LoadConfigData("config/epproxy.yaml");
	if (!g_prx_ctx) {
		TRACE_ERROR("LoadConfigData() error\n");
		exit(-1);
	}		

	for (p = 0; p < g_prx_ctx->backend_num; p++) {
		size_t bpool_size = get_backend_poolsize(&g_prx_ctx->bpool[p]);

		if (!bpool_size){
			TRACE_ERROR("No Available Backend Server.\n");
			exit(-1);
		}
	}

	/* initialize hmap for backend server pool */
	if (g_prx_ctx->balance != BL_ROUNDROBIN &&
		g_prx_ctx->balance != BL_SINGLE) {

		TAILQ_INIT(&g_prx_ctx->bnode_hmap);

		for (p = 0; p < g_prx_ctx->backend_num; p++) {
			size_t bpool_size = get_backend_poolsize(&g_prx_ctx->bpool[p]);
			for (i = 0; i < bpool_size; i++) {
				struct backend_info* binfo = get_server_from_bpool_by_pos(&g_prx_ctx->bpool[p], i);
				if (binfo == NULL) {
					TRACE_ERROR("get_server_from_bpool_by_pos() error\n");
					exit(-1);
				}
				InsertHashNodes(binfo);
			}
		}
		
	}

	/* run load balancer threads */
	for (i = 0; i < num_cores; i++) {
		cores[i] = i;
		num_cores_used++;
		if (pthread_create(&mtcp_thread[i], NULL, RunMTCP, (void *)&cores[i])) {
			TRACE_ERROR("Failed to create msg_test thread.\n");
			exit(-1);
		}
		
	}
	
	for (i = 0; i < num_cores; i++) {
		pthread_join(mtcp_thread[i], NULL);
		TRACE_INFO("Message test thread %d joined.\n", i);
	}
		
#if USE_MTCP
	/* clean up epproxy and mTCP internal variables */	
	mtcp_destroy();
#endif

	return 0;
}
/*----------------------------------------------------------------------------*/
