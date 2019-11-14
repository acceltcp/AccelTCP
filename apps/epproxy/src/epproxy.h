#ifndef __EPPROXY_H_
#define __EPPROXY_H_
#define _LARGEFILE64_SOURCE
#include <stdlib.h>
#include <assert.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
#include <stdio.h>
#include <sys/queue.h>
#include <stdint.h>
#include "http_stream.h"
#include "persist.h"
#include "backend_pool.h"
/*----------------------------------------------------------------------------*/
#define USE_MTCP 1
#if USE_MTCP
#include <mtcp_api.h>
#else
#include <fcntl.h>
#include <unistd.h>
#define MAX_CONCURRENCY_LIMIT 1000000
#endif
/*---------------------------------------------------------------------------*/
/* configurable parameters for epproxy */
#define MAX_PROXY_NUM          1
#define MAX_BACKEND_NUM        1024
#define MAX_BACKEND_POOL_NUM   4
#define MAX_COOKIE_NAME_LEN    20
#define MAX_SERVER_NAME_LEN    10
#define PB_ALLOCSIZE           8192
/*---------------------------------------------------------------------------*/
// #define MAX_IP_LEN 15
#define MAX_IPADDR_STRLEN      15
#define MAX_PERSIST_METHOD_LEN 14
/*----------------------------------------------------------------------------*/
#define COOKIE_HEADER_LEN   13  /* = 12 for "Set-Cookie: " + 1 for "=" */
#define COOKIE_PREFIX_LEN   COOKIE_HEADER_LEN + MAX_COOKIE_NAME_LEN
#define COOKIE_TOTAL_LEN    COOKIE_PREFIX_LEN + MAX_SERVER_NAME_LEN
/*----------------------------------------------------------------------------*/
#define PB_READSIZE  PB_ALLOCSIZE - MAX_IPADDR_STRLEN - COOKIE_TOTAL_LEN
/*----------------------------------------------------------------------------*/
extern const char* const config_opts[];
extern const char* const persist_opts[];
/*---------------------------------------------------------------------------*/
enum {BL_SINGLE, BL_ROUNDROBIN, BL_LEAST, BL_URI};
/*---------------------------------------------------------------------------*/
typedef struct thread_context
{
#if USE_MTCP
	mctx_t mctx;                 /* mtcp context */
	int cpu;                    /* CPU core number */
#endif
	int listener;                /* listener socket */
	int ep;                      /* epoll socket */
	int rr_count;                /* round-robin counter */

	http_stream *stream;         /* per-socket HTTP stream structure */	

	http_buf *hbmap;             /* per-stream HTTP buffer structure */
	TAILQ_HEAD (, http_buf) free_hbmap;  /* list of free HTTP buffers */
	
	struct sticky_table sticky_map;  /* sticky table */

} thread_context;
/*----------------------------------------------------------------------------*/
struct proxy_context {
	/* listening address of the frontend server */
	struct sockaddr_in listen_addr;

	/* load balancing method */
	int balance;

	/* backend server pool information */
	struct backend_pool bpool[MAX_BACKEND_POOL_NUM];
	/* consistent hash node map for backend servers */
	TAILQ_HEAD (, backend_node) bnode_hmap;  

	/* number of persistent backend connections */
	int conn_per_backend;

	/* session persistence method */
	int persist_method;
	/* session persistence cookie name */
	char persist_cookie[MAX_COOKIE_NAME_LEN + 1];

	/* config parameter */
	uint8_t listen_done:1,
		    balance_done:1,
	//	    backend_done:1,
		    conn_pool_done:1,
		    persist_done:1;

	int backend_num;
	
};
/*---------------------------------------------------------------------------*/
struct config {
	int proxy_num;
	struct proxy_context pconf[MAX_PROXY_NUM];
} g_conf;
/*---------------------------------------------------------------------------*/
struct proxy_context *g_prx_ctx;
/*---------------------------------------------------------------------------*/
#endif
