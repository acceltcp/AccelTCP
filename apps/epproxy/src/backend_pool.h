#ifndef _INCLUDE_BACKEND_POOL_H_
#define _INCLUDE_BACKEND_POOL_H_

#include <stdint.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <pthread.h>
#include <sys/queue.h>

/* use pthread_rwlock by default (rte_rwlock should be tested further) */
#define USE_PTHREAD_RWLOCK

#ifdef USE_PTHREAD_RWLOCK
#include <pthread.h>
#else
#include <rte_rwlock.h>
#endif /* USE_PTHREAD_RWLOCK */

//#include "util.h"

/*
enum addr_type {
	LB_BACKEND_IPV4,
	LB_BACKEND_IPV6
};
*/

typedef struct backend_info {
	struct sockaddr_in addr;	/* backend address (IPv4) */
	char* name;                 /* backend name */
	int weight;                 /* backend server load weight (C-HASH) */

	TAILQ_ENTRY (backend_info) link; /* backend info link */

	/* list of free persistent connections to backend servers */
	TAILQ_HEAD (, http_stream) idle_conns[16]; /* FIXME: fixed number */

	/* a connection for health check to backend servers */
	struct http_stream *hc_conn;

	/* those fields can be used in the future */
	//	enum hc_state bhealth;		/* backend health */

	uint8_t addr_done:1,
		    name_done:1,
		    weight_done:1;

} backend_info;

typedef struct backend_pool {
	size_t pool_size;		/* size of backend pool */
	TAILQ_HEAD(, backend_info) bi_list; /* backend info list */
	
#ifdef USE_PTHREAD_RWLOCK
	pthread_rwlock_t pool_lock;
#else
	rte_rwlock_t pool_lock;
#endif

	/* those fields can be used in the future */
	//	enum hc_method hcm;		/* health check method for this pool */
	//	bool dsr;				/* DSR-based pool */
	//	enum addr_type	atype;	/* IP address type (IPv4 or IPv6) */

} backend_pool;

//struct backend_pool active_pool[MAX_CPUS];

/* initialize and destroy pool */
int init_backend_pool(struct backend_pool *
					  /*, enum hc_method, enum addr_type, bool dsr*/);
void destory_backend_pool(struct backend_pool *);

/* add and remove backend */
int add_to_bpool(struct backend_pool *, struct sockaddr_in *, char *, int);
int add_to_bpool_entry(struct backend_pool *pool, struct backend_info* back_ctx);
int remove_from_bpool_by_addr(struct backend_pool *, struct sockaddr_in *);
int remove_from_bpool_by_pos(struct backend_pool *, size_t);

/* get information from pool */
size_t get_backend_poolsize(struct backend_pool *);
struct backend_info *get_server_from_bpool_by_addr(struct backend_pool *, struct sockaddr_in *);
struct backend_info *get_server_from_bpool_by_pos(struct backend_pool *, size_t);

#endif /* _INCLUDE_BACKEND_POOL_H_ */
