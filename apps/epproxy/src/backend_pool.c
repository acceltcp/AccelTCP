#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdbool.h>
#include <netinet/in.h>

#include "backend_pool.h"
#include "util.h"

/*****************************************************************************/
int
init_backend_pool(struct backend_pool *pool
				  /*, enum hc_method hcm, enum addr_type type, bool dsr*/) {
	int ret = 0;
	
	if (!pool) {
		TRACE_ERROR("invalid parameter! (NULL)\n");
		exit(-1);
	}

#ifdef USE_PTHREAD_RWLOCK
	pthread_rwlockattr_t attr;

	if (pthread_rwlockattr_init(&attr)) {
		TRACE_ERROR("pthread_rwlockattr_init() error\n");
		return -1;
	}
	if (pthread_rwlockattr_setkind_np(&attr,
			  PTHREAD_RWLOCK_PREFER_WRITER_NONRECURSIVE_NP)) {
		TRACE_ERROR("pthread_rwlockattr_setkind_np() error\n");
		return -1;
	}

	/* initialize rwlock with write favored setup */
	if (pthread_rwlock_init(&pool->pool_lock, &attr)) {
		TRACE_ERROR("pthread_rwlock_init() error\n");
		return -1;
	}

	/* destroy rwlock attribute since it's no longer be used */
	if (pthread_rwlockattr_destroy(&attr)) {
		TRACE_ERROR("pthread_rwlockattr_destroy() error\n");
		return -1;
	}

#else
	/* DPDK rwlock implementation is write favored */
	rte_rwlock_init(&pool->pool_lock);
#endif

	/* the following values are not used for now */
	//	pool->atype = type;
	//	pool->hcm = hcm;
	//	pool->dsr = dsr;

	/* setup empty list condition */
	pool->pool_size = 0;

	TAILQ_INIT(&pool->bi_list);

	return ret;
}

/*****************************************************************************/

void
destroy_backend_pool(struct backend_pool *pool) {

	struct backend_info *walk;

	if (!pool) {
		TRACE_ERROR("invalid parameter! (NULL)\n");
		exit(-1);		
	}

	/* wait for all pending request first */
#ifdef USE_PTHREAD_RWLOCK
	pthread_rwlock_wrlock(&pool->pool_lock);
#else
	rte_rwlock_write_lock(&pool->pool_lock);
#endif

	while (!TAILQ_EMPTY(&pool->bi_list)) {
		walk = TAILQ_FIRST(&pool->bi_list);
		TAILQ_REMOVE(&pool->bi_list, walk, link);
		free(walk);
	}
	pool->pool_size = 0;

#ifdef USE_PTHREAD_RWLOCK
	pthread_rwlock_unlock(&pool->pool_lock);

	/* destroy lock here (what if two writers exist?) */
	if (pthread_rwlock_destroy(&pool->pool_lock)) {
		TRACE_ERROR("pthread_rwlock_destroy() failed\n");
		exit(-1);
	}
#else
	rte_rwlock_write_unlock(&pool->pool_lock);
#endif
}

/*****************************************************************************/

size_t
get_backend_poolsize(struct backend_pool *pool) {

	size_t ret = 0;

	if (!pool) {
		TRACE_ERROR("invalid parameter! (NULL)\n");
		return -1;
	}

#ifdef USE_PTHREAD_RWLOCK
	pthread_rwlock_rdlock(&pool->pool_lock);
#else
	rte_rwlock_read_lock(&pool->pool_lock);
#endif

	ret = pool->pool_size;

#ifdef USE_PTHREAD_RWLOCK
	pthread_rwlock_unlock(&pool->pool_lock);
#else
	rte_rwlock_read_unlock(&pool->pool_lock);
#endif

	return ret;
}


/*****************************************************************************/

static inline struct backend_info *
create_new_backend_info (struct sockaddr_in *server,
						 char* server_name,
						 int server_weight) {

	struct backend_info *ret = NULL;

	if (!server) {
		TRACE_ERROR("invalid parameter! (NULL)\n");
		exit(-1);
	}

	/* allocate memory for new backend */
	ret = calloc(1, sizeof(struct backend_info));
	if (ret == 0) {
		fprintf(stderr, "Failed to allocate memory for new server\n");

		return ret;
	}

	/* initialize entries */
	memcpy(&ret->addr, server, sizeof(struct sockaddr_in));
	//ret->bhealth = HC_STATE_UNKNOWN;
	ret->name = server_name;
	ret->weight = server_weight;

	return ret;
}

/*****************************************************************************/

int
add_to_bpool(struct backend_pool *pool, struct sockaddr_in *server,
			 char* server_name, int server_weight) {

	struct backend_info *new_entry = NULL;

	/* NOTE: we don't allow the weight = 0 case for now */
	if (!pool || !server || !server_name || server_weight <= 0) {
		TRACE_ERROR("invalid parameter! (NULL)\n");
		exit(-1);
	}

	/* create new server entry */
	new_entry = create_new_backend_info(server, server_name, server_weight);
	if (new_entry == NULL) {
		return -1;
	}

#ifdef USE_PTHREAD_RWLOCK
	pthread_rwlock_wrlock(&pool->pool_lock);
#else
	rte_rwlock_write_lock(&pool->pool_lock);
#endif

	TAILQ_INSERT_TAIL(&pool->bi_list, new_entry, link);
	pool->pool_size++;

#ifdef USE_PTHREAD_RWLOCK
	pthread_rwlock_unlock(&pool->pool_lock);
#else
	rte_rwlock_write_unlock(&pool->pool_lock);
#endif
	return 0;
}
/*****************************************************************************/
int
add_to_bpool_entry(struct backend_pool *pool, struct backend_info* new_entry) {

	if (!new_entry)
		return -1;

#ifdef USE_PTHREAD_RWLOCK
	pthread_rwlock_wrlock(&pool->pool_lock);
#else
	rte_rwlock_write_lock(&pool->pool_lock);
#endif

	TAILQ_INSERT_TAIL(&pool->bi_list, new_entry, link);
	pool->pool_size++;

#ifdef USE_PTHREAD_RWLOCK
	pthread_rwlock_unlock(&pool->pool_lock);
#else
	rte_rwlock_write_unlock(&pool->pool_lock);
#endif

	return 0;
}
/*****************************************************************************/

int
remove_from_bpool(struct backend_pool *p, struct backend_info *bs) {

	int ret = 0;

	if (!p || !bs) {
		TRACE_ERROR("invalid parameter! (NULL)\n");
		exit(-1);
	}

	if (!bs->name) {
		TRACE_ERROR("should not happen!\n");
		exit(-1);
	}
	
#ifdef USE_PTHREAD_RWLOCK
	pthread_rwlock_wrlock(&p->pool_lock);
#else
	rte_rwlock_write_lock(&p->pool_lock);
#endif

	p->pool_size--;
	TAILQ_REMOVE(&p->bi_list, bs, link);
	free(bs->name);
	free(bs);

#ifdef USE_PTHREAD_RWLOCK
	pthread_rwlock_unlock(&p->pool_lock);
#else
	rte_rwlock_write_unlock(&p->pool_lock);
#endif

	return ret;
}

/*****************************************************************************/
int
remove_from_bpool_by_addr(struct backend_pool *p, struct sockaddr_in *a) {

	struct backend_info *tmp;
	int ret = -1;

	if (!p || !a) {
		TRACE_ERROR("invalid parameter! (NULL)\n");
		exit(-1);
	}

#ifdef USE_PTHREAD_RWLOCK
	pthread_rwlock_wrlock(&p->pool_lock);
#else
	rte_rwlock_write_lock(&p->pool_lock);
#endif

	TAILQ_FOREACH(tmp, &p->bi_list, link) {
		if (memcmp(&tmp->addr, a, sizeof(struct sockaddr_in)) == 0) {
			p->pool_size--;
			TAILQ_REMOVE(&p->bi_list, tmp, link);
			free(tmp);
			ret = 0; /* return 0 if we found a matching one */
			break;
		}
	}

#ifdef USE_PTHREAD_RWLOCK
	pthread_rwlock_unlock(&p->pool_lock);
#else
	rte_rwlock_write_unlock(&p->pool_lock);
#endif

	return ret;
}

/*****************************************************************************/

int
remove_from_bpool_by_pos(struct backend_pool *pool, size_t pos) {

	struct backend_info *tmp;
	size_t i = 0;
	int ret = -1;

	if (!pool) {
		TRACE_ERROR("invalid parameter! (NULL)\n");
		exit(-1);
	}

#ifdef USE_PTHREAD_RWLOCK
	pthread_rwlock_wrlock(&pool->pool_lock);
#else
	rte_rwlock_write_lock(&pool->pool_lock);
#endif
	pool->pool_size--;	
	TAILQ_FOREACH(tmp, &pool->bi_list, link) {
		if (i == pos) {
			TAILQ_REMOVE(&pool->bi_list, tmp, link);
			free(tmp);
			ret = 0;
			break;
		}
		i++;
	}
	
#ifdef USE_PTHREAD_RWLOCK
	pthread_rwlock_unlock(&pool->pool_lock);
#else
	rte_rwlock_write_unlock(&pool->pool_lock);
#endif

	return ret;
}

/*****************************************************************************/

struct backend_info *
get_server_from_bpool_by_addr(struct backend_pool *p, struct sockaddr_in *a) {

	struct backend_info *ret = NULL, *tmp;

	if (!p || !a) {
		TRACE_ERROR("invalid parameter! (NULL)\n");
		exit(-1);
	}

#ifdef USE_PTHREAD_RWLOCK
	pthread_rwlock_rdlock(&p->pool_lock);
#else
	rte_rwlock_read_lock(&p->pool_lock);
#endif

	/* locate backend entry */
	TAILQ_FOREACH(tmp, &p->bi_list, link) {
		if (memcmp(&tmp->addr, a, sizeof(struct sockaddr_in)) == 0) {
			ret = tmp;
			break;
		}
	}

#ifdef USE_PTHREAD_RWLOCK
	pthread_rwlock_unlock(&p->pool_lock);
#else
	rte_rwlock_read_unlock(&p->pool_lock);
#endif

	return ret;
}

/*****************************************************************************/

struct backend_info *
get_server_from_bpool_by_pos(struct backend_pool *pool, size_t pos) {

	struct backend_info *ret = NULL, *walk;
	size_t i = 0;

	if (!pool) {
		TRACE_ERROR("invalid parameter! (NULL)\n");
		exit(-1);
	}
	
#ifdef USE_PTHREAD_RWLOCK
	pthread_rwlock_rdlock(&pool->pool_lock);
#else
	rte_rwlock_read_lock(&pool->pool_lock);
#endif

	TAILQ_FOREACH(walk, &pool->bi_list, link) {
		if (i == pos) {
			ret = walk;
			break;
		}
		i++;
	}

#ifdef USE_PTHREAD_RWLOCK
	pthread_rwlock_unlock(&pool->pool_lock);
#else
	rte_rwlock_read_unlock(&pool->pool_lock);
#endif

	return ret;
}
