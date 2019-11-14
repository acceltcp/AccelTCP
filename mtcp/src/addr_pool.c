#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include "addr_pool.h"
#include "splice_pool.h"

#include "rss.h"
#include "debug.h"
/*----------------------------------------------------------------------------*/
int
GetNumFree(addr_pool_t ap)
{
	return ap->num_free;
}
int
GetNumUsed(addr_pool_t ap)
{
	return ap->num_used;
}

int
GetNumSplice(addr_pool_t ap)
{
	return ap->num_splice;
}
/*----------------------------------------------------------------------------*/

int
MoveAddressToSplice(addr_pool_t ap, const struct sockaddr_in *addr)
{
	struct addr_entry *walk, *next;
	int ret = -1;

	if (!ap || !addr)
		return -1;
	if(pthread_mutex_lock(&ap->lock) < 0) {
		TRACE_DBG("pthread_mutex_lock failed\n");
		exit(-1);
	}
	if (ap->mapper) {
		uint32_t addr_h = ntohl(addr->sin_addr.s_addr);
		uint16_t port_h = ntohs(addr->sin_port);
		int index = addr_h - ap->addr_base;

		if (index >= 0 && index < ap->num_addr) {
			walk = ap->mapper[addr_h - ap->addr_base].addrmap[port_h];
		} else {
			walk = NULL;
		}

	} else {
		walk = TAILQ_FIRST(&ap->used_list);
		while (walk) {
			next = TAILQ_NEXT(walk, addr_link);
			if (addr->sin_port == walk->addr.sin_port && 
					addr->sin_addr.s_addr == walk->addr.sin_addr.s_addr) {
				break;
			}

			walk = next;
		}

	}

	if (walk) {
		TAILQ_REMOVE(&ap->used_list, walk, addr_link);
		TAILQ_INSERT_TAIL(&ap->splice_list, walk, addr_link);
		ap->num_splice++;
		ap->num_used--;

		ret = 0;
	}
	if(pthread_mutex_unlock(&ap->lock) < 0) {
		TRACE_DBG("pthread_mutex_unlock failed\n");
		exit(-1);
	}
	return ret;
}

int 
FreeSpliceAddress(addr_pool_t ap, const struct sockaddr_in *addr)
{
	struct addr_entry *walk, *next;
	int ret = -1;

	if (!ap || !addr)
		return -1;

	if(pthread_mutex_lock(&ap->lock) < 0) {
		TRACE_DBG("pthread_mutex_lock failed\n");
		exit(-1);
	}

	if (ap->mapper) {
		uint32_t addr_h = ntohl(addr->sin_addr.s_addr);
		uint16_t port_h = ntohs(addr->sin_port);
		int index = addr_h - ap->addr_base;

		if (index >= 0 && index < ap->num_addr) {
			walk = ap->mapper[addr_h - ap->addr_base].addrmap[port_h];
		} else {
			walk = NULL;
		}

	} else {
		walk = TAILQ_FIRST(&ap->splice_list);
		while (walk) {
			next = TAILQ_NEXT(walk, addr_link);
			if (addr->sin_port == walk->addr.sin_port && 
					addr->sin_addr.s_addr == walk->addr.sin_addr.s_addr) {
				break;
			}

			walk = next;
		}

	}

	if (walk) {
		TAILQ_REMOVE(&ap->splice_list, walk, addr_link);
		TAILQ_INSERT_TAIL(&ap->free_list, walk, addr_link);
		ap->num_free++;
		ap->num_splice--;
		ret = 0;
	}
	else {
		TRACE_ERROR("Cannot Find Splice Entry\n");
	}
	if(pthread_mutex_unlock(&ap->lock) < 0) {
		TRACE_DBG("pthread_mutex_unlock failed\n");
		exit(-1);
	}


	return ret;
}

int 
SearchSpliceAddress(addr_pool_t ap, const struct sockaddr_in *addr)
{
	struct addr_entry *walk, *next;
	int ret = -1;

	if (!ap || !addr)
		return -1;

	if(pthread_mutex_lock(&ap->lock) < 0) {
		TRACE_DBG("pthread_mutex_lock failed\n");
		exit(-1);
	}

	if (ap->mapper) {
		uint32_t addr_h = ntohl(addr->sin_addr.s_addr);
		uint16_t port_h = ntohs(addr->sin_port);
		int index = addr_h - ap->addr_base;

		if (index >= 0 && index < ap->num_addr) {
			walk = ap->mapper[addr_h - ap->addr_base].addrmap[port_h];
		} else {
			walk = NULL;
		}

	} else {
		walk = TAILQ_FIRST(&ap->splice_list);
		while (walk) {
			next = TAILQ_NEXT(walk, addr_link);
			if (addr->sin_port == walk->addr.sin_port && 
					addr->sin_addr.s_addr == walk->addr.sin_addr.s_addr) {
				break;
			}

			walk = next;
		}

	}

	if (walk)
		ret = 0;
	
	if(pthread_mutex_unlock(&ap->lock) < 0) {
		TRACE_DBG("pthread_mutex_unlock failed\n");
		exit(-1);
	}


	return ret;
}
/*----------------------------------------------------------------------------*/

addr_pool_t 
CreateAddressPool(in_addr_t addr_base, int num_addr)
{
	struct addr_pool *ap;
	int num_entry;
	int i, j, cnt;
	in_addr_t addr;
	uint32_t addr_h;

	ap = (addr_pool_t)calloc(1, sizeof(struct addr_pool));
	if (!ap)
		return NULL;

	/* initialize address pool */
	num_entry = num_addr * (MAX_PORT - MIN_PORT);
	ap->pool = (struct addr_entry *)calloc(num_entry, sizeof(struct addr_entry));
	if (!ap->pool) {
		free(ap);
		return NULL;
	}

	/* initialize address map */
	ap->mapper = (struct addr_map *)calloc(num_addr, sizeof(struct addr_map));
	if (!ap->mapper) {
		free(ap->pool);
		free(ap);
		return NULL;
	}

	TAILQ_INIT(&ap->free_list);
	TAILQ_INIT(&ap->used_list);
	TAILQ_INIT(&ap->splice_list);

	if (pthread_mutex_init(&ap->lock, NULL)) {
		free(ap->pool);
		free(ap);
		return NULL;
	}
#ifdef ENABLE_UCTX
#else
	if(pthread_mutex_lock(&ap->lock) < 0) {
		TRACE_DBG("pthread_mutex_lock failed\n");
		exit(-1);
	}
#endif
	ap->addr_base = ntohl(addr_base);
	ap->num_addr = num_addr;

	cnt = 0;
	for (i = 0; i < num_addr; i++) {
		addr_h = ap->addr_base + i;
		addr = htonl(addr_h);
		for (j = MIN_PORT; j < MAX_PORT; j++) {
			ap->pool[cnt].addr.sin_addr.s_addr = addr;
			ap->pool[cnt].addr.sin_port = htons(j);
			ap->mapper[i].addrmap[j] = &ap->pool[cnt];
			
			TAILQ_INSERT_TAIL(&ap->free_list, &ap->pool[cnt], addr_link);

			if ((++cnt) >= num_entry)
				break;
		}
	}
	ap->num_entry = cnt;
	ap->num_free = cnt;
	ap->num_used = 0;
	ap->num_splice = 0;

#ifdef ENABLE_UCTX
#else
	if(pthread_mutex_unlock(&ap->lock) < 0) {
		TRACE_DBG("pthread_mutex_unlock failed\n");
		exit(-1);
	}

#endif
	return ap;
}
/*----------------------------------------------------------------------------*/
addr_pool_t 
CreateAddressPoolPerCore(int core, int num_queues, 
		in_addr_t saddr_base, int num_addr, in_addr_t daddr, in_port_t dport)
{
	struct addr_pool *ap;
	int num_entry;
	int i, j, cnt;
	in_addr_t saddr;
	uint32_t saddr_h;
	uint16_t sport_h;
	uint32_t daddr_h;
	uint16_t dport_h;
	int rss_core;
#if 0
	uint8_t endian_check = (current_iomodule_func == &dpdk_module_func) ?
		0 : 1;
#else
	uint8_t endian_check = FetchEndianType();	
#endif

	ap = (addr_pool_t)calloc(1, sizeof(struct addr_pool));
	if (!ap)
		return NULL;

	/* initialize address pool */
	num_entry = (num_addr * (MAX_PORT - MIN_PORT)) / num_queues;

	ap->pool = (struct addr_entry *)calloc(num_entry, sizeof(struct addr_entry));
	if (!ap->pool) {
		free(ap);
		return NULL;
	}
	
	/* initialize address map */
	ap->mapper = (struct addr_map *)calloc(num_addr, sizeof(struct addr_map));
	if (!ap->mapper) {
		free(ap->pool);
		free(ap);
		return NULL;
	}

	TAILQ_INIT(&ap->free_list);
	TAILQ_INIT(&ap->used_list);
	TAILQ_INIT(&ap->splice_list);

	if (pthread_mutex_init(&ap->lock, NULL)) {
		free(ap->pool);
		free(ap);
		return NULL;
	}
#ifdef ENABLE_UCTX
#else
	if(pthread_mutex_lock(&ap->lock) < 0) {
		TRACE_DBG("pthread_mutex_lock failed\n");
		exit(-1);
	}
#endif

	ap->addr_base = ntohl(saddr_base);
	ap->num_addr = num_addr;
	daddr_h = ntohl(daddr);
	dport_h = ntohs(dport);
	ap->daddr = daddr;
	ap->dport = dport;

	/* search address space to get RSS-friendly addresses */
	cnt = 0;
	for (i = 0; i < num_addr; i++) {
		saddr_h = ap->addr_base + i;
		saddr = htonl(saddr_h);
		for (j = MIN_PORT; j < MAX_PORT; j++) {
			if (cnt >= num_entry)
				break;

			sport_h = j;
			rss_core = GetRSSCPUCore(daddr_h, saddr_h, dport_h, sport_h, num_queues, endian_check);
			if (rss_core != core)
				continue;

			ap->pool[cnt].addr.sin_addr.s_addr = saddr;
			ap->pool[cnt].addr.sin_port = htons(sport_h);
			ap->mapper[i].addrmap[j] = &ap->pool[cnt];
			TAILQ_INSERT_TAIL(&ap->free_list, &ap->pool[cnt], addr_link);
			cnt++;
		}
	}

	ap->num_entry = cnt;
	ap->num_free = cnt;
	ap->num_used = 0;
	ap->num_splice = 0;

	if (ap->num_entry < CONFIG.max_concurrency) {
		fprintf(stderr, "[WARINING] Available # addresses (%d) is smaller than"
				" the max concurrency (%d).\n", 
				ap->num_entry, CONFIG.max_concurrency);
	}
#ifdef ENABLE_UCTX
#else
	if(pthread_mutex_unlock(&ap->lock) < 0) {
		TRACE_DBG("pthread_mutex_unlock failed\n");
		exit(-1);
	}

#endif

	return ap;
}
/*----------------------------------------------------------------------------*/
void
DestroyAddressPool(addr_pool_t ap)
{
	if (!ap)
		return;

	if (ap->pool) {
		free(ap->pool);
		ap->pool = NULL;
	}

	if (ap->mapper) {
		free(ap->mapper);
		ap->mapper = NULL;
	}

	pthread_mutex_destroy(&ap->lock);

	free(ap);
}
/*----------------------------------------------------------------------------*/
int 
FetchAddress(addr_pool_t ap, int core, int num_queues, 
		const struct sockaddr_in *daddr, struct sockaddr_in *saddr)
{
	struct addr_entry *walk, *next;
	int rss_core;
	int ret = -1;
#if 0
	uint8_t endian_check = (current_iomodule_func == &dpdk_module_func) ?
		0 : 1;
#else
	uint8_t endian_check = FetchEndianType();	
#endif

	if (!ap || !daddr || !saddr)
		return -1;

	if(pthread_mutex_lock(&ap->lock) < 0) {
		TRACE_DBG("pthread_mutex_lock failed\n");
		exit(-1);
	}


	walk = TAILQ_FIRST(&ap->free_list);
	while (walk) {
		next = TAILQ_NEXT(walk, addr_link);

		if (saddr->sin_addr.s_addr != INADDR_ANY &&
		    walk->addr.sin_addr.s_addr != saddr->sin_addr.s_addr) {
			walk = next;
			continue;
		}

		if (saddr->sin_port != INPORT_ANY &&
		    walk->addr.sin_port != saddr->sin_port) {
			walk = next;
			continue;
		}

		rss_core = GetRSSCPUCore(ntohl(walk->addr.sin_addr.s_addr), 
					 ntohl(daddr->sin_addr.s_addr), ntohs(walk->addr.sin_port), 
					 ntohs(daddr->sin_port), num_queues, endian_check);

		if (core == rss_core)
			break;

		walk = next;
	}

	if (walk) {
		*saddr = walk->addr;
		TAILQ_REMOVE(&ap->free_list, walk, addr_link);
		TAILQ_INSERT_TAIL(&ap->used_list, walk, addr_link);
		ap->num_free--;
		ap->num_used++;
		ret = 0;
	}
	
	if(pthread_mutex_unlock(&ap->lock) < 0) {
		TRACE_DBG("pthread_mutex_unlock failed\n");
		exit(-1);
	}


	return ret;
}
/*----------------------------------------------------------------------------*/
int 
FetchAddressPerCore(addr_pool_t ap, int core, int num_queues,
		    const struct sockaddr_in *daddr, struct sockaddr_in *saddr)
{
	struct addr_entry *walk;
	int ret = -1;

	if (!ap || !daddr || !saddr)
		return -1;
#ifdef ENABLE_UCTX
#else
	if(pthread_mutex_lock(&ap->lock) < 0) {
		TRACE_DBG("pthread_mutex_lock failed\n");
		exit(-1);
	}

#endif	
	/* we don't need to calculate RSSCPUCore if mtcp_init_rss is called */
	walk = TAILQ_FIRST(&ap->free_list);
	if (walk) {
		*saddr = walk->addr;
		TAILQ_REMOVE(&ap->free_list, walk, addr_link);
		TAILQ_INSERT_TAIL(&ap->used_list, walk, addr_link);
		ap->num_free--;
		ap->num_used++;
		ret = 0;
	}
#ifdef ENABLE_UCTX
#else
	if(pthread_mutex_unlock(&ap->lock) < 0) {
		TRACE_DBG("pthread_mutex_unlock failed\n");
		exit(-1);
	}

#endif
	
	return ret;
}
/*----------------------------------------------------------------------------*/
int 
FreeAddress(addr_pool_t ap, const struct sockaddr_in *addr)
{
	struct addr_entry *walk, *next;
	int ret = -1;

	if (!ap || !addr)
		return -1;

	if (pthread_mutex_lock(&ap->lock) < 0) {
		TRACE_DBG("pthread_mutex_lock failed\n");
		exit(-1);
	}

	if (ap->mapper) {
		uint32_t addr_h = ntohl(addr->sin_addr.s_addr);
		uint16_t port_h = ntohs(addr->sin_port);
		int index = addr_h - ap->addr_base;

		if (index >= 0 && index < ap->num_addr) {
			walk = ap->mapper[addr_h - ap->addr_base].addrmap[port_h];
		} else {
			walk = NULL;
		}

	} else {
		walk = TAILQ_FIRST(&ap->used_list);
		while (walk) {
			next = TAILQ_NEXT(walk, addr_link);
			if (addr->sin_port == walk->addr.sin_port && 
					addr->sin_addr.s_addr == walk->addr.sin_addr.s_addr) {
				break;
			}

			walk = next;
		}

	}

	if (walk) {
		TAILQ_REMOVE(&ap->used_list, walk, addr_link);
		TAILQ_INSERT_TAIL(&ap->free_list, walk, addr_link);
		ap->num_free++;
		ap->num_used--;
		ret = 0;
	}

	if (pthread_mutex_unlock(&ap->lock) < 0) {
		TRACE_DBG("pthread_mutex_unlock failed\n");
		exit(-1);
	}

	return ret;
}
/*----------------------------------------------------------------------------*/
