#ifndef __ADDR_POOL_H_
#define __ADDR_POOL_H_

#include <netinet/in.h>
#include <sys/queue.h>

#define MIN_PORT (1025)
#define MAX_PORT (65535 + 1)
/*----------------------------------------------------------------------------*/
struct addr_entry
{
	struct sockaddr_in addr;
	TAILQ_ENTRY(addr_entry) addr_link;
};
/*----------------------------------------------------------------------------*/
struct addr_map
{
	struct addr_entry *addrmap[MAX_PORT];
};
/*----------------------------------------------------------------------------*/
struct addr_pool
{
	struct addr_entry *pool;		/* address pool */
	struct addr_map *mapper;		/* address map  */

	uint32_t addr_base;				/* in host order */
	int num_addr;					/* number of addresses in use */

	int num_entry;
	int num_free;
	int num_used;

	in_addr_t daddr;
	in_port_t dport;

	pthread_mutex_t lock;
	TAILQ_HEAD(, addr_entry) free_list;
	TAILQ_HEAD(, addr_entry) used_list;

	int num_splice;
	TAILQ_HEAD(, addr_entry) splice_list;

	TAILQ_ENTRY(addr_pool) ap_link;
};
typedef struct addr_pool *addr_pool_t;	
/*----------------------------------------------------------------------------*/
int GetNumFree(addr_pool_t ap);
int GetNumUsed(addr_pool_t ap);
/*----------------------------------------------------------------------------*/
/* CreateAddressPool()                                                        */
/* Create address pool for given address range.                               */
/* addr_base: the base address in network order.                              */
/* num_addr: number of addresses to use as source IP                          */
/*----------------------------------------------------------------------------*/
addr_pool_t 
CreateAddressPool(in_addr_t addr_base, int num_addr);
/*----------------------------------------------------------------------------*/
/* CreateAddressPoolPerCore()                                                 */
/* Create address pool only for the given core number.                        */
/* All addresses and port numbers should be in network order.                 */
/*----------------------------------------------------------------------------*/
addr_pool_t 
CreateAddressPoolPerCore(int core, int num_queues, 
		in_addr_t saddr_base, int num_addr, in_addr_t daddr, in_port_t dport);
/*----------------------------------------------------------------------------*/
void
DestroyAddressPool(addr_pool_t ap);
/*----------------------------------------------------------------------------*/
int 
FetchAddress(addr_pool_t ap, int core, int num_queues, 
		const struct sockaddr_in *daddr, struct sockaddr_in *saddr);
/*----------------------------------------------------------------------------*/
int 
FetchAddressPerCore(addr_pool_t ap, int core, int num_queues, 
		    const struct sockaddr_in *daddr, struct sockaddr_in *saddr);
/*----------------------------------------------------------------------------*/
int 
FreeAddress(addr_pool_t ap, const struct sockaddr_in *addr);
/*----------------------------------------------------------------------------*/

#endif /* __ADDR_POOL_H_ */
