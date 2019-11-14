#ifndef __SPLICE_POOL_H_
#define __SPLICE_POOL_H_

#include <netinet/in.h>
#include <sys/queue.h>

int GetNumSplice(addr_pool_t ap);
/*----------------------------------------------------------------------------*/
int
MoveAddressToSplice(addr_pool_t ap, const struct sockaddr_in *addr);
/*----------------------------------------------------------------------------*/
int
FreeSpliceAddress(addr_pool_t ap, const struct sockaddr_in *addr);
/*----------------------------------------------------------------------------*/
int
SearchSpliceAddress(addr_pool_t ap, const struct sockaddr_in *addr);

#endif /* __SPLICE_POOL_H_ */
