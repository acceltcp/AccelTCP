#include <stdint.h>
#include "config.h"
/*---------------------------------------------------------------------------*/
/* (weight factor) to (# nodes in consistent hash ring) ratio
 * => We use the same value (16) as recommended by HAProxy for now
 * (https://github.com/haproxy/haproxy/blob/master/include/types/backend.h)
 *
 * The scale factor between user weight and effective weight allows smooth
 * weight modulation even with small weights (eg: 1). It should not be too high
 * though because it limits the number of servers in FWRR mode in order to
 * prevent any integer overflow. The max number of servers per backend is
 * limited to about (2^32-1)/256^2/scale ~= 65535.9999/scale. A scale of 16
 * looks like a good value, as it allows 4095 servers per backend while leaving
 * modulation steps of about 6% for servers with the lowest weight (1).
 */
#define CHASH_WFACTOR_SCALE   16
/* max weight factor for backend servers */
#define CHASH_MAX_WFACTOR     256
/* max node = SCALE * MAX_WFACTOR = 4096 -> 4 digits */
#define CHASH_NODE_MAX_DIGIT  4
/*---------------------------------------------------------------------------*/
/* TODO: this should be configurable */
/* default weight factor for backend servers */
#define CHASH_DEFAULT_WFACTOR 1
/*---------------------------------------------------------------------------*/
/* A full avalanche hashing function that fits well with 32-bit space
 * This also guarantees good distribution for small-sized numbers 
 * (by deriving a hash value by multiplication with a large prime number)
 * 
 * Provided by Bob Jonkins
 * (See http://burtleburtle.net/bob/hash/integer.html)
 */
static inline uint32_t
full_aval_hash (uint32_t a)
{
	a = (a+0x7ed55d16) + (a<<12);
	a = (a^0xc761c23c) ^ (a>>19);
	a = (a+0x165667b1) + (a<<5);
	a = (a+0xd3a2646c) ^ (a<<9);
	a = (a+0xfd7046c5) + (a<<3);
	a = (a^0xb55a4f09) ^ (a>>16);

	return a * 3221225473U;
}
/*---------------------------------------------------------------------------*/
/* sdbm (a public-domain reimplementation of ndbm) hash function
 * This is a faster version than the original one used in gawk
 * 
 * (See http://www.cse.yorku.ca/~oz/hash.html) 
 */
static inline uint32_t
sdbm_hash (const char* str, uint32_t len)
{
    uint32_t hash = 0;
	uint32_t i;

	for (i = 0; i < len; i++)
        hash = (str[i]) + (hash << 6) + (hash << 16) - hash;

    return hash;
}
/*---------------------------------------------------------------------------*/
typedef struct backend_node {
	uint32_t hash;
	struct backend_info* binfo;
	
	TAILQ_ENTRY (backend_node) link;
	
} backend_node;
/*---------------------------------------------------------------------------*/
/* select a backend by a given hash value */
struct backend_info* SelectNodeByHash(uint32_t hash);
/* insert nodes by its hash value */
void InsertHashNodes(struct backend_info* binfo);
/* remove nodes in consistent hash id by backend id */
int RemoveNodesByID(struct backend_info* binfo);
/*---------------------------------------------------------------------------*/

