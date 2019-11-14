#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>
#include "hash.h"
#include "epproxy.h"
#include "util.h"
/*----------------------------------------------------------------------------*/
struct backend_info*
SelectNodeByHash(uint32_t hash)
{
	struct backend_node* walk;
	int count = 0;

	if (TAILQ_EMPTY(&g_prx_ctx->bnode_hmap)) {
		TRACE_ERROR("should not happen!\n");
		exit(-1);
	}

	TAILQ_FOREACH(walk, &g_prx_ctx->bnode_hmap, link) {
		count++;
		if (walk->hash > hash)
			return walk->binfo;
	}

	walk = TAILQ_FIRST(&g_prx_ctx->bnode_hmap);

	return walk->binfo;
}
/*----------------------------------------------------------------------------*/
void
InsertHashNodes(struct backend_info* binfo)
{
	struct backend_node* walk = NULL, *bnode;
	int j = 0;

	/* insert nodes in consistent hash ring */
	for (j = 0; j < CHASH_WFACTOR_SCALE * binfo->weight; j++) {
		bnode = calloc(1, sizeof(struct backend_node));
		bnode->binfo = binfo;

		bnode->hash = sdbm_hash(binfo->name, strlen(binfo->name));
		bnode->hash += full_aval_hash(j);
		bnode->hash = full_aval_hash(bnode->hash);
		
		/* bnode_hmap is aligned by increasing order of hash values */
		TAILQ_FOREACH(walk, &g_prx_ctx->bnode_hmap, link) {
			/* insert before the larger hash */
			if (walk->hash > bnode->hash) {
				TAILQ_INSERT_BEFORE(walk, bnode, link);
				break;
			}
		}

		/* reached the end of the hash map
		   (either it's empty or the given one has the largest value) */
		if (!walk)
			TAILQ_INSERT_TAIL(&g_prx_ctx->bnode_hmap, bnode, link);	
	}
}
/*----------------------------------------------------------------------------*/
int
RemoveNodesByID(struct backend_info* binfo)
{
	struct backend_node* walk;
	int res = -1;

	TAILQ_FOREACH(walk, &g_prx_ctx->bnode_hmap, link) {
		if (walk->binfo == binfo) {
			TAILQ_REMOVE(&g_prx_ctx->bnode_hmap, walk, link);
			res = 0;
		}
	}
	
	return res;
}
/*----------------------------------------------------------------------------*/
