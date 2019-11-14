#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>
#include "balance.h"
#include "http_stream.h"
#include "http_parser.h"
#include "util.h"
#include "hash.h"
#include "persist.h"
#include "epproxy.h"
/*----------------------------------------------------------------------------*/
inline backend_info*
FindBackendByURI(const char* uri, uint32_t uri_len)
{
	uint32_t hash;

	/* calculate two-step hash functions */
	hash = sdbm_hash(uri, uri_len);	
	hash = full_aval_hash(hash);

	/* find for a corresponding server node */
	return SelectNodeByHash(hash);
}
/*----------------------------------------------------------------------------*/
void
DecideBackendServer(struct sticky_table *sticky_map,
					int* rr_count, struct http_stream *hs)
{
	struct backend_pool* bpool = &g_prx_ctx->bpool[hs->nif_out];
	size_t bpool_num = get_backend_poolsize(bpool);

	/* load balancing algorithm */
	if (hs->backend == NULL) {
		if (g_prx_ctx->balance == BL_ROUNDROBIN) {
			hs->backend = get_server_from_bpool_by_pos(bpool,
													   (*rr_count) % bpool_num);
			(*rr_count)++;
		}
		else if (g_prx_ctx->balance == BL_SINGLE) {
			hs->backend = get_server_from_bpool_by_pos(bpool, 0);
		}
		else if (g_prx_ctx->balance == BL_URI) {
			if (!hs->uri) {
				/* For now, we exit on this case for debugging.. */
				exit(-1);
			}
			
			/* find for a backend server by URI */
			hs->backend = FindBackendByURI(hs->uri, strlen(hs->uri));			
		}
		else {
			TRACE_ERROR("we don't support others for a while\n");
			exit(-1);
		}
	}
}
/*----------------------------------------------------------------------------*/
