#include <stdint.h>
#include <sys/types.h>

#include "mtcp.h"
#include "nic_control.h"
#include "eth_out.h"
#include "debug.h"

#include "splice_pool.h"
#include "ip_out.h"

struct control_splice_finish_hdr
{
	uint16_t close_reason;		/* the reason of spliced connection close */
	uint32_t ip_addr;		/* the ip address of client-side spliced connection */
	uint16_t port;			/* the port of client-side spliced connection */
	uint32_t unused;		/* unused field */
	uint16_t eth_type;		/* the ethernet type to distinguish the type of the packet */
	uint32_t dst_addr;
	uint16_t dst_port;
} __attribute__ ((packed));

void
DumpSpliceFinishPacket(struct control_splice_finish_hdr *ctrlh);

int 
ProcessSpliceFinishPacket(mtcp_manager_t mtcp, uint32_t cur_ts,
		                  const int ifidx, unsigned char *pkt_data, int len)
{
	struct control_splice_finish_hdr* ctrlh = 
			(struct control_splice_finish_hdr* )pkt_data;
	struct sockaddr_in splice_addr;
	int ret;

	struct addr_pool *ap_walk = NULL;
	struct addr_pool *splice_ap = NULL;

#ifdef VERBOSE
	DumpSpliceFinishPacket(ctrlh);
#endif
	splice_addr.sin_addr.s_addr = ctrlh->ip_addr;
	splice_addr.sin_port = ctrlh->port;

	TAILQ_FOREACH(ap_walk, &mtcp->ap_list, ap_link) {
		if (ap_walk->daddr == ctrlh->dst_addr && ap_walk->dport == ctrlh->dst_port) {
			splice_ap = ap_walk;
			break;
		}
	}
	if (splice_ap) {
		ret = FreeSpliceAddress(splice_ap, &splice_addr);
	} else {
		uint8_t is_external;
		int nif = GetOutputInterface(splice_addr.sin_addr.s_addr, &is_external);
		if (nif < 0) {
			TRACE_ERROR("nif is negative!\n");
			ret = -1;
		} else {
			int eidx = CONFIG.nif_to_eidx[nif];
			ret = FreeSpliceAddress(ap[eidx], &splice_addr);
		}
		UNUSED(is_external);
	}
	if (ret < 0) {
		TRACE_ERROR("(NEVER HAPPEN) Failed to free address.\n");
	}
	else {
		if (mtcp->cb) {
			nsplice_meta_t meta;
			meta.ip_addr = ctrlh->ip_addr;
			meta.port = ctrlh->port;
			meta.dst_addr = ctrlh->dst_addr;
			meta.dst_port = ctrlh->dst_port;
			meta.close_reason = ctrlh->close_reason;
			mtcp->cb(&meta);
		}
	}


	return ret;
}

void 
DumpSpliceFinishPacket(struct control_splice_finish_hdr *ctrlh)
{
	TRACE_INFO("--------------------------------\n"
			"Splice Finished Packet\n"
			"close_reason:	%X\n"
			"ip_addr:	%x\n"
			"port:		%u\n"
			"control_type:	%X\n"
			"dst_addr:	%x\n"
			"dst_port:	%u\n"
			"\n",
			ntohs(ctrlh->close_reason),
			ntohl(ctrlh->ip_addr),
			ntohs(ctrlh->port),
			ntohs(ctrlh->eth_type),
			ntohl(ctrlh->dst_addr),
			ntohs(ctrlh->dst_port));
}
/*----------------------------------------------------------------------------*/
