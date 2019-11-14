#include <stdio.h>

#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>

#include <linux/if_ether.h>
#include <linux/tcp.h>
#include <netinet/ip.h>

#include "mtcp.h"
#include "arp.h"
#include "eth_out.h"
#include "debug.h"

#ifndef TRUE
#define TRUE (1)
#endif

#ifndef FALSE
#define FALSE (0)
#endif

#ifndef ERROR
#define ERROR (-1)
#endif

#define MAX(a, b) ((a)>(b)?(a):(b))
#define MIN(a, b) ((a)<(b)?(a):(b))

#define MAX_WINDOW_SIZE 65535

/*----------------------------------------------------------------------------*/
uint8_t *
EthernetOutput(struct mtcp_manager *mtcp, uint16_t h_proto, 
			   int nif, unsigned char* dst_haddr, uint16_t iplen,
			   struct mtcp_offload_meta* offload_meta)
{
	uint8_t *buf;
	struct ethhdr *ethh;
	int i, eidx;

	/* 
 	 * -sanity check- 
	 * return early if no interface is set (if routing entry does not exist)
	 */
	if (nif < 0) {
		TRACE_INFO("No interface set!\n");
		return NULL;
	}

	eidx = CONFIG.nif_to_eidx[nif];
	if (eidx < 0) {
		TRACE_INFO("No interface selected!\n");
		return NULL;
	}

	if (offload_meta && offload_meta->splice_meta)
		buf = mtcp->iom->get_wptr(mtcp->ctx, eidx, iplen + ETHERNET_HEADER_LEN + sizeof(struct mtcp_splice_meta));
	else
		buf = mtcp->iom->get_wptr(mtcp->ctx, eidx, iplen + ETHERNET_HEADER_LEN);
	if (!buf) {
		//TRACE_DBG("Failed to get available write buffer\n");
		return NULL;
	}
	//memset(buf, 0, ETHERNET_HEADER_LEN + iplen);

#if 0
	TRACE_DBG("dst_hwaddr: %02X:%02X:%02X:%02X:%02X:%02X\n",
				dst_haddr[0], dst_haddr[1], 
				dst_haddr[2], dst_haddr[3], 
				dst_haddr[4], dst_haddr[5]);
#endif

	ethh = (struct ethhdr *)buf;
	for (i = 0; i < ETH_ALEN; i++) {
		ethh->h_source[i] = CONFIG.eths[eidx].haddr[i];
		ethh->h_dest[i] = dst_haddr[i];
	}

	if (offload_meta) {
		ethh->h_proto = htons(offload_meta->offload_type);
		//ethh->h_proto = htons(h_proto);
		if (offload_meta->splice_meta) {
			ethh += 1;
			struct mtcp_splice_meta* insert;
			insert = (struct mtcp_splice_meta*)ethh;
			memcpy(insert, offload_meta->splice_meta, sizeof(struct mtcp_splice_meta));
			return (uint8_t *)(insert + 1);
		}
	}		
	else
		ethh->h_proto = htons(h_proto);

	return (uint8_t *)(ethh + 1);
}
/*----------------------------------------------------------------------------*/
#ifdef USE_NFP_NIC
uint8_t *
EthernetControlOutput(struct mtcp_manager *mtcp)
{
	uint8_t *buf;
	struct ethhdr *ethh;
	int eidx;
	uint32_t c;
	uint8_t bitshift_c = 0;
	
	eidx = CONFIG.nif_to_eidx[0];
	if (eidx < 0) {
		TRACE_INFO("No interface selected!\n");
		return NULL;
	}

	buf = mtcp->iom->get_wptr(mtcp->ctx, eidx, ETHERNET_HEADER_LEN);
	if (!buf) {
		TRACE_ERROR("get_wptr() failed\n");		
		return NULL;
	}

	ethh = (struct ethhdr *)buf;
	ethh->h_proto = htons(ETH_P_IP_TCP_OFFLOAD_INIT_CTRL);

	/* check if the number of CPU cores is power of 2 (max: 2^8 = 256) */
	c = CONFIG.num_cores;
	while ((c & 0x1) == 0x0 && bitshift_c < 8) {
		c >>= 1;
		bitshift_c++;
	}

	/* deliver CPU bitmask to NIC (to be used for RSS) */
	if ((c >> 1) != 0) {		
		/* if # CPU cores is not power of 2, set bitmask as 0 (use 1 core) */
		TRACE_ERROR("Number of CPU cores is not power of 2.. use 1 core\n");
		ethh->h_source[5] = 0x0;
	}
	else {
		/* if # CPU cores is power of 2, set bitmask */
		ethh->h_source[5] = CONFIG.num_cores - 1;
	}
	
	return (uint8_t *)(ethh + 1);
}
/*----------------------------------------------------------------------------*/
uint8_t *
AddListenNICPort(struct mtcp_manager *mtcp, uint32_t ip, uint16_t port)
{
	uint8_t *buf;
	struct ethhdr *ethh;
	int eidx;
	
	eidx = CONFIG.nif_to_eidx[0];
	if (eidx < 0) {
		TRACE_INFO("No interface selected!\n");
		return NULL;
	}

	buf = mtcp->iom->get_wptr(mtcp->ctx, eidx, ETHERNET_HEADER_LEN);
	if (!buf) {
		TRACE_ERROR("get_wptr() failed\n");		
		return NULL;
	}

	ethh = (struct ethhdr *)buf;
	ethh->h_proto = htons(ETH_P_IP_TCP_OFFLOAD_LISTEN);

	memcpy(&(ethh->h_source[2]), &ip, sizeof(uint32_t));
	memcpy(&(ethh->h_dest[0]), &port, sizeof(uint16_t));
	
	return (uint8_t *)(ethh + 1);
}
/*----------------------------------------------------------------------------*/
uint8_t *
DelListenNICPort(struct mtcp_manager *mtcp)
{
	uint8_t *buf;
	struct ethhdr *ethh;
	int eidx;
	uint32_t ip = 0;
	uint16_t port = 0;	
	
	eidx = CONFIG.nif_to_eidx[0];
	if (eidx < 0) {
		TRACE_INFO("No interface selected!\n");
		return NULL;
	}

	buf = mtcp->iom->get_wptr(mtcp->ctx, eidx, ETHERNET_HEADER_LEN);
	if (!buf) {
		TRACE_ERROR("get_wptr() failed\n");		
		return NULL;
	}

	ethh = (struct ethhdr *)buf;
	ethh->h_proto = htons(ETH_P_IP_TCP_OFFLOAD_LISTEN);

	memcpy(&(ethh->h_source[2]), &ip, sizeof(uint32_t));
	memcpy(&(ethh->h_dest[0]), &port, sizeof(uint16_t));
	
	return (uint8_t *)(ethh + 1);
}
#endif
/*----------------------------------------------------------------------------*/
