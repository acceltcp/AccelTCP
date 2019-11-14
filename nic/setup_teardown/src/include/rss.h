#ifndef RSS_H
#define RSS_H
/*------------------------------------------------------------------------*/
#include <std/hash.h>
/*------------------------------------------------------------------------*/
#define BASE_PHY0_PORT_ID 0x0000
#define BASE_VF0_PORT_ID  0x0300
/*------------------------------------------------------------------------*/
/* RSS-specific variables */
/* RSS key that satisfies the condition for symmetric RSS
   (make sure that mTCP uses the same key to support GetRSSCPUCore()) */
__shared __declspec(local_mem) const uint8_t rss_key[HASH_TOEPLITZ_SECRET_KEY_SZ] = {
	0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05,
	0x05, 0x05, 0x05, 0x05,	0x05, 0x05, 0x05, 0x05,
	0x05, 0x05, 0x05, 0x05,	0x05, 0x05, 0x05, 0x05,
	0x05, 0x05, 0x05, 0x05,	0x05, 0x05, 0x05, 0x05,
	0x05, 0x05, 0x05, 0x05,	0x05, 0x05, 0x05, 0x05
};
/*------------------------------------------------------------------------*/
/* RSS bitmask (NOTE: we consider (# cores) = (power of 2) case only) */
__shared __export __addr40 __imem uint8_t rss_bitmask;
/*------------------------------------------------------------------------*/
uint32_t
set_rss_bitmask(EXTRACTED_HEADERS_T *headers) {

	PIF_PLUGIN_ethernet_T *eth = pif_plugin_hdr_get_ethernet(headers);
	
	rss_bitmask = PIF_HEADER_GET_ethernet___srcAddr___0(eth);
}
/*------------------------------------------------------------------------*/
uint32_t
get_rss_egress_port(EXTRACTED_HEADERS_T *headers) {

	PIF_PLUGIN_ipv4_T *ipv4 = pif_plugin_hdr_get_ipv4(headers);
	PIF_PLUGIN_tcp_T *tcp = pif_plugin_hdr_get_tcp(headers);	
	uint32_t hash_key[3];
	uint32_t hash_value;
	unsigned ingress_port;
	
	ingress_port = pif_plugin_meta_get__standard_metadata__ingress_port(headers);

	hash_key[0] = ipv4->srcAddr;
	hash_key[1] = ipv4->dstAddr;
	hash_key[2] = tcp->sdPorts;
	hash_value = hash_toeplitz((void *)hash_key, sizeof(hash_key),
							   (void *)rss_key, HASH_TOEPLITZ_SECRET_KEY_SZ);

	return BASE_VF0_PORT_ID + (hash_value & rss_bitmask);
}
/*------------------------------------------------------------------------*/
#endif
