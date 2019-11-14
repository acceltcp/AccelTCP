#ifndef RSS_H
#define RSS_H
/*------------------------------------------------------------------------*/
/* RSS-specific variables */

/* the number of LSBs taken from the hash value
   (e.g., 9 LSBs in Intel 40GbE NIC, see Section 7.1.8 of XL710-QDA2 datasheet) */
#define RSS_LSB_MASK  0x01FF

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
__shared __export volatile __addr40 __imem uint8_t rss_bitmask = 0;
/*------------------------------------------------------------------------*/
void
set_rss_bitmask(EXTRACTED_HEADERS_T *headers) {

	PIF_PLUGIN_ethernet_T *eth = pif_plugin_hdr_get_ethernet(headers);
	
	rss_bitmask = PIF_HEADER_GET_ethernet___srcAddr___0(eth);
}
/*------------------------------------------------------------------------*/
uint32_t
get_rss_egress_port(EXTRACTED_HEADERS_T *headers) {

	PIF_PLUGIN_ipv4_T *ipv4 = pif_plugin_hdr_get_ipv4(headers);
	PIF_PLUGIN_tcp_T *tcp = pif_plugin_hdr_get_tcp(headers);	

	return get_rss_egress_port_by_value(
		pif_plugin_meta_get__standard_metadata__ingress_port(headers),
                ipv4->srcAddr,
                ipv4->dstAddr,
                tcp->sdPorts);
}
/*------------------------------------------------------------------------*/
uint32_t
get_rss_egress_port_by_value(uint32_t ingress_port, uint32_t srcAddr,
                             uint32_t dstAddr, uint32_t sdPorts) {

	/* For FIN management, always send to BASE_VF0 */
	volatile uint32_t hash_key[3];
	uint32_t hash_value;
	uint32_t egress_port;

	hash_key[0] = srcAddr;
	hash_key[1] = dstAddr;
	hash_key[2] = sdPorts;
	hash_value = hash_toeplitz((void *)hash_key,
				   sizeof(hash_key),
				   (void *)rss_key,
				   HASH_TOEPLITZ_SECRET_KEY_SZ);

	egress_port  = (ingress_port == BASE_PHY0_PORT_ID) ?
                                   BASE_VF0_PORT_ID : BASE_VF1_PORT_ID;
	egress_port += (hash_value & rss_bitmask);
	return egress_port;
}
/*------------------------------------------------------------------------*/
#endif

