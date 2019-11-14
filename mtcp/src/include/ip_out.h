#ifndef __IP_OUT_H_
#define __IP_OUT_H_

#include <stdint.h>
#include "tcp_stream.h"

extern inline int 
GetOutputInterface(uint32_t daddr, uint8_t* is_external);

void
ForwardIPv4Packet(mtcp_manager_t mtcp, int nif_in, char *buf, int len);

uint8_t *
IPOutputStandalone(struct mtcp_manager *mtcp, uint16_t eth_type, uint8_t protocol, 
		uint16_t ip_id, uint32_t saddr, uint32_t daddr, uint16_t tcplen);

uint8_t *
IPOutput(struct mtcp_manager *mtcp, tcp_stream *stream, uint16_t tcplen,
		 struct mtcp_offload_meta* offload_meta);

#endif /* __IP_OUT_H_ */
