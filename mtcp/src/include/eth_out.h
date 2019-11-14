#ifndef __ETH_OUT_H_
#define __ETH_OUT_H_

#include <stdint.h>

#include "mtcp.h"
#include "tcp_stream.h"
#ifndef DISABLE_PSIO
#include "ps.h"
#endif

#define MAX_SEND_PCK_CHUNK 64

/*------------------------------------------------------------------------------------------*/
/* ethernet type used for NIC offload (setup, splice, teardown) */
#define ETH_P_IP_TCP_SETUP_OFFLOAD       0x0809
#define ETH_P_IP_TCP_OFFLOAD_LISTEN      0x080B
#define ETH_P_IP_TCP_SPLICE_OFFLOAD      0x0807
#define CTRL_P_SPLICE_FINISH             0x0901
#define DISABLE_HOST_ACK                 FALSE
#define ETH_P_IP_TCP_TEARDOWN_OFFLOAD    0x0808
#define ETH_P_IP_TCP_OFFLOAD_INIT_CTRL   0x080C
/*------------------------------------------------------------------------------------------*/

uint8_t *
EthernetOutput(struct mtcp_manager *mtcp, uint16_t h_proto, 
			   int nif, unsigned char* dst_haddr, uint16_t iplen,
			   struct mtcp_offload_meta* offload_meta);

#ifdef USE_NFP_NIC
uint8_t *
EthernetControlOutput(struct mtcp_manager *mtcp);
uint8_t *
AddListenNICPort(struct mtcp_manager *mtcp, uint32_t ip, uint16_t port);
uint8_t *
DelListenNICPort(struct mtcp_manager *mtcp);
#endif

#endif /* __ETH_OUT_H_ */
