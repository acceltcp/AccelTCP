#ifndef COMMON_H
#define COMMON_H
/*------------------------------------------------------------------------*/
#include <pif_plugin.h>
#include <pif_headers.h>
#include <pkt_ops.h>
#include <blm.h>
/*------------------------------------------------------------------------*/
/* user-configurable parameters                                           */
/*------------------------------------------------------------------------*/
/* enable connection setup offload */
#define ENABLE_SETUP_OFFLOAD    1
/* enable connetion teardown offload */
#define ENABLE_TEARDOWN_OFFLOAD 1
/* (teardown offload) enable retransmission of offloaded payload */
#define ENABLE_TEARDOWN_RTO     1
#if ENABLE_TEARDOWN_RTO
#define DEFAULT_TS_RTO          TS_500MS
#define DEFAULT_RTO_EPOCH       (DEFAULT_TS_RTO >> BITSHIFT_RTO_GROUPS)
#endif
/*------------------------------------------------------------------------*/
/* enable TCP timestamp option */
#define ENABLE_TIMESTAMP         1
/*------------------------------------------------------------------------*/
/* enable timewait in connection teardown */
#define ENABLE_TEARDOWN_TIMEWAIT 0
#if ENABLE_TEARDOWN_TIMEWAIT
/* TIME_WAIT duration = (DEFAULT_TS_RTO * TW_TIMER_CYCLE) */ 
#define TW_TIMER_CYCLE           3
#define INIT_TWCYCLE             (TW_TIMER_CYCLE << 28)
#define TWCYCLE_1                (1 << 28)
#endif
/*------------------------------------------------------------------------*/
/* enable early retransmission on payload retransmission from client */
#define EARLY_REXMIT 0
/*------------------------------------------------------------------------*/
#define FILTER_BY_ADDR 1
/*------------------------------------------------------------------------*/
/* TCP option values (FIXME: hard-coded default values of mTCP) */
#define TCP_WSCALE_DEFAULT      7
#define TCP_MSS_DEFAULT         1460
/*------------------------------------------------------------------------*/
/* implementation-specific parameters                                     */
/*------------------------------------------------------------------------*/
#define NUM_RTO_GROUPS          8  /* should be power of 2 */
#define BITMASK_RTO_GROUPS      (NUM_RTO_GROUPS - 1)
#define BITSHIFT_RTO_GROUPS     3  /* 2^3 = 8 */
/*------------------------------------------------------------------------*/
#define NUM_HOSTS    4
#define NUM_PORTS    (1 << 16)
#define MAX_FLOWS    NUM_HOSTS * NUM_PORTS
/*------------------------------------------------------------------------*/
#define MAX_PKTNUM  1
#define PKTBUF_SIZE ((DEFAULT_MTU + sizeof(uint32_t) - 1) / sizeof(uint32_t))
/*------------------------------------------------------------------------*/
/* constant/type definitions                                              */
/*------------------------------------------------------------------------*/
#define TRUE  1
#define FALSE 0
#define NULL  0
/*------------------------------------------------------------------------*/
#define NET_TCP_FLAG_SYN    0x02
#define NET_TCP_FLAG_ACK    0x10
#define NET_TCP_FLAG_SYNACK 0x12
#define NET_TCP_FLAG_FIN    0x01
#define NET_TCP_FLAG_RST    0x04
/*------------------------------------------------------------------------*/
#define ETHERTYPE_IPV4                0x0800
#define ETHERTYPE_TEARDOWN_OFFLOAD    0x0808
#define ETHERTYPE_SETUP_OFFLOAD       0x0809
#define ETHERTYPE_SETUP_OFFLOAD_CTRL  0x080B
#define ETHERTYPE_OFFLOAD_INIT_CTRL   0x080C
/*------------------------------------------------------------------------*/
#define DEFAULT_MTU  1514
#define DEFAULT_MSS  1460
#define DEFAULT_HDR  54
#define ETH_HDRLEN   14
#define TCP_HDRLEN   20
#define TCPIP_HDRLEN 40
/*------------------------------------------------------------------------*/
#define ISN_FILTER   0x00FFFFFF
/*------------------------------------------------------------------------*/

#define MIN(a,b) ((a < b)? a : b)
#define SWAP(ports) ((ports >> 16) | ((ports & 0xFFFF) << 16))
/*------------------------------------------------------------------------*/
#endif
