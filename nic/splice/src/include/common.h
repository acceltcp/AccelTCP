#ifndef COMMON_H
#define COMMON_H

#include <std/hash.h>
#include <pkt_ops.h>
#include <net/eth.h>
#include <net/ip.h>
#include <net/tcp.h>
#include <pif_plugin.h>

/*------------------------------------------------------------------------*/
/* Enable Connection Setup Offload */
#define ENABLE_SETUP_OFFLOAD 1
/*------------------------------------------------------------------------*/
/* Update Checksum */
#define UPDATE_CHECKSUM 1
/*------------------------------------------------------------------------*/
/* NIC MAC Address */

/* Port 0 */
#define PORT0_MAC_0 0x00154d12
#define PORT0_MAC_1 0x129b

/* Port 1 */
#define PORT1_MAC_0 0x00154d12
#define PORT1_MAC_1 0x129c
/*------------------------------------------------------------------------*/
/* For RSS */
#define NUM_RX_CORES 8
#define ETHERTYPE_OFFLOAD_INIT_CTRL 0x080C
#define ETHERTYPE_SETUP_OFFLOAD 0x0809

#define BASE_PHY0_PORT_ID 0x0000
#define BASE_PHY1_PORT_ID 0x0004
#define BASE_VF0_PORT_ID  0x0300
#define BASE_VF1_PORT_ID  (0x0300 + NUM_RX_CORES)
/*------------------------------------------------------------------------*/
/* For Packet Management */
#define CTRL_P_SPLICE_FINISH 0x0901
#define TCP_DATA_LEN 10
#define SWAP(ports) ((ports >>16) | (ports << 16))
/*------------------------------------------------------------------------*/
/* TCP Flag Value */
#define TCP_FLAG_FIN    0x01    // 0000 0001
#define TCP_FLAG_SYN    0x02    // 0000 0010
#define TCP_FLAG_RST    0x04    // 0000 0100
#define TCP_FLAG_PSH    0x08    // 0000 1000
#define TCP_FLAG_ACK    0x10    // 0001 0000
#define TCP_FLAG_URG    0x20    // 0010 0000
/*------------------------------------------------------------------------*/
#define PACKET_CASE_NORMAL	0x00	// 0000
#define PACKET_CASE_RST 	0x01	// 0001
#define PACKET_CASE_FIN 	0x02	// 0010
#define PACKET_CASE_FINACK	0x04	// 0100
/*------------------------------------------------------------------------*/
/* for debugging */
__export __emem uint32_t wire_debug[1024*1024];
__export __emem uint32_t wire_debug_idx;
#define DEBUG(_a, _b, _c, _d) do { \
                __xrw uint32_t _idx_val = 4; \
                __xwrite uint32_t _dvals[4]; \
                mem_test_add(&_idx_val, &wire_debug_idx, sizeof(_idx_val)); \
                _dvals[0] = _a; \
                _dvals[1] = _b; \
                _dvals[2] = _c; \
                _dvals[3] = _d; \
                mem_write_atomic(_dvals, \
                                                 wire_debug + (_idx_val % (1024 * 1024)), sizeof(_dvals)); \
        } while(0)
/*------------------------------------------------------------------------*/
#endif /* COMMON_H */
