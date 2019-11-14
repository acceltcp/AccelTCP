#ifndef __TCP_OUT_H_
#define __TCP_OUT_H_

#include "mtcp.h"
#include "tcp_stream.h"

enum ack_opt
{
	ACK_OPT_NOW, 
	ACK_OPT_AGGREGATE, 
	ACK_OPT_WACK
};

uint8_t*
SendTCPPacketStandalone(struct mtcp_manager *mtcp, 
		uint32_t saddr, uint16_t sport, uint32_t daddr, uint16_t dport, 
		uint32_t seq, uint32_t ack_seq, uint16_t window, uint8_t flags, 
		const uint8_t *payload, uint16_t payloadlen, 
		uint32_t cur_ts, uint32_t echo_ts);

int
SendTCPPacket(struct mtcp_manager *mtcp, tcp_stream *cur_stream,
		uint32_t cur_ts, uint8_t flags, uint8_t *payload, uint16_t payloadlen);

uint8_t*
SendTCPOffloadPacketStandalone(struct mtcp_manager *mtcp, uint16_t offload_type,
		uint32_t saddr, uint16_t sport, uint32_t daddr, uint16_t dport, 
		uint32_t seq, uint32_t ack_seq, uint16_t window, uint8_t flags, 
		const uint8_t *payload, uint16_t payloadlen, 
	    uint32_t cur_ts, uint32_t echo_ts);

int
SendTCPOffloadPacket(struct mtcp_manager *mtcp, tcp_stream *cur_stream,
					 uint32_t cur_ts, uint8_t flags, uint8_t *payload, uint16_t payloadlen,
					 struct mtcp_offload_meta* offload_meta);

extern inline int 
WriteTCPControlList(mtcp_manager_t mtcp, 
		struct mtcp_sender *sender, uint32_t cur_ts, int thresh);

extern inline int
WriteTCPDataList(mtcp_manager_t mtcp, 
		struct mtcp_sender *sender, uint32_t cur_ts, int thresh);

extern inline int 
WriteTCPACKList(mtcp_manager_t mtcp, 
		struct mtcp_sender *sender, uint32_t cur_ts, int thresh);

extern inline void 
AddtoControlList(mtcp_manager_t mtcp, tcp_stream *cur_stream, uint32_t cur_ts);

extern inline void 
AddtoSendList(mtcp_manager_t mtcp, tcp_stream *cur_stream);

extern inline void 
RemoveFromControlList(mtcp_manager_t mtcp, tcp_stream *cur_stream);

extern inline void 
RemoveFromSendList(mtcp_manager_t mtcp, tcp_stream *cur_stream);

extern inline void 
RemoveFromACKList(mtcp_manager_t mtcp, tcp_stream *cur_stream);

extern inline void
EnqueueACK(mtcp_manager_t mtcp, 
		tcp_stream *cur_stream, uint32_t cur_ts, uint8_t opt);

extern inline void 
DumpControlList(mtcp_manager_t mtcp, struct mtcp_sender *sender);

#if TCP_CALCULATE_CHECKSUM
#ifdef DISABLE_HWCSUM
void
UpdateTCPChecksum(struct tcphdr* tcph, tcp_stream *cur_stream);
#endif
#endif

#endif /* __TCP_OUT_H_ */
