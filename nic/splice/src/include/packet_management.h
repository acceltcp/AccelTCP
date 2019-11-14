#ifndef PACKET_MANAGEMENT_H
#define PACKET_MANAGEMENT_H

/*------------------------------------------------------------------------*/
/* Ethernet Packet Management */
/*------------------------------------------------------------------------*/
struct packet_tx_control {
	union {
		__packed struct {
			uint16_t	close_reason;
			uint32_t        ip_addr;
			uint16_t	port;
			uint32_t        unused;
			uint16_t        eth_type;
			/* For RSS ap search */
			uint32_t	dst_addr;
			uint16_t	dst_port;
		};
		uint32_t            __raw[5];
	};
};
/*------------------------------------------------------------------------*/
static void
send_control_packet(uint32_t out_port,
		    uint16_t close_reason,
		    uint32_t ip_addr, uint16_t port,
		    uint32_t dst_addr, uint16_t dst_port)
{
	int i;
	/* We write to packet data here and copy it into the ctm buffer */
	__lmem struct packet_tx_control Pdata;

	/* Build up the packet */
	reg_zero(Pdata.__raw, sizeof(struct packet_tx_control));

	Pdata.close_reason = close_reason; 
	Pdata.ip_addr = ip_addr;
	Pdata.port = port;
	Pdata.unused = 0x0000; 
	Pdata.eth_type = CTRL_P_SPLICE_FINISH;
	Pdata.dst_addr = dst_addr;
	Pdata.dst_port = dst_port;

	/* TO_HOST */
	if ((out_port & BASE_VF0_PORT_ID) == BASE_VF0_PORT_ID) {
		send_packet_host_anyway(&(Pdata.__raw),
				 (out_port - BASE_VF0_PORT_ID),
				 sizeof(struct packet_tx_control));
	}
	/* Wrong Port (We send control packets only to the host) */
	else {
		/* Given port is not VF */
		local_csr_write(local_csr_mailbox_2, 0xFFFF0000);
	}
}

/*------------------------------------------------------------------------*/
/* TCP Packet Management */
/*------------------------------------------------------------------------*/
#define TCP_DATA_LEN 1
struct packet_tx_tcp {
	union {
		__packed struct {
			uint16_t        eth_dst_hi;
			uint32_t        eth_dst_lo;
			uint32_t        eth_src_hi;
			uint16_t        eth_src_lo;
			uint16_t        eth_type;
			struct ip4_hdr  ip;
			struct tcp_hdr  tcp;
			uint8_t         tcp_data[TCP_DATA_LEN];
		};
		uint32_t            __raw[16];
	};
};
/*------------------------------------------------------------------------*/
static void
send_tcp_packet(uint32_t out_port, 
		uint16_t dst_mac_hi, uint32_t dst_mac_lo,
		uint32_t src_mac_hi, uint16_t src_mac_lo,
		uint32_t srcAddr, uint32_t dstAddr,
#if UPDATE_CHECKSUM
		uint16_t ip_sum, uint32_t tcp_sum,
#endif
		uint16_t tcp_flag, 
		uint16_t srcPort, uint16_t dstPort,
		uint32_t seqNum,  uint32_t ackNum)
{
	int i;
	/* We write to packet data here and copy it into the ctm buffer */
	__lmem struct packet_tx_tcp Pdata;

	/* Build up the packet */
	reg_zero(Pdata.__raw, sizeof(struct packet_tx_tcp));
 
	Pdata.eth_dst_hi = dst_mac_hi;
	Pdata.eth_dst_lo = dst_mac_lo;
	Pdata.eth_src_hi = src_mac_hi;
	Pdata.eth_src_lo = src_mac_lo;
	Pdata.eth_type = NET_ETH_TYPE_IPV4;

	Pdata.ip.ver = 4;
	Pdata.ip.hl = 5;
	Pdata.ip.tos = 0;
	Pdata.ip.len = sizeof(Pdata.ip) +
		sizeof(Pdata.tcp) + sizeof(Pdata.tcp_data);
	Pdata.ip.frag = 0;
	Pdata.ip.ttl = 64;
	Pdata.ip.proto = 0x06;
	Pdata.ip.src = srcAddr;
	Pdata.ip.dst = dstAddr;

	Pdata.tcp.sport = srcPort;
	Pdata.tcp.dport = dstPort;
	Pdata.tcp.seq = seqNum;
	Pdata.tcp.ack = ackNum;
	Pdata.tcp.off = 5;
	Pdata.tcp.flags = tcp_flag;
	Pdata.tcp.win = 6000;
	Pdata.tcp.urp = 0;

#if UPDATE_CHECKSUM	
	Pdata.ip.sum = ip_sum;
	Pdata.tcp.sum = tcp_sum; 
#endif

	/* TO_WIRE */
	if ((out_port & BASE_VF0_PORT_ID) == BASE_PHY0_PORT_ID) {
		send_packet_wire(&(Pdata.__raw),
				 (out_port ?
				 1 : 0),
				 sizeof(struct packet_tx_tcp));
	}
	/* Wrong Port */
	else {
		/* Given port is neither PF nor VF */
		local_csr_write(local_csr_mailbox_2, 0xFFFF0000);
	}
}
/*------------------------------------------------------------------------*/

#endif /* PACKET_MANAGEMENT_H */
