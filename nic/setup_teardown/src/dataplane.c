/*------------------------------------------------------------------------*/
#include <common.h>
#include <conn_table.h>
#include <nfp_device.h>
#include <nfp_util.h>
#include <rss.h>
#include <nbi_out.h>
/*------------------------------------------------------------------------*/
#if ENABLE_SETUP_OFFLOAD
__shared __export __addr40 __imem uint32_t listen_addr = 0;
__shared __export __addr40 __imem uint16_t listen_port = 0;
#endif
#if ENABLE_TEARDOWN_OFFLOAD && ENABLE_TEARDOWN_RTO
__declspec(local_mem) uint64_t last_rto_check_ts = 0;
__declspec(local_mem) uint32_t cur_ts_epoch = 0;
__declspec(imem export scope(global)) uint32_t global_ts_epoch = 0;
#endif
/*------------------------------------------------------------------------*/
/* initialization function triggered only in master ME */
void
pif_plugin_init_master()
{
	/* initialize connection state table and RTO bitmap */
#if ENABLE_TEARDOWN_OFFLOAD
	table_init();
#endif
}
/*------------------------------------------------------------------------*/
/* initialization function triggered in each MEs */
void
pif_plugin_init()
{
	/* calculate continuous meid on start
	 * (in order to prevent dataplane from calculating for every packet) */
#if ENABLE_TEARDOWN_OFFLOAD && ENABLE_TEARDOWN_RTO
	nfp_dev_set_cont_meid();
#endif
}
/*------------------------------------------------------------------------*/
uint32_t
ones_sum_add(uint32_t sum1, uint32_t sum2)
{
  __gpr uint32_t ret;
  __asm alu[ret , sum1, +, sum2];
  __asm alu[ret, ret, +carry, 0];
  return ret;
}
/*------------------------------------------------------------------------*/
uint16_t
ones_sum_fold16(uint32_t sum)
{
  uint32_t ret;
  ret = (sum >> 16) + (uint16_t)(sum);
  ret = (ret >> 16) + (uint16_t)(ret);
  return ret;
}
/*------------------------------------------------------------------------*/
int
reply_with_ack(EXTRACTED_HEADERS_T *headers,
			   PIF_PLUGIN_ethernet_T *eth,
			   PIF_PLUGIN_ipv4_T *ipv4,
			   PIF_PLUGIN_tcp_T *tcp,
			   uint32_t seqNo, uint32_t ackNo, uint8_t flags)
{
  PIF_PLUGIN_tcp_opt_T *tcp_opt;
  uint32_t dstMAC_0 = PIF_HEADER_GET_ethernet___dstAddr___0(eth);
  uint32_t dstMAC_1 = PIF_HEADER_GET_ethernet___dstAddr___1(eth);
  uint32_t dstAddr = dstAddr = ipv4->dstAddr;
  uint32_t new_tcp_csum, tcpcsumOff;
  
  /* swap L2-L4 address and ports */
  PIF_HEADER_SET_ethernet___dstAddr___0(eth,
                                  PIF_HEADER_GET_ethernet___srcAddr___0(eth));
  PIF_HEADER_SET_ethernet___dstAddr___1(eth,
                                  PIF_HEADER_GET_ethernet___srcAddr___1(eth));
  PIF_HEADER_SET_ethernet___srcAddr___0(eth, dstMAC_0);
  PIF_HEADER_SET_ethernet___srcAddr___1(eth, dstMAC_1);
  
  ipv4->dstAddr = ipv4->srcAddr;
  ipv4->srcAddr = dstAddr;
  tcp->sdPorts = SWAP(tcp->sdPorts);
  
  tcpcsumOff = ones_sum_add(~(tcp->seqNo), seqNo);
  tcp->seqNo = seqNo;
  
  tcpcsumOff = ones_sum_add(tcpcsumOff, ~(tcp->ackNo));
  tcpcsumOff = ones_sum_add(tcpcsumOff, ackNo);
  tcp->ackNo = ackNo;
  
  tcpcsumOff = ones_sum_add(tcpcsumOff, ~(tcp->flags));
  tcpcsumOff = ones_sum_add(tcpcsumOff, flags);  
  tcp->flags = flags;

  /* encode window scale option in TCP timestamp */
#if ENABLE_TIMESTAMP
  tcpcsumOff = ones_sum_add(tcpcsumOff, ~(tcp->ts_ecr));
  tcp->ts_ecr = tcp->ts_val;
  tcp->ts_val = ((local_csr_read(local_csr_timestamp_high) << 6)
				 | TCP_WSCALE_DEFAULT);
  tcpcsumOff = ones_sum_add(tcpcsumOff, tcp->ts_val);
#endif

  /* update TCP checksum for the new packet */
  new_tcp_csum = ones_sum_add(~(tcp->checksum), tcpcsumOff);
  PIF_HEADER_SET_tcp___checksum (tcp,  ~ones_sum_fold16(new_tcp_csum));

  pif_plugin_meta_set__standard_metadata__egress_spec(headers,
                                                      BASE_PHY0_PORT_ID);	
  return PIF_PLUGIN_RETURN_FORWARD;
}
/*------------------------------------------------------------------------*/
#if ENABLE_TEARDOWN_OFFLOAD && ENABLE_TEARDOWN_RTO
void
pif_plugin__process_timer_control()
{
  __gpr uint32_t i, cnt, idx;
  __gpr uint64_t val;
  __gpr uint8_t cur_rtoGroup = (cur_ts_epoch + 1) & BITMASK_RTO_GROUPS;
  __gpr uint32_t start_flow_group = FLOW_GROUP_PER_ME * nfp_dev_get_cont_meid();
  __gpr uint32_t end_flow_group   = start_flow_group + FLOW_GROUP_PER_ME;
  __gpr uint32_t j, pkt_cnt, pkt_acked, tw_cycle_left;

  volatile __declspec(imem) __declspec(addr40) uint64_t *preg
    = &g_retx_map[cur_rtoGroup][start_flow_group];
  
  /* because the total number of flow groups might not be multiple of
     FLOW_GROUP_PER_ME, adjust the end_flow_group in the last ME */
  if (end_flow_group > MAX_FLOW_GROUP)
    end_flow_group = MAX_FLOW_GROUP;
  
  /* ygmoon: now bitmap traversal and RTO check is performed by every ME
   * (each ME has its own dedicated space on RTO bitmap to handle) */
  for (i = start_flow_group; i < end_flow_group; i++, preg++) {
    val = *preg;
    cnt = 0;
	
    /* if val != 0, check which bit is set */
    while (val != 0) {
      if (val & 1) {
        idx = (i << 6) + cnt;
#if ENABLE_TEARDOWN_TIMEWAIT
		tw_cycle_left = FLOWID_TO_TWCYCLE(idx);
		if (tw_cycle_left == 1)
		  table_remove_fid(idx);
		else if (tw_cycle_left != 0)
		  table_timewait_decr(idx);
		else {
#endif
		pkt_cnt = FLOWID_TO_PKTCNT(idx);
		pkt_acked = FLOWID_TO_PKTACKED(idx);
		for (j = pkt_acked; j < pkt_cnt; j++)
		  nbi_send_pkt(&state_pktbuf[idx], j);
#if ENABLE_TEARDOWN_TIMEWAIT
        }
#endif
      }
      val >>= 1;
      cnt++;
    }
  }
  cur_ts_epoch++;
}
#endif
/*------------------------------------------------------------------------*/
int
pif_plugin__from_wire(EXTRACTED_HEADERS_T *headers, MATCH_DATA_T *match_data)
{
  PIF_PLUGIN_ethernet_T *eth = pif_plugin_hdr_get_ethernet(headers);
  PIF_PLUGIN_ipv4_T *ipv4 = pif_plugin_hdr_get_ipv4(headers);
  PIF_PLUGIN_tcp_T *tcp = pif_plugin_hdr_get_tcp(headers);
  uint32_t hash_value, sport, payloadlen;
#if ENABLE_TEARDOWN_OFFLOAD
  __xread flow_entry read_entry;
  
#if ENABLE_TEARDOWN_RTO
  if (__ctx() == MASTER_CTX) {
    if (__MEID == MASTER_MEID) {
      uint64_t cur_ts = nfp_timer_get_cur_ts();
      if (cur_ts - last_rto_check_ts > DEFAULT_RTO_EPOCH) {
        last_rto_check_ts = cur_ts;
        pif_plugin__process_timer_control();
        global_ts_epoch++;
      }
    }			
    else if (global_ts_epoch > cur_ts_epoch) {
      pif_plugin__process_timer_control();
    }
  }
#endif
#endif
		
  if (!pif_plugin_hdr_tcp_present(headers)) {
    pif_plugin_meta_set__standard_metadata__egress_spec(headers,
                                                        BASE_VF0_PORT_ID);
    return PIF_PLUGIN_RETURN_FORWARD;
  }

#if (ENABLE_SETUP_OFFLOAD || ENABLE_TEARDOWN_OFFLOAD)
  /* hash_value: used for both SYN cookie and connection table lookup */
  hash_value = nfp_perform_crc32(ipv4->srcAddr, ipv4->dstAddr, tcp->sdPorts);
#endif
  
#if ENABLE_SETUP_OFFLOAD
  /* SYN packet -> reply with SYN + ACK (carrying SYN cookie) */
  if ((tcp->flags == NET_TCP_FLAG_SYN)) {
	  uint8_t mss_enc_val = 0x0;
	  
#if FILTER_BY_ADDR
	  if (!((ipv4->dstAddr == listen_addr) &&
			((tcp->sdPorts & 0xFFFF) == listen_port))) {
		  goto out;
	  }
#endif

	if (pif_plugin_hdr_tcp_opt_present(headers)) {
	  PIF_PLUGIN_tcp_opt_T *tcp_opt = pif_plugin_hdr_get_tcp_opt(headers);
	  if (tcp_opt->mss_val >= 1460)
		  mss_enc_val = 0x3;
	  else if (tcp_opt->mss_val >= 1440)
	    mss_enc_val = 0x2;
	  else if (tcp_opt->mss_val >= 1300)
	    mss_enc_val = 0x1;
	}
	
    return reply_with_ack(headers, eth, ipv4, tcp,
						  ((mss_enc_val << 30) |
						   (local_csr_read(local_csr_timestamp_high) & 0x3F000000) |
						   (hash_value & ISN_FILTER)),
						  tcp->seqNo + 1, NET_TCP_FLAG_SYNACK);
  }
#endif

#if ENABLE_TEARDOWN_OFFLOAD  
  sport = (tcp->sdPorts >> 16);  
  /* we have an flow entry whose teardown is being offloaded */
  if (table_lookup_and_fetch(ipv4->srcAddr, sport, &read_entry)) {

    /* if it's a client-side FIN, validate its seq & ack numbers,
       remove the corresponding flow entry, send the final ack, and stop */	  
	if (tcp->flags & NET_TCP_FLAG_FIN) {
	  /* assumption: client sends no more data after teardown offload for now */
      if ((tcp->seqNo == read_entry.expectedSeqNo) &&
          (tcp->ackNo == read_entry.expectedAckNo)) {
#if ENABLE_TEARDOWN_TIMEWAIT
		table_timewait(ipv4->srcAddr, sport);
#else
		table_remove_fid(FLOWID(ipv4->srcAddr, sport));
#endif
		return reply_with_ack(headers, eth, ipv4, tcp,
                              tcp->ackNo, tcp->seqNo + 1, NET_TCP_FLAG_ACK);
      }
    }
    /* if it's a client-side RST, remove the flow entry */ 
    else if (tcp->flags & NET_TCP_FLAG_RST) {
	  table_remove_fid(FLOWID(ipv4->srcAddr, sport));
    }
    else { /* if (tcp->flags & NET_TCP_FLAG_ACK) */
		uint32_t flow_id = FLOWID(ipv4->srcAddr, sport);
		/* calculate the number of acknowledged packets */
		int pktAcked = ((tcp->ackNo & ISN_FILTER) - ((hash_value & ISN_FILTER) + 1)) / DEFAULT_MSS;
		if (pktAcked > 0) {
			uint32_t flow_state = read_entry.pktCnt_pktAcked_rtoGroup;
			/* update the number of acknowledged packets */
			flow_state = (flow_state & 0xFFFFFF0F) | (pktAcked << 4);
			g_flow_table[flow_id].pktCnt_pktAcked_rtoGroup = flow_state;
		}

#if EARLY_REXMIT
		/* if client retransmits payload, do early retransmission */
		if (nbi_get_payloadlen(ipv4) > 0) {
			int pktCount = (read_entry.pktCnt_pktAcked_rtoGroup >> 8);
			while (pktAcked < pktCount) {
				nbi_send_pkt(&state_pktbuf[flow_id], pktAcked++);
			}
		}
#endif
    }
	
    return PIF_PLUGIN_RETURN_DROP;
  }
#endif

#if ENABLE_SETUP_OFFLOAD
  /* the ACK packet for SYN + ACK -> mark and forward to host */
  if ((tcp->ackNo & ISN_FILTER) == ((hash_value & ISN_FILTER) + 1)) {	  
  /* mark and forward the packet to host */
    eth->etherType = ETHERTYPE_SETUP_OFFLOAD;
  }
#endif

out:
  /* pass up regular packets to the host side */
  pif_plugin_meta_set__standard_metadata__egress_spec(headers,
                                                get_rss_egress_port(headers));	
  return PIF_PLUGIN_RETURN_FORWARD;
}
/*------------------------------------------------------------------------*/
int
pif_plugin__from_host(EXTRACTED_HEADERS_T *headers, MATCH_DATA_T *match_data)
{
  PIF_PLUGIN_ethernet_T *eth = pif_plugin_hdr_get_ethernet(headers);
  PIF_PLUGIN_ipv4_T *ipv4;
  PIF_PLUGIN_tcp_T *tcp;
  uint16_t dport;
  int pkt_cnt = 1;
  
  /* initialize dataplane (control packet sent from mTCP at host) */
  if (eth->etherType == ETHERTYPE_OFFLOAD_INIT_CTRL) {
    set_rss_bitmask(headers);
    pif_plugin_init_master();
    return PIF_PLUGIN_RETURN_DROP;
  }
  else if (eth->etherType == ETHERTYPE_SETUP_OFFLOAD_CTRL) {
	listen_addr = PIF_HEADER_GET_ethernet___srcAddr___0(eth);
	listen_port = PIF_HEADER_GET_ethernet___dstAddr___1(eth);
	return PIF_PLUGIN_RETURN_DROP;
  }
  
#if ENABLE_TEARDOWN_OFFLOAD
  ipv4 = pif_plugin_hdr_get_ipv4(headers);
  tcp = pif_plugin_hdr_get_tcp(headers);
  dport = (tcp->sdPorts & 0xFFFF);
  
  /* if it's a server-side FIN whose teardown process is offloaded to NIC */
  if (eth->etherType == ETHERTYPE_TEARDOWN_OFFLOAD) {
	__xwrite flow_entry insert_entry;
	
    if (!table_lookup(ipv4->dstAddr, dport)) {
#if ENABLE_TEARDOWN_RTO
      uint8_t cur_rtoGroup;
#endif

	  /* set etherType as ETHERTYPE_IPV4 */
	  eth->etherType = ETHERTYPE_IPV4;
	  
	  /* store packets in emem */
	  if (pif_pkt_info_global.pkt_len > DEFAULT_MTU) {
		  pkt_cnt = nbi_dump_pkt_tso(&state_pktbuf[FLOWID(ipv4->dstAddr, dport)]);
	  }
	  else {
		  nbi_dump_pkt(&state_pktbuf[FLOWID(ipv4->dstAddr, dport)]);
	  }
	  
	  /* store expected sequence & acknowledge number for validation */
      insert_entry.expectedSeqNo = tcp->ackNo;
      insert_entry.expectedAckNo = tcp->seqNo + nfp_get_payloadlen() + 1;
	  
#if ENABLE_TEARDOWN_RTO
      cur_rtoGroup = global_ts_epoch & BITMASK_RTO_GROUPS;
      insert_entry.pktCnt_pktAcked_rtoGroup = (pkt_cnt << 8) | cur_rtoGroup;
      table_insert(&insert_entry, ipv4->dstAddr, dport, cur_rtoGroup);
#else
      insert_entry.pktCnt_pktAcked_rtoGroup = (pkt_cnt << 8);
      table_insert(&insert_entry, ipv4->dstAddr, dport, 0);
#endif
    }
  }
  else if (tcp->flags & NET_TCP_FLAG_RST) {
    if (table_lookup(ipv4->dstAddr, dport)) {	  
      table_remove_fid(FLOWID(ipv4->dstAddr, dport));
	}
  }  
#else /* ENABLE_TEARDOWN_OFFLOAD */
  /* perform TSO without dumping to emem */
  if (pif_pkt_info_global.pkt_len > DEFAULT_MTU) {
	  pkt_cnt = nbi_dump_pkt_tso(NULL);
  }  
#endif

  /* if the packet is segmented, drop the original packet */
  if (pkt_cnt > 1)
	  return PIF_PLUGIN_RETURN_DROP;
  
  pif_plugin_meta_set__standard_metadata__egress_spec(headers,
                                                      BASE_PHY0_PORT_ID);  
  return PIF_PLUGIN_RETURN_FORWARD;
}
/*------------------------------------------------------------------------*/
