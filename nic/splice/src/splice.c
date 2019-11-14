#include <nfp/mem_atomic.h>
#include <pif_plugin.h>
#include <pif_plugin_metadata.h>
#include <pkt_ops.h>
#include <pif_headers.h>
#include <nfp_override.h>
#include <pif_common.h>
#include <std/hash.h>
#include <nfp/me.h>

#include <common.h>
#include <rss.h>
#include <packet_management.h>
#include <nbi_out.h>

#include <hash_table.h>

#define SET_SRC_MACADDR(e, m1, m2) { \
    PIF_HEADER_SET_ethernet___srcAddr___0(e, m1); \
    PIF_HEADER_SET_ethernet___srcAddr___1(e, m2); \
}

#define SET_DST_MACADDR(e, m1, m2) { \
    PIF_HEADER_SET_ethernet___dstAddr___0(e, m1); \
    PIF_HEADER_SET_ethernet___dstAddr___1(e, m2); \
}

/*---------------------------------------------------------------------------*/
/* The initiallization code with -DPIF_PLUGIN_INIT in compile option. */
void
pif_plugin_init_master()
{
  int i, j;
  for (i = 0; i < (TABLE_SIZE + 1); i++){
    state_hashtable[i].id = i;
    for (j = 0; j < BUCKET_SIZE; j++)
      clear_entry(&(state_hashtable[i].entry_list[j]));
  }
}
/*---------------------------------------------------------------------------*/
#if UPDATE_CHECKSUM
uint32_t
ones_sum_add(uint32_t sum1, uint32_t sum2)
{
  __gpr uint32_t ret;
  __asm alu[ret , sum1, +, sum2];
  __asm alu[ret, ret, +carry, 0];
  return ret;
}
/*---------------------------------------------------------------------------*/
uint16_t
ones_sum_fold16(uint32_t sum)
{
  uint32_t ret;
  ret = (sum >> 16) + (uint16_t)(sum);
  ret = (ret >> 16) + (uint16_t)(ret);
  return ret;
}
#endif
/*---------------------------------------------------------------------------*/
static int
forward_to_host_vf(EXTRACTED_HEADERS_T *headers)
{
  pif_plugin_meta_set__standard_metadata__egress_spec(headers,
					get_rss_egress_port(headers));
  return PIF_PLUGIN_RETURN_FORWARD;
}
/*---------------------------------------------------------------------------*/
#if ENABLE_SETUP_OFFLOAD
int
reply_with_ack(EXTRACTED_HEADERS_T *headers,
			   PIF_PLUGIN_ethernet_T *eth,
			   PIF_PLUGIN_ipv4_T *ipv4,
			   PIF_PLUGIN_tcp_T *tcp,
			   uint32_t seqNo, uint32_t ackNo, uint8_t flags)
{
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
  
  new_tcp_csum = ones_sum_add(~(tcp->checksum), tcpcsumOff);
  PIF_HEADER_SET_tcp___checksum (tcp,  ~ones_sum_fold16(new_tcp_csum));
  
  pif_plugin_meta_set__standard_metadata__egress_spec(headers,
                                                      BASE_PHY0_PORT_ID);
	
  return PIF_PLUGIN_RETURN_FORWARD;
}
#endif
/*------------------------------------------------------------------------*/

/* send a control packet to host which notifies that */
/* the splice of particular address is finished */
__forceinline void
notify_splice_finish(uint32_t ingress_port, 
                     __xrw state_entry* local_entry,
                     uint32_t close_reason)
{
  uint32_t egress_port;

  if (local_entry->match.side == FRONT_TO_BACK) {
    egress_port = get_rss_egress_port_by_value(ingress_port,
                                               local_entry->match.srcAddr, 
                                               local_entry->match.dstAddr,
                                               local_entry->match.sdPorts);
    send_control_packet(egress_port,
                        close_reason,
                        local_entry->action._srcAddr,
                        ((local_entry->action._sdPorts) >> 16),
			local_entry->action._dstAddr,
			((local_entry->action._sdPorts) & 0x0000FFFF));
  }
  else if (local_entry->match.side == BACK_TO_FRONT) {
    egress_port = get_rss_egress_port_by_value(ingress_port,
                                               local_entry->action._dstAddr, 
                                               local_entry->action._srcAddr,
                                               SWAP(local_entry->action._sdPorts));
    send_control_packet(egress_port,
                        close_reason,
                        local_entry->match.dstAddr,
                        ((local_entry->match.sdPorts) & 0x0000FFFF),
			local_entry->match.srcAddr,
			((local_entry->match.sdPorts) >> 16));
  }
  else {
    /* Should Never Happen */
    local_csr_write(local_csr_mailbox_2, 0xFFFF0003);
  }
}
/*---------------------------------------------------------------------------*/
int
pif_plugin_lookup_state(EXTRACTED_HEADERS_T *headers,
			MATCH_DATA_T *match_data)
{
  PIF_PLUGIN_ethernet_T *eth;
  PIF_PLUGIN_ipv4_T *ipv4;
  PIF_PLUGIN_tcp_T *tcp;
  volatile __imem bucket* target_bucket;
  volatile __imem bucket* pair_bucket;

  __xrw state_entry local_entry;
  __xrw state_entry pair_entry;
  __xwrite uint32_t temp_write;
  __xread uint32_t temp_read;
  __xwrite uint32_t temp_write_sup;
  __xread uint32_t temp_read_sup;
  int state, pair_state;
  int index, pair_index;
#if UPDATE_CHECKSUM
  uint32_t new_ipv4_csum, new_tcp_csum;
#endif
  uint32_t cleanup = 0;
  uint32_t packet_case;
  uint32_t ingress_port;
#if ENABLE_SETUP_OFFLOAD
  uint32_t hash_value;
  uint32_t hash_key[3];
#endif
  
  ingress_port =
    pif_plugin_meta_get__standard_metadata__ingress_port(headers);

  if (!pif_plugin_hdr_tcp_present(headers)) {
    pif_plugin_meta_set__standard_metadata__egress_spec(
      headers,
      (ingress_port == 
                     BASE_PHY0_PORT_ID) ? BASE_VF0_PORT_ID:BASE_VF1_PORT_ID);
    return PIF_PLUGIN_RETURN_FORWARD;
  }
  eth = pif_plugin_hdr_get_ethernet(headers);
  ipv4 = pif_plugin_hdr_get_ipv4(headers);
  tcp = pif_plugin_hdr_get_tcp(headers);

#if ENABLE_SETUP_OFFLOAD
  hash_key[0] = ipv4->srcAddr;
  hash_key[1] = ipv4->dstAddr;
  hash_key[2] = tcp->sdPorts;
  hash_value = hash_me_crc32((void *)hash_key, sizeof(hash_key), 1);

  target_bucket = &(state_hashtable[hash_value & TABLE_SIZE]);
#else
  target_bucket = get_bucket_by_hash(ipv4->srcAddr,
                                     ipv4->dstAddr,
                                     tcp->sdPorts);
#endif
  
  /* acquire per-bucket lock */
  acquire_bucket(target_bucket);    
  state = search_current_in_bucket(ipv4->srcAddr,
                                   ipv4->dstAddr,
                                   tcp->sdPorts,
				   target_bucket,
                                   &local_entry,
                                   &index);
  /* release per-bucket lock */
  release_bucket(target_bucket);
  
  if (state < 0) {
#if ENABLE_SETUP_OFFLOAD
    /* SYN packet -> reply with SYN + ACK (carrying SYN cookie) */	
    if (tcp->flags == TCP_FLAG_SYN) {
      return reply_with_ack(headers, eth, ipv4, tcp,
                            hash_value, tcp->seqNo + 1, (TCP_FLAG_SYN | TCP_FLAG_ACK));
    }

    /* the ACK packet for SYN + ACK -> mark and forward to host */
    if (tcp->ackNo == (hash_value + 1)) {
      /* mark and forward the packet to host */
      eth->etherType = ETHERTYPE_SETUP_OFFLOAD;
    }
#endif

    return forward_to_host_vf(headers);
  }

  if (index < 0) {
    /* This should never happen */
    local_csr_write(local_csr_mailbox_2, 0xFFFF0040);
  }

  /* if entry isn't found, forward it to a host VF */
  /* FIX ME: if it's unspliced, drop the packet for now */
  if (!(state & FL_SPLICED)) {
    /* this should not happen */
    local_csr_write(local_csr_mailbox_2, 0xFFFF0003); 
    return PIF_PLUGIN_RETURN_DROP;
  }

#if 0  
  if ((tcp->flags & TCP_FLAG_SYN) && (tcp->flags & TCP_FLAG_ACK)) {
    if (local_entry.side == BACK_TO_FRONT) { 
      return PIF_PLUGIN_RETURN_DROP;
    }
  }
#endif

  /* this connection is spliced */

  /*-------------------------------------------------------------------------*/
  /* determine the packet case */
  packet_case = PACKET_CASE_NORMAL;
  if (tcp->flags & TCP_FLAG_RST) {
    local_csr_write(local_csr_mailbox_2, 0xFFFF0070);
    packet_case |= PACKET_CASE_RST;
  }
  else {
    if (tcp->flags & TCP_FLAG_FIN)
      packet_case |= PACKET_CASE_FIN;

    /* check if this packet is ACK packet of a FIN packet and */
    /* has a correct ack number compared to the seqcuence number of FIN */
    if ((state & FL_FIN_SENT) &&
        (tcp->flags & TCP_FLAG_ACK) &&
        (tcp->ackNo == local_entry.match.seqFINsent + 1))
      packet_case |= PACKET_CASE_FINACK;
  }

  if (packet_case == 0) 
    goto normal_case;
  
  /* packet_case is not PACKET_CASE_NORMAL */
  /* calculate the bucket number of the pair entry */
  pair_bucket = get_bucket_by_hash(local_entry.action._dstAddr,
				   local_entry.action._srcAddr,
				   SWAP(local_entry.action._sdPorts));
  
  /* acquire per-bucket lock of pair bucket */
  acquire_bucket(pair_bucket);
  
  /* find if appropriate pair entry exists in the calculated pair bucket */
  if ((pair_state = search_current_in_bucket(local_entry.action._dstAddr,
					     local_entry.action._srcAddr,
					     SWAP(local_entry.action._sdPorts),
					     pair_bucket,
					     &pair_entry,
					     &pair_index)) <= 0) {
    /* this should not happen: the pair entry does not exist */
    local_csr_write(local_csr_mailbox_2, 0xFFFF0001);
    release_bucket(pair_bucket);
    goto normal_case;
  }

  /* the pair entry is found */
  if ((packet_case & PACKET_CASE_RST) ||
      ((packet_case & PACKET_CASE_FINACK) && (pair_state & FL_FINACK_RCVD))) {
    /* remove the pair entry if the reset packet is come or */
    /* teardown is finished */
    
    temp_write = FL_DELETED;
    mem_write_atomic(&temp_write,
		     (uint32_t*)&(pair_bucket->entry_list[pair_index].match.state),
		     sizeof(temp_write));
    
    //if (packet_case & PACKET_CASE_FINACK)
    cleanup = 1;
  }
  
  if ((packet_case & PACKET_CASE_FIN) && !(pair_state & FL_FIN_SENT)) {
    /* mark the pair entry state to be FL_FIN_SENT */
    /* if this is the first time that FIN PACKET come. */
    temp_write = (pair_state | FL_FIN_SENT);
    temp_write_sup = tcp->seqNo + local_entry.action._seqOff;
    
    mem_write_atomic(&temp_write,
		     (uint32_t*)&(pair_bucket->entry_list[pair_index].match.state),
		     sizeof(temp_write));
    mem_write_atomic(&temp_write_sup,
		     (uint32_t*)&(pair_bucket->entry_list[pair_index].match.seqFINsent),
		     sizeof(temp_write_sup));
  }
  /* release the per-bucket lock of the pair entry */
  release_bucket(pair_bucket);

  if (cleanup) {
    /* if the packet is RST packet or cleanup variable is marked, */
    /* remove the current entry */
    acquire_bucket(target_bucket);

    temp_write = FL_DELETED;
    mem_write_atomic(&temp_write,
		     (uint32_t*)&(target_bucket->entry_list[index].match.state),
		     sizeof(temp_write));
    
    release_bucket(target_bucket);
    /* notify stack to reuse the ports */
    /* 
       close_reason
       normal teardown : 0,
       reset           : 1
    */
    notify_splice_finish(ingress_port, &local_entry, (cleanup ? 0 : 1));
  }
  else if ((packet_case & PACKET_CASE_FINACK) && !(state & FL_FINACK_RCVD)) {
    /* if this packet is the first ACK of the FIN sent by current entry, */
    /* mark the current entry state to be FL_FINACK_RCVD */
    acquire_bucket(target_bucket);
    temp_write = (state | FL_FINACK_RCVD);

    mem_write_atomic(&temp_write,
		     (uint32_t*)&(target_bucket->entry_list[index].match.state),
		     sizeof(temp_write));

    release_bucket(target_bucket);
  }
  
 normal_case:
  
  /*-------------------------------------------------------------------------*/
  /* perform connection splicing */
  /*-------------------------------------------------------------------------*/
  /* update L2-L4 addresses and ports */
  pif_plugin_meta_set__standard_metadata__egress_spec(headers,
                                                     local_entry.action._egress_port);

  if (local_entry.action._egress_port == BASE_PHY0_PORT_ID) {
    SET_SRC_MACADDR(eth, PORT0_MAC_0, PORT0_MAC_1);
  }
  else {
    SET_SRC_MACADDR(eth, PORT1_MAC_0, PORT1_MAC_1);
  }
  SET_DST_MACADDR(eth, local_entry.action._dstMac_0, local_entry.action._dstMac_1);
  PIF_HEADER_SET_ipv4___srcAddr(ipv4, local_entry.action._srcAddr); 
  PIF_HEADER_SET_ipv4___dstAddr(ipv4, local_entry.action._dstAddr);			
  PIF_HEADER_SET_tcp___sdPorts(tcp, local_entry.action._sdPorts);
  /*-------------------------------------------------------------------------*/
#if UPDATE_CHECKSUM
  /* calculate and update the new tcp/ip checksum */
  new_ipv4_csum = ones_sum_add(~(ipv4->checksum), local_entry.match._ipcsumOff);
  new_tcp_csum = ones_sum_add(~(tcp->checksum), local_entry.match._tcpcsumOff);	
  /*
    NOTE: TCP checksum uses 1's complement adder
    (0xFFFFFFFF + 1 = 0x00000001) but seq/ack num uses
    unsigned int adder (0xFFFFFFFF + 1 = 0x00000000) ->
    substract checksum by 1 in case a wraparound in
    seq/ack num exists
  */
  if ((uint32_t) tcp->seqNo > (uint32_t) ~local_entry.action._seqOff)
    new_tcp_csum--;			
  if ((uint32_t) tcp->ackNo > (uint32_t) ~local_entry.action._ackOff)
    new_tcp_csum--;		
  
  PIF_HEADER_SET_tcp___checksum (tcp,  ~ones_sum_fold16(new_tcp_csum));
  PIF_HEADER_SET_ipv4___checksum(ipv4, ~ones_sum_fold16(new_ipv4_csum));
#endif
  /*-------------------------------------------------------------------------*/
  /* update tcp seq/ack numbers */
  PIF_HEADER_SET_tcp___seqNo(tcp, tcp->seqNo + local_entry.action._seqOff);
  PIF_HEADER_SET_tcp___ackNo(tcp, tcp->ackNo + local_entry.action._ackOff);		

  return PIF_PLUGIN_RETURN_FORWARD;
}
/*---------------------------------------------------------------------------*/
int
pif_plugin_apply_offload(EXTRACTED_HEADERS_T *headers,
			 MATCH_DATA_T *match_data)
{
  PIF_PLUGIN_offload_T *offload;
  PIF_PLUGIN_ethernet_T *eth;
  PIF_PLUGIN_ipv4_T *ipv4;
  PIF_PLUGIN_tcp_T *tcp;
  volatile __imem bucket* target_bucket;
  __xrw state_entry ent;
  __xread state_entry local_entry;
  __xread uint32_t temp_read;

  __xread state_entry debug_entry1;

  int state;
  int index;

  int pair_bucket_num;
#if UPDATE_CHECKSUM
  uint32_t ipcsumOff, tcpcsumOff;
#endif
  uint32_t ingress_port;

  offload = pif_plugin_hdr_get_offload(headers);
  eth = pif_plugin_hdr_get_ethernet(headers);
  ipv4 = pif_plugin_hdr_get_ipv4(headers);
  tcp = pif_plugin_hdr_get_tcp(headers);
  
  ingress_port = 
    pif_plugin_meta_get__standard_metadata__ingress_port(headers);

  /* install frontend -> backend translation */
  ent.match.state = FL_SPLICED;
  ent.match.side = FRONT_TO_BACK;

  /* match info */
  ent.match.srcAddr = offload->frontend_srcip;
  ent.match.dstAddr = offload->frontend_dstip;
  ent.match.sdPorts = offload->frontend_sdPorts;

  /* translation info */
  ent.action._egress_port =
    (ingress_port < BASE_VF1_PORT_ID)? BASE_PHY0_PORT_ID : BASE_PHY1_PORT_ID;
  ent.action._dstMac_0 = PIF_HEADER_GET_ethernet___dstAddr___0(eth);
  ent.action._dstMac_1 = PIF_HEADER_GET_ethernet___dstAddr___1(eth);
  ent.action._srcAddr = ipv4->srcAddr;
  ent.action._dstAddr = ipv4->dstAddr;
  ent.action._sdPorts = tcp->sdPorts;
  ent.action._seqOff = offload->seq_offset;
  ent.action._ackOff = offload->ack_offset;
 
#if UPDATE_CHECKSUM 
  /* precalculate checksum offset */
  ipcsumOff = ones_sum_add(~(offload->frontend_srcip), ipv4->dstAddr);
  ipcsumOff = ones_sum_add(ipcsumOff, ~(offload->frontend_dstip));
  ipcsumOff = ones_sum_add(ipcsumOff, ipv4->srcAddr);
  
  ent.match._ipcsumOff = ipcsumOff;
  tcpcsumOff = ones_sum_add(ipcsumOff, ~(offload->frontend_sdPorts));
  tcpcsumOff = ones_sum_add(tcpcsumOff, tcp->sdPorts);
  tcpcsumOff = ones_sum_add(tcpcsumOff, offload->seq_offset);
  tcpcsumOff = ones_sum_add(tcpcsumOff, offload->ack_offset);
  ent.match._tcpcsumOff = tcpcsumOff;
#endif
  
  /* install */
  target_bucket = get_bucket_by_hash(offload->frontend_srcip, ipv4->srcAddr,
				     offload->frontend_sdPorts);

  acquire_bucket(target_bucket);
  if ((index = insert_entry_to_bucket(target_bucket, &ent, &debug_entry1)) < 0) {
    /* this should not happen : not enough entry in the bucket */
    local_csr_write(local_csr_mailbox_2, 0xFFFF0004);
  }
  release_bucket(target_bucket);	
  
  /* install backend -> frontend translation */
  ent.match.state = FL_SPLICED;
  ent.match.side = BACK_TO_FRONT;

  /* match info */
  ent.match.srcAddr = ipv4->dstAddr;
  ent.match.dstAddr = ipv4->srcAddr;
  ent.match.sdPorts = SWAP(tcp->sdPorts);

  /* translation info */
  /* if nif = 0, forward to BASE_PHY0_PORT_ID (0x0000)
     if nif = 1, forward to BASE_PHY1_PORT_ID (0x0004) */
  ent.action._egress_port = offload->frontend_nif * 4;
  
  ent.action._dstMac_0 = PIF_HEADER_GET_offload___frontend_srcmac___0(offload);
  ent.action._dstMac_1 = PIF_HEADER_GET_offload___frontend_srcmac___1(offload);
  ent.action._srcAddr = offload->frontend_dstip;
  ent.action._dstAddr = offload->frontend_srcip;
  ent.action._sdPorts = SWAP(offload->frontend_sdPorts);
  ent.action._seqOff = -offload->ack_offset;
  ent.action._ackOff = -offload->seq_offset;
  
#if UPDATE_CHECKSUM
  /* precalculate checksum offset */
  ent.match._ipcsumOff = ~ipcsumOff; /* derive from the previous one */
  tcpcsumOff = ones_sum_add(~ipcsumOff,  ~(SWAP(tcp->sdPorts)));
  tcpcsumOff = ones_sum_add(tcpcsumOff, SWAP(offload->frontend_sdPorts));
  
  tcpcsumOff = ones_sum_add(tcpcsumOff, -offload->ack_offset);
  tcpcsumOff = ones_sum_add(tcpcsumOff, -offload->seq_offset);
  ent.match._tcpcsumOff = tcpcsumOff;
#endif
  /*
    (TODO: see if we can derive tcp checksum offset from the previous one)
    ent._tcpcsumOff = ~tcpcsumOff + 2;
  */
  

  /* install */
  target_bucket = get_bucket_by_hash(ipv4->dstAddr,
				     ipv4->srcAddr, SWAP(tcp->sdPorts));
  acquire_bucket(target_bucket);
  if ((index = insert_entry_to_bucket(target_bucket, &ent, &debug_entry1)) < 0) {
    /* this should not happen : not enough entry in the bucket */
    local_csr_write(local_csr_mailbox_2, 0xFFFF0005);
  }
  release_bucket(target_bucket);
  
  return PIF_PLUGIN_RETURN_FORWARD;
}
/*------------------------------------------------------------------------*/
int
pif_plugin_fwd_from_host_vf(EXTRACTED_HEADERS_T *headers,
			    MATCH_DATA_T *match_data)
{
  PIF_PLUGIN_ethernet_T *eth;
  PIF_PLUGIN_ipv4_T *ipv4;
  PIF_PLUGIN_tcp_T *tcp;

  unsigned egress_port;
  unsigned ingress_port;
  int i, j;


  eth = pif_plugin_hdr_get_ethernet(headers);

  if(eth->etherType == ETHERTYPE_OFFLOAD_INIT_CTRL) {
    /* if the initialization packet is come from the host, */
    /* set the rss bitmask and clear all entries in buckets */
    set_rss_bitmask(headers);

    local_csr_write(local_csr_mailbox_2, sizeof(state_entry));
    for (i = 0; i < (TABLE_SIZE + 1); i++){
      state_hashtable[i].id = i;
      for (j = 0; j < BUCKET_SIZE; j++)
        clear_entry(&(state_hashtable[i].entry_list[j]));
    }

    return PIF_PLUGIN_RETURN_DROP;
  }  

  /* calculate the port to forward packet out from ingress vf */
  ingress_port =
       pif_plugin_meta_get__standard_metadata__ingress_port(headers);
  egress_port = (ingress_port < BASE_VF1_PORT_ID) ?
                    BASE_PHY0_PORT_ID : BASE_PHY1_PORT_ID;
  pif_plugin_meta_set__standard_metadata__egress_spec(headers, egress_port);

  
  return PIF_PLUGIN_RETURN_FORWARD;
}
/*------------------------------------------------------------------------*/
