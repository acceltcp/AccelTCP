#ifndef STATE_TABLE_H
#define STATE_TABLE_H
/*------------------------------------------------------------------------*/
#include <common.h>
/*------------------------------------------------------------------------*/
#define FLOWS_PER_GROUP    64 /* RTO bits are grouped 4 (uint64_t) */
#define BITSHIFT_GROUP     6  /* RTO bits are grouped by 2 ^ 6 = 64 (uint64_t) */
#define MAX_FLOW_GROUP     (MAX_FLOWS >> BITSHIFT_GROUP)
#define FLOW_GROUP_PER_ME  51 /* FIXME: hard-coded (# MES is not power of 2) */
/*------------------------------------------------------------------------*/
/* calculate the flow id with addr and port */
#define FLOWID(addr, port)  (((addr) & (NUM_HOSTS - 1)) << 16) | (port)
/* convert the flow id to a RTO bit */
#define FLOWID_TO_BITS(fid) ((uint64_t) 1 << (fid & (FLOWS_PER_GROUP - 1)))
/* retrieve the length of the offloaded packet of the flow id */
#define FLOWID_TO_PKTCNT(fid)   ((g_flow_table[fid].pktCnt_pktAcked_rtoGroup & 0xF00) >> 8)
/* retrieve the length of the offloaded packet of the flow id */
#define FLOWID_TO_PKTACKED(fid) ((g_flow_table[fid].pktCnt_pktAcked_rtoGroup & 0xF0) >> 4)
/* retrieve which RTO group the flow id belongs to */
#define FLOWID_TO_RTOGROUP(fid) ((g_flow_table[fid].pktCnt_pktAcked_rtoGroup) \
								 & BITMASK_RTO_GROUPS)
#define FLOWID_TO_TWCYCLE(fid)  (g_flow_table[fid].pktCnt_pktAcked_rtoGroup >> 28)
/*------------------------------------------------------------------------*/
typedef struct flow_entry {
	/* TODO: hold 5-tuple of each flow here in hash table version */
	/* flow states */
	/* from LSB: (11:8) = pktCnt, (7:4) = pktAcked, (3:0) = rtoGroup */
	uint32_t pktCnt_pktAcked_rtoGroup;
	/* expected sequence number of incoming FIN packet */
	uint32_t expectedSeqNo;
	/* expected acknowledge number of incoming ACK packet */
	uint32_t expectedAckNo;
} flow_entry;
/*------------------------------------------------------------------------*/
typedef struct pktbuf {
    uint32_t buf[MAX_PKTNUM][PKTBUF_SIZE];
} pktbuf;
/*------------------------------------------------------------------------*/
__declspec(imem export scope(global)) flow_entry g_flow_table[MAX_FLOWS];
__declspec(imem export scope(global)) uint64_t g_retx_map[NUM_RTO_GROUPS] \
                                                         [MAX_FLOW_GROUP];
__declspec(emem export scope(global)) pktbuf state_pktbuf[MAX_FLOWS];
/*------------------------------------------------------------------------*/
void
table_init() {
	__xwrite uint32_t empty = 0;
	__xwrite uint64_t empty_64 = 0;
	int i, j;

	for (i = 0; i < MAX_FLOWS; i++) {
		mem_write32(&empty, &(g_flow_table[i].pktCnt_pktAcked_rtoGroup), sizeof(uint32_t)); 
	}

	for (i = 0; i < NUM_RTO_GROUPS; i++) {
		for (j = 0; j < MAX_FLOW_GROUP; j++) {
			mem_write32(&empty_64, &(g_retx_map[i][j]), sizeof(uint64_t));
		}
	}
}
/*------------------------------------------------------------------------*/
void
table_insert(__xwrite flow_entry* insert_entry, uint32_t addr,
			 uint16_t port, uint8_t rtoGroup) {

   uint32_t fid = FLOWID(addr, port); 
      
#if ENABLE_TEARDOWN_RTO
   uint32_t idx = fid >> BITSHIFT_GROUP;
   __xwrite uint64_t xwr = FLOWID_TO_BITS(fid);
   mem_bitset(&xwr, &g_retx_map[rtoGroup][idx], sizeof(uint64_t));
#endif

   mem_write32(insert_entry, &(g_flow_table[fid]), sizeof(flow_entry));
}
/*------------------------------------------------------------------------*/
int
table_lookup(uint32_t addr, uint16_t port) {
	
	return (g_flow_table[FLOWID(addr, port)].pktCnt_pktAcked_rtoGroup != 0);	
}
/*------------------------------------------------------------------------*/
int
table_lookup_and_fetch(uint32_t addr, uint16_t port,
					   __xread flow_entry* read_entry) {
	
	mem_read32(read_entry, &(g_flow_table[FLOWID(addr, port)]),
			   sizeof(flow_entry));

	return (read_entry->pktCnt_pktAcked_rtoGroup != 0);
}
/*------------------------------------------------------------------------*/
#if ENABLE_TEARDOWN_TIMEWAIT
void
table_timewait(uint32_t addr, uint16_t port) {
	
	uint32_t fid = FLOWID(addr, port);
	uint32_t flow_state = g_flow_table[fid].pktCnt_pktAcked_rtoGroup;
	g_flow_table[fid].pktCnt_pktAcked_rtoGroup = (INIT_TWCYCLE | flow_state);
}

void
table_timewait_decr(uint32_t fid) {
	uint32_t flow_state = g_flow_table[fid].pktCnt_pktAcked_rtoGroup;
	g_flow_table[fid].pktCnt_pktAcked_rtoGroup = (flow_state - TWCYCLE_1);
}

#endif
/*------------------------------------------------------------------------*/
void
table_remove_fid(uint32_t fid) {
	__xwrite uint32_t empty = 0;	
#if ENABLE_TEARDOWN_RTO
	uint8_t rtoGroup = FLOWID_TO_RTOGROUP(fid);
	uint32_t idx = fid >> BITSHIFT_GROUP;
	__xwrite uint64_t xwr = FLOWID_TO_BITS(fid);
	mem_bitclr(&xwr, &g_retx_map[rtoGroup][idx], sizeof(uint64_t));  
#endif
	
	mem_write32(&empty, &(g_flow_table[fid].pktCnt_pktAcked_rtoGroup),
				sizeof(uint32_t));
}
/*------------------------------------------------------------------------*/
#endif
