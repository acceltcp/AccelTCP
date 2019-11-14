/*-------------------------------------------------------------------------*/
/* Packet I/O-related functions for NBI of Agilio NFP NICs */
#ifndef NBI_OUT_H
#define NBI_OUT_H
/*-------------------------------------------------------------------------*/
#define MAC_CHAN_PER_PORT     8
#define TMQ_PER_PORT          (MAC_CHAN_PER_PORT * 8)
#define MAC_TO_PORT(x)        (x / MAC_CHAN_PER_PORT)
#define PORT_TO_TMQ(x)        (x * TMQ_PER_PORT)
#define CTM_ALLOC_ERR         0xffffffff
#define PIF_32_BIT_XFR_LW     32
#define PIF_32_BIT_XFR_BYTES  ((PIF_32_BIT_XFR_LW) * 4)
/*-------------------------------------------------------------------------*/
#define CTM_OFFSET        256 // (256 << PKT_CTM_SIZE_256)
/* maximum bytes of a packet that a CTM buffer can hold */
#define CTM_HEADROOM      128 // (CTM_OFFSET - PKT_NBI_OFFSET)
/*-------------------------------------------------------------------------*/
#define BLM_OFFSET(p) ((uint64_t) blm_buf_handle2ptr(p) + CTM_OFFSET)
/*-------------------------------------------------------------------------*/
__import __shared __cls struct ctm_pkt_credits ctm_credits;
/*-------------------------------------------------------------------------*/
struct tso_meta {
	int seg_offset; /* for TSO */
	int ip_len;     /* for TSO */
	int seg_left;   /* for TSO */
};	   
/*-------------------------------------------------------------------------*/
/*
 * Packet metadata operations
 */
void
build_tx_meta(__lmem struct nbi_meta_catamaran *nbi_meta,
			  uint8_t ctm_buf_size)
{
	int pkt_num;
	__xread blm_buf_handle_t buf;
	int blq = pif_pkt_info_global.bls;

	reg_zero(nbi_meta->__raw, sizeof(struct nbi_meta_catamaran));

	/* Poll for a CTM buffer until one is returned */
	while (1) {
		pkt_num = pkt_ctm_alloc(&ctm_credits, __ISLAND, ctm_buf_size, 1, 1);
		if (pkt_num != CTM_ALLOC_ERR)
			break;
		sleep(BACKOFF_SLEEP);
	}

	/* Poll for MU buffer until one is returned */
	while (blm_buf_alloc(&buf, blq) != 0) {
		sleep(BACKOFF_SLEEP);
	}
	
	nbi_meta->pkt_info.isl = __ISLAND;
	nbi_meta->pkt_info.pnum = pkt_num;
	nbi_meta->pkt_info.bls = blq;
	nbi_meta->pkt_info.muptr = buf;
}
/*-------------------------------------------------------------------------*/
void
copy_mu_buffer(__mem __addr40 uint32_t *src_mu_ptr,
			   __mem __addr40 uint32_t *dst_mu_ptr,
			   uint32_t byte_length,
			   int *lookup_pktlen)
{
    /* Copy 32-bit words whole words for bulk of packet */
	__xread uint32_t   rd_buffer[PIF_32_BIT_XFR_LW];
	__xwrite uint32_t  wr_buffer[PIF_32_BIT_XFR_LW];
	__gpr uint32_t     to_copy_words = ((byte_length + 7) >> 3);
    __gpr uint32_t     chunk = PIF_32_BIT_XFR_LW;
    __gpr uint32_t     offset = 0;
	SIGNAL             sig;

	while (to_copy_words) {
		if (to_copy_words < PIF_32_BIT_XFR_LW)
			chunk = to_copy_words;
		
		__mem_read64(rd_buffer, ((uint64_t)src_mu_ptr + offset), chunk << 3,
					 PIF_32_BIT_XFR_BYTES, ctx_swap, &sig);
			
		reg_cp(wr_buffer, rd_buffer, sizeof(rd_buffer) >> 1);
		reg_cp(&wr_buffer[PIF_32_BIT_XFR_LW >> 1],
			   &rd_buffer[PIF_32_BIT_XFR_LW >> 1], sizeof(rd_buffer) >> 1);

		if (lookup_pktlen && offset == 0) {
			/* update ethertype (only in teardown offload) */
			wr_buffer[3] = (0x08000000) | (rd_buffer[3] & 0xffff);
			/* derive the total packet length from ipv4 header if required */
			(*lookup_pktlen) = ((rd_buffer[4] >> 16) + ETH_HDRLEN);
		}
			
		__mem_write64(wr_buffer, ((uint64_t)dst_mu_ptr + offset), chunk << 3,
					  PIF_32_BIT_XFR_BYTES, ctx_swap, &sig);
		
		to_copy_words -= chunk;
		offset += (chunk << 3);
	}
}
/*-------------------------------------------------------------------------*/
void
copy_mu_buffer_tso_mod(__mem __addr40 uint32_t *src_mu_ptr,
					   __mem __addr40 uint32_t *dst_mu_ptr,
					   __mem __addr40 uint32_t *dmp_mu_ptr,
					   uint32_t byte_length,
					   struct tso_meta *meta)
{
    /* Copy 32-bit words whole words for bulk of packet */
	__xread uint32_t    rd_buffer[PIF_32_BIT_XFR_LW];
	__xwrite uint32_t   wr_buffer[PIF_32_BIT_XFR_LW];
	__gpr uint32_t      to_copy_words = ((byte_length + 7) >> 3);
    __gpr uint32_t      chunk = PIF_32_BIT_XFR_LW;
    __gpr uint32_t      offset = 0;
    SIGNAL              sig;	

	while (to_copy_words) {
		if (to_copy_words < PIF_32_BIT_XFR_LW)
			chunk = to_copy_words;

		__mem_read64(rd_buffer, ((uint64_t)src_mu_ptr + offset), chunk << 3,
					 PIF_32_BIT_XFR_BYTES, ctx_swap, &sig);
			
		reg_cp(wr_buffer, rd_buffer, sizeof(rd_buffer) >> 1);
		reg_cp(&wr_buffer[PIF_32_BIT_XFR_LW >> 1],
			   &rd_buffer[PIF_32_BIT_XFR_LW >> 1], sizeof(rd_buffer) >> 1);

		/* update TCP/IP header for TCP segmentation */
		if (meta) {
			// update ethertype (only in teardown offload)
			wr_buffer[3] = (0x08000000) | (rd_buffer[3] & 0xffff);
			// update ip length
			wr_buffer[4] = (meta->ip_len << 16) | (rd_buffer[4] & 0xffff);
			// update tcp seqeuence number (if offset > 0)
			if (meta->seg_offset > 0) {
				__gpr uint32_t seq;					
				seq = ((rd_buffer[9] & 0xffff) << 16) | (rd_buffer[10] >> 16);
				seq += meta->seg_offset;
				wr_buffer[9]  = (rd_buffer[9] & 0xffff0000) | (seq >> 16);
				wr_buffer[10] = ((seq & 0xffff) << 16) | (rd_buffer[10] & 0xffff);
			}
			// unset tcp fin flag if this is not the last segment
			if (meta->seg_left)
				wr_buffer[11] = rd_buffer[11] & 0xFFFFFFFE;
		}

		__mem_write64(wr_buffer, ((uint64_t)dst_mu_ptr + offset), chunk << 3,
					  PIF_32_BIT_XFR_BYTES, ctx_swap, &sig);
		if (dmp_mu_ptr)
			__mem_write64(wr_buffer, ((uint64_t)dmp_mu_ptr + offset), chunk << 3,
						  PIF_32_BIT_XFR_BYTES, ctx_swap, &sig);		
		
		to_copy_words -= chunk;
		offset += (chunk << 3);
	}
}
/*--------------------------------------------------------------------------*/
void
nbi_send_pkt(volatile __emem __addr40 pktbuf* src, int pkt_idx)
{
	__lmem struct nbi_meta_catamaran mdata;
	__gpr struct pkt_ms_info msi;
	__xwrite uint32_t xwr[32];
	__declspec(aligned(4)) __mem char *pbuf;
	int pkt_len, left_len;
	
	/* Allocate packet and write out packet metadata to packet buffer */
	build_tx_meta(&mdata, PKT_CTM_SIZE_256);	
	reg_cp((void *)xwr, (void *)&mdata, sizeof(struct nbi_meta_catamaran));
	pbuf = pkt_ctm_ptr40(mdata.pkt_info.isl, mdata.pkt_info.pnum, 0);
	mem_write32(xwr, pbuf, sizeof(struct nbi_meta_catamaran));

	/* Packet length is bigger than CTM buffer size, copy full CTM
	 * buffer size - pkt_off and then copy rest of packet into MU
	 * buffer. Start of data in MU buffer is size of CTM buffer */
	copy_mu_buffer(src->buf[pkt_idx],
				   pbuf + PKT_NBI_OFFSET,
				   CTM_HEADROOM,
				   &pkt_len);
	
	if ((left_len = pkt_len - CTM_HEADROOM) > 0)
		copy_mu_buffer(src->buf[pkt_idx] + CTM_HEADROOM,
					   BLM_OFFSET(pif_pkt_info_global.muptr),
					   left_len,
					   NULL);
	
	/* set up the packet modifier to trim bytes for alignment */
	msi = pkt_msd_write(pbuf, PKT_NBI_OFFSET);
	
	/* send the packet */
	pkt_nbi_send(mdata.pkt_info.isl, mdata.pkt_info.pnum, &msi, pkt_len,
				 0, 0, /* nbi, PORT_TO_TMQ(out_port), */
				 0, 0, /* mdata.seqr, mdata.seq, */
				 PKT_CTM_SIZE_256);
}
/*--------------------------------------------------------------------------*/
void
nbi_send_segment(__mem __addr40 uint32_t *src_ctm_ptr,
				 __mem __addr40 uint32_t *src_blm_ptr,
				 __mem __addr40 uint32_t *dmp_ctm_ptr,
				 __mem __addr40 uint32_t *dmp_blm_ptr,
				 int eth_len,
				 struct tso_meta *meta)
{
	__lmem struct nbi_meta_catamaran mdata;
	__gpr struct pkt_ms_info msi;
	__xwrite uint32_t xwr[32];
	__declspec(aligned(4)) __mem char *pbuf;
	int left_len;
	
	/* Allocate packet and write out packet metadata to packet buffer */
	build_tx_meta(&mdata, PKT_CTM_SIZE_256);	
	reg_cp((void *)xwr, (void *)&mdata, sizeof(struct nbi_meta_catamaran));
	pbuf = pkt_ctm_ptr40(mdata.pkt_info.isl, mdata.pkt_info.pnum, 0);
	mem_write32(xwr, pbuf, sizeof(struct nbi_meta_catamaran));

	/* Packet length is bigger than CTM buffer size, copy full CTM
	 * buffer size - pkt_off and then copy rest of packet into MU
	 * buffer. Start of data in MU buffer is size of CTM buffer */
	copy_mu_buffer_tso_mod(src_ctm_ptr,
						   pbuf + PKT_NBI_OFFSET,
						   dmp_ctm_ptr,
						   CTM_HEADROOM,
						   meta);
	
	if ((left_len = eth_len - CTM_HEADROOM) > 0)
		copy_mu_buffer_tso_mod(src_blm_ptr,
							   BLM_OFFSET(pif_pkt_info_global.muptr),
							   dmp_blm_ptr,
							   left_len,
							   NULL);				 
	
	/* set up the packet modifier to trim bytes for alignment */
	msi = pkt_msd_write(pbuf, PKT_NBI_OFFSET);

	/* send the packet */
	pkt_nbi_send(mdata.pkt_info.isl, mdata.pkt_info.pnum, &msi, eth_len,
				 0, 0, /* nbi, PORT_TO_TMQ(out_port), */
				 0, 0, /* mdata.seqr, mdata.seq, */
				 PKT_CTM_SIZE_256);	
}
/*--------------------------------------------------------------------------*/
void
nbi_dump_pkt(volatile __emem __addr40 pktbuf* dump_dst)
{
	/* if (pif_pkt_info_global.pkt_len <= DEFAULT_MTU) */
	int left = pif_pkt_info_global.pkt_len - CTM_HEADROOM;
	copy_mu_buffer(pkt_ctm_ptr40(__ISLAND, pif_pkt_info_global.pkt_num,
								 PKT_NBI_OFFSET),
				   dump_dst->buf[0],
				   (left > 0)? CTM_HEADROOM : pif_pkt_info_global.pkt_len,
				   NULL);
	if (left > 0)
		copy_mu_buffer(BLM_OFFSET(pif_pkt_info_global.muptr),
					   ((uint64_t)(dump_dst->buf[0])) + CTM_HEADROOM,
					   left,
					   NULL);
}
/*---------------------------------------------------------------------------*/
int
nbi_dump_pkt_tso(volatile __emem __addr40 pktbuf* dst)
{
	int num_segs = 0;	
	int seg_offset = 0;
	int remain_seg_len = nfp_get_payloadlen();
	struct tso_meta m;
	int seg_len, pkt_len;
		
	while (remain_seg_len > 0) {
		seg_len = MIN(remain_seg_len, DEFAULT_MSS);
		pkt_len = DEFAULT_HDR + seg_len;

		/* metadata required for TCP segmentation */
		m.seg_offset = seg_offset;
		m.ip_len = pkt_len - ETH_HDRLEN;
		m.seg_left = remain_seg_len - seg_len;
		
		nbi_send_segment(pkt_ctm_ptr40(__ISLAND, pif_pkt_info_global.pkt_num,
									   PKT_NBI_OFFSET),
						 BLM_OFFSET(pif_pkt_info_global.muptr) + seg_offset,
						 ((dst)? dst->buf[num_segs] : NULL),
						 ((dst)? ((uint64_t)(dst->buf[num_segs])
								  + CTM_HEADROOM) : NULL),
						 pkt_len,
						 &m);
		
		remain_seg_len -= seg_len;
		seg_offset += seg_len;
		num_segs++;			
	}
	
	return num_segs;
}
/*--------------------------------------------------------------------------*/
#endif
