#ifndef NBI_OUT_H
#define NBI_OUT_H

#include <pif_plugin_metadata.h>
#include <vnic/pci_out.h>
#include <blm.h>
#include <nfp/cls.h>
#include <std/reg_utils.h>
/*------------------------------------------------------------------------*/
/* Default Header Value */
#define DEFAULT_MTU 1514
#define DEFAULT_HDR 66   /* XXX: to be updated depending on TCP header options */
#define DEFAULT_MSS (DEFAULT_MTU - DEFAULT_HDR)
#define ETHER_HDR   14

/*
 * Defines
 */

#define MAC_CHAN_PER_PORT   8
#define TMQ_PER_PORT        (MAC_CHAN_PER_PORT * 8)
#define MAC_TO_PORT(x)      (x / MAC_CHAN_PER_PORT)
#define PORT_TO_TMQ(x)      (x * TMQ_PER_PORT)

/* CTM credit defines */
#define CTM_ALLOC_ERR 0xffffffff

/* 4B mac egress prepend for L3/4 checksums are not used for now */
#define MAC_EGRESS_PREPEND_SIZE 0

/*
 * Globals
 */

/* credits for CTM */
__import __shared __cls struct ctm_pkt_credits ctm_credits;

#define PIF_8_BIT_XFR_LW     8
#define PIF_8_BIT_XFR_BYTES  ((PIF_8_BIT_XFR_LW) * 4)

#define PIF_32_BIT_XFR_LW     16
#define PIF_32_BIT_XFR_BYTES  ((PIF_32_BIT_XFR_LW) * 4)

/*--------------------------------------------------------------------------------------*/
/* Packet metadata operations */
/*--------------------------------------------------------------------------------------*/
static void build_tx_meta(__lmem struct nbi_meta_catamaran *nbi_meta,
						  uint8_t ctm_buf_size)
{
	int pkt_num;
	__xread blm_buf_handle_t buf;
	int blq = pif_pkt_info_global.bls;

	reg_zero(nbi_meta->__raw, sizeof(struct nbi_meta_catamaran));

	/*
     * Poll for a CTM buffer until one is returned
     */
	while (1) {
		pkt_num = pkt_ctm_alloc(&ctm_credits, __ISLAND, ctm_buf_size, 1, 1);
		if (pkt_num != CTM_ALLOC_ERR)
			break;
		sleep(BACKOFF_SLEEP);
	}

	// XXX: for debugging (dump with /opt/netronome/bin/nfp-rtsym _wire_debug)
	//DEBUG(0xf00d, (__MEID << 16) | ctx(), blq, 0);
	/*
     * Poll for MU buffer until one is returned.
     */
	while (blm_buf_alloc(&buf, blq) != 0) {
		sleep(BACKOFF_SLEEP);
	}
	//DEBUG(0xcafe, (__MEID << 16) | ctx(), blq, 0);

	nbi_meta->pkt_info.isl = __ISLAND;
	nbi_meta->pkt_info.pnum = pkt_num;
	nbi_meta->pkt_info.bls = blq;
	nbi_meta->pkt_info.muptr = buf;
}

/*--------------------------------------------------------------------------------------*/
/* Registering Packet Information for Host-side TX */
/*--------------------------------------------------------------------------------------*/
__intrinsic static void
pif_pkt_info_to_nfdtxd(__gpr struct nfd_out_input *nfd_txd, 
			__lmem struct nbi_meta_catamaran *nbi_meta,
			__gpr uint32_t pkt_offset,
			uint32_t out_port,
			int len)
{
	uint16_t flags = 0;

	/* Ensure pkt_tx_desc is zero before populating it. */
	reg_zero(nfd_txd, sizeof(struct nfd_out_input));

	/* Address details */
	nfd_txd->cpp.isl = (nbi_meta->pkt_info.isl & 0x3f);
	nfd_txd->cpp.pktnum = nbi_meta->pkt_info.pnum;
	nfd_txd->cpp.mu_addr = nbi_meta->pkt_info.muptr;
	nfd_txd->cpp.split = PKT_CTM_SIZE_256;
	nfd_txd->cpp.bls = nbi_meta->pkt_info.bls;

	/* Length and offset details. */
	nfd_txd->rxd.data_len = len;
	nfd_txd->cpp.offset = pkt_offset;

	nfd_out_check_ctm_only(nfd_txd);

	nfd_txd->rxd.queue = out_port;

	nfd_out_dummy_vlan(nfd_txd, 0, flags);
}


/*--------------------------------------------------------------------------------------*/
/* Send Packet to Host Anyway */
/*--------------------------------------------------------------------------------------*/
static void
send_packet_host_anyway(__addr32 void* mbuf, uint32_t out_port, int len)
{
	/* Please refer /opt/netronome/p4/components/nfp_pif/me/apps/common/src/pkt_ops.c */
	__lmem struct nbi_meta_catamaran mdata;

	__gpr struct nfd_out_input nfd_txd;
	__gpr uint32_t nfd_q;
	__xwrite uint32_t xwr[32];
	__mem char *pbuf;
	__gpr uint32_t credit;

	int pkt_offset = PKT_NBI_OFFSET + MAC_EGRESS_PREPEND_SIZE;
	uint32_t nbi = 0;

	build_tx_meta(&mdata, PKT_CTM_SIZE_256);

	reg_cp((void*)xwr, (void*)&mdata, sizeof(struct nbi_meta_catamaran));
	pbuf = pkt_ctm_ptr40(mdata.pkt_info.isl, mdata.pkt_info.pnum, 0);
	mem_write32(xwr, pbuf, sizeof(struct nbi_meta_catamaran));

	reg_cp((void*)xwr, mbuf, len);
	mem_write32(xwr, pbuf + pkt_offset, len);

	nfd_q = out_port;
	while(!credit) {
		credit = nfd_out_get_credit(PCIE_ISL, nfd_q, 1);
		sleep(BACKOFF_SLEEP);
	}

	pif_pkt_info_to_nfdtxd(&nfd_txd, &mdata, PKT_NBI_OFFSET, out_port, len);
	nfd_out_send(PCIE_ISL,
		     nfd_q,
		     &nfd_txd);
}

/*--------------------------------------------------------------------------------------*/
/* Send Packet to Wire */
/*--------------------------------------------------------------------------------------*/

static void
send_packet_wire(__addr32 void* mbuf, uint32_t out_port, int len)
{
	/* packet metadata, always goes at start of ctm buffer */
	__lmem struct nbi_meta_catamaran mdata;
	/* this is the inline packet modifier data, ensures 8B alignment */
	__gpr struct pkt_ms_info msi;
	/* transfer registers for copying out packet data to ctm */
	__xwrite uint32_t xwr[32];
	/* point to packet data in CTM */
	__mem char *pbuf;
	/* we take care to start the packet on 8B alignment + 4B
     * as the egress prepend is 4B this amounts to an offset
     * of 8B which means the packet modification script is a nop
     */
	int pkt_offset = PKT_NBI_OFFSET + MAC_EGRESS_PREPEND_SIZE;
	uint32_t nbi = 0;

	/* Allocate packet and write out packet metadata to packet buffer */
	build_tx_meta(&mdata, PKT_CTM_SIZE_256);

	reg_cp((void*)xwr, (void*)&mdata, sizeof(struct nbi_meta_catamaran));
	pbuf = pkt_ctm_ptr40(mdata.pkt_info.isl, mdata.pkt_info.pnum, 0);
	mem_write32(xwr, pbuf, sizeof(struct nbi_meta_catamaran));
		
	/* copy and write out the packet data into the packet buffer */
	reg_cp((void*)xwr, mbuf, len);
	mem_write32(xwr, pbuf + pkt_offset, len);

	/* set up the packet modifier to trim bytes for alignment */
	msi = pkt_msd_write(pbuf, PKT_NBI_OFFSET);

	/* send the packet */
	pkt_nbi_send(mdata.pkt_info.isl, mdata.pkt_info.pnum, &msi,
				 len + MAC_EGRESS_PREPEND_SIZE,
				 nbi, PORT_TO_TMQ(out_port),
				 mdata.seqr, mdata.seq, PKT_CTM_SIZE_256);
}
#endif /* NBI_OUT_H */
