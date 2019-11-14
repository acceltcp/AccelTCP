/* Agilio NFP NIC-specific variables */
#ifndef NFP_DEVICE_H
#define NFP_DEVICE_H
/*-------------------------------------------------------------------------*/
#define MASTER_MEID       0x0204
#define MASTER_CTX        0
/*-------------------------------------------------------------------------*/
#define BASE_ISLAND_ID    32
#define BASE_MEID_OFFSET  4
#define MAX_ME_PER_ISLAND 12
#define MAX_ISLANDS       7
/*-------------------------------------------------------------------------*/
/* calculate continuous meid starting from zero */
void
nfp_dev_set_cont_meid() {

	/* ygmoon: convert device specific IDs to continuous meid
	 * (i32.me0: 0, i32.me1: 1, .., i33.me11: MAX_ME_PER_ISLAND = 12, ..) */
	uint32_t cont_meid = (__ISLAND - BASE_ISLAND_ID) * MAX_ME_PER_ISLAND
		                 + ((__MEID & 0xF) - BASE_MEID_OFFSET);
	
	/* ygmoon: adjust cont_meid to be continuous
	 * (note that i33.me10, i33.me11, i36.me11 are not used in nfp6000) */
	if (cont_meid > 0x15)
		cont_meid -= 2;
	if (cont_meid > 0x38)
		cont_meid -= 1;
	
	/* store continuous meid at local_csr_mailbox_2 */
	local_csr_write(local_csr_mailbox_2, cont_meid);
}
/*-------------------------------------------------------------------------*/
uint32_t
nfp_dev_get_cont_meid() {

	/* load continuous meid from local_csr_mailbox_2 */
	return local_csr_read(local_csr_mailbox_2);	
}
/*-------------------------------------------------------------------------*/
#endif
