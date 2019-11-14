#ifndef __NIC_CONTROL_H_
#define __NIC_CONTROL_H_

int 
ProcessSpliceFinishPacket(mtcp_manager_t mtcp, uint32_t cur_ts,
		const int ifidx, unsigned char* pkt_data, int len);

#endif /* __NIC_CONTROL_H_ */
