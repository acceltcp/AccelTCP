#ifndef NFP_UTIL_H
#define NFP_UTIL_H
/*------------------------------------------------------------------------*/
#include <std/hash.h>
/*------------------------------------------------------------------------*/
#define TS_1MS      0x124F8 
#define TS_5MS      0x5B8D8
#define TS_10MS     0xB71B0
#define TS_100MS    0x7270E0
#define TS_500MS    0x23C30F0
#define TS_1S       0x47868C0
#define TS_5S       0x165A0BC0
/*------------------------------------------------------------------------*/
uint64_t
nfp_timer_get_cur_ts()
{
  return (((uint64_t) local_csr_read(local_csr_timestamp_high) << 32)
          | local_csr_read(local_csr_timestamp_low));	
}
/*------------------------------------------------------------------------*/
uint32_t
nfp_perform_crc32(uint32_t a, uint32_t b, uint32_t c)
{
  uint32_t hash_key[3] = {a, b, c};
  return hash_me_crc32((void *)hash_key, sizeof(hash_key), 1);	
}
/*------------------------------------------------------------------------*/
/* note: should be used only in pif_plugin__from_host() */
int
nfp_get_payloadlen() {
  return (pif_pkt_info_global.pkt_len - pif_pkt_info_global.pkt_pl_off);
}
/*------------------------------------------------------------------------*/
int
nbi_get_payloadlen(PIF_PLUGIN_ipv4_T *ipv4) {
  return (ipv4->totalLen - TCPIP_HDRLEN);
}
/*------------------------------------------------------------------------*/
/* for debugging */
#define MILLION (1024*1024)
__export __emem uint32_t wire_debug[MILLION];
__export __emem uint32_t wire_debug_idx;
#define DEBUG(_a, _b, _c, _d) do { \
    __xrw uint32_t _idx_val = 4;                                    \
    __xwrite uint32_t _dvals[4] = {_a, _b, _c, _d};                 \
    mem_test_add(&_idx_val, &wire_debug_idx, sizeof(_idx_val));     \
    mem_write_atomic(_dvals,                                        \
                     wire_debug + (_idx_val & (MILLION-1)),       \
                     sizeof(_dvals));                               \
  } while(0)
/*------------------------------------------------------------------------*/
#endif
