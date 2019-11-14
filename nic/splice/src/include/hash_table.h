#include <nfp/mem_atomic.h>
#include <pif_plugin.h>
#include <pif_plugin_metadata.h>
#include <pkt_ops.h>
#include <pif_headers.h>
#include <nfp_override.h>
#include <pif_common.h>
#include <std/hash.h>
#include <nfp/me.h>
/*------------------------------------------------------------------------*/
#define BUCKET_SIZE    14
#define TABLE_SIZE     0xFFF
/*------------------------------------------------------------------------*/
#define UNUSED         0x0008
#define FL_DELETED     0x0010
#define FL_SPLICED     0x0001
#define FL_FIN_SENT    0x0002
#define FL_FINACK_RCVD 0x0004
/*------------------------------------------------------------------------*/
#define FRONT_TO_BACK  0x0001
#define BACK_TO_FRONT  0x0002
/*------------------------------------------------------------------------*/
typedef struct match_entry
{
  uint32_t state;
  uint32_t side;
  uint32_t srcAddr;
  uint32_t dstAddr;
  uint32_t sdPorts;	
#if UPDATE_CHECKSUM
  /* checksum offset (TODO: see if we can fold those fields into
     16-bit fields) */
  uint32_t _ipcsumOff;
  uint32_t _tcpcsumOff;
#endif
  uint32_t seqFINsent; // storing the last FIN sent
} match_entry;

typedef struct action_entry
{
  uint32_t _egress_port;
  uint32_t _dstMac_0;
  uint32_t _dstMac_1;
  uint32_t _srcAddr;
  uint32_t _dstAddr;
  uint32_t _sdPorts;
  uint32_t _seqOff;
  uint32_t _ackOff;
} action_entry;

typedef struct state_entry
{
  match_entry match;
  action_entry action;
} state_entry;
/*------------------------------------------------------------------------*/
typedef struct bucket {
    uint32_t in_use;
    uint32_t id;
    state_entry entry_list[BUCKET_SIZE];
} bucket;
#ifndef NULL
#define NULL (void *) 0
#endif
/*------------------------------------------------------------------------*/
__export volatile __addr40 __imem bucket state_hashtable[TABLE_SIZE+1];
/*------------------------------------------------------------------------*/
__forceinline void
acquire_bucket(volatile __imem bucket* target_bucket)
{
  __xrw uint32_t xfer = 1;
  
  do {
    mem_test_set(&xfer, (uint32_t*)&(target_bucket->in_use), sizeof(xfer));
  } while (xfer == 1);
  
  return;
}
/*------------------------------------------------------------------------*/
__forceinline void
release_bucket(volatile __imem bucket* target_bucket)
{
  __xrw uint32_t xfer = 0;
  mem_write_atomic(&xfer, (uint32_t*)&(target_bucket->in_use), sizeof(xfer));
  return;
}
/*------------------------------------------------------------------------*/
volatile __imem bucket*
get_bucket_by_hash(uint32_t srcAddr, uint32_t dstAddr, uint32_t sdPorts)
{
  uint32_t hash_key[3];
  uint32_t hash_value;
  
  hash_key[0] = srcAddr;
  hash_key[1] = dstAddr;
  hash_key[2] = sdPorts;
  
  hash_value = hash_me_crc32((void *)hash_key, sizeof(hash_key), 1);
  hash_value &= TABLE_SIZE;
  return &(state_hashtable[hash_value]);
}
/*------------------------------------------------------------------------*/
__forceinline int
insert_entry_to_bucket(volatile __imem bucket* target_bucket,
		       __xrw state_entry* temp_entry,
                       __xread state_entry* debug_entry)
{
  int i;
  __xread uint32_t state;
  
  for (i = 0; i < BUCKET_SIZE; i++) {
    mem_read_atomic(&state,
                    (uint32_t*)&(target_bucket->entry_list[i].match.state),
                    sizeof(state));
    if (!(state & FL_SPLICED)) {
      mem_write_atomic(&(temp_entry->match),
                       (uint32_t*)&(target_bucket->entry_list[i].match),
                       sizeof(match_entry));
      mem_write_atomic(&(temp_entry->action),
                       (uint32_t*)&(target_bucket->entry_list[i].action),
                       sizeof(action_entry));

      return i;            
    }
  }
  
  return -1;
}
/*------------------------------------------------------------------------*/
__forceinline int
search_current_in_bucket(uint32_t srcAddr,
			 uint32_t dstAddr,				 
			 uint32_t sdPorts,	
			 volatile __imem bucket* target_bucket,
			 __xrw state_entry *local_entry,
			 int* index)
{
  uint32_t i;
  
  for (i = 0; i < BUCKET_SIZE; i++) {
    mem_read_atomic(&(local_entry->match),
                    (uint32_t*)&(target_bucket->entry_list[i].match),
                    sizeof(match_entry));
    if (local_entry->match.state & FL_SPLICED) {
      if (srcAddr == local_entry->match.srcAddr &&
	  dstAddr == local_entry->match.dstAddr &&
	  sdPorts == local_entry->match.sdPorts) {

        mem_read_atomic(&(local_entry->action),
                        (uint32_t*)&(target_bucket->entry_list[i].action),
                        sizeof(action_entry));
	(*index) = i;
	return local_entry->match.state;
      }
    }
  }
  (*index) = -1;

  return -1;
}
/*------------------------------------------------------------------------*/
__forceinline void
clear_entry(volatile __imem state_entry* target_entry)
{
    __xwrite uint32_t temp;
    temp = UNUSED;

    mem_write_atomic(&temp,
                     (uint32_t*)&(target_entry->match.state),
                     sizeof(temp));
    mem_write_atomic(&temp,
                     (uint32_t*)&(target_entry->match.side),
                     sizeof(temp));
}
/*------------------------------------------------------------------------*/

