#ifndef __MTCP_H_
#define __MTCP_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <sys/queue.h>
#include <pthread.h>

#include "memory_mgt.h"
#include "tcp_ring_buffer.h"
#include "tcp_send_buffer.h"
#include "tcp_stream_queue.h"
#include "socket.h"
#include "mtcp_api.h"
#include "eventpoll.h"
#include "addr_pool.h"
#ifndef DISABLE_PSIO
#include "ps.h"
#endif
#include "logger.h"
#include "stat.h"
#include "io_module.h"
#include "splice_pool.h"
#ifdef ENABLE_UCTX
#include "lthread.h"
#endif

#ifndef TRUE
#define TRUE (1)
#endif

#ifndef FALSE
#define FALSE (0)
#endif

#ifndef ERROR
#define ERROR (-1)
#endif

/*------------------------------------------------------------------------------------------*/
#define VERIFY_RX_CHECKSUM          TRUE    // whether to verify TCP Rx checksum
#define TCP_CALCULATE_CHECKSUM      TRUE    // whether to update TCP Tx checksum
#define TCP_OPT_TIMESTAMP_ENABLED   TRUE
/*------------------------------------------------------------------------------------------*/
/* increasing initial congestion window size to 10 MSS (rfc6928) */
#define INIT_CWND_10                FALSE
/* TCP segmentation offload */
#define ENABLE_TSO                  FALSE
#if ENABLE_TSO
#ifdef USE_NFP_NIC
/* maximum segment size for TSO is limited to 8K in Agilio NICs */
#define MAX_TSO_BUFSIZE (8 * 1024)
#else
#define MAX_TSO_BUFSIZE (64 * 1024)
#endif
#endif
/*------------------------------------------------------------------------------------------*/
#define ETHERNET_HEADER_LEN		14	// sizeof(struct ethhdr)
#define IP_HEADER_LEN			20	// sizeof(struct iphdr)
#define TCP_HEADER_LEN			20	// sizeof(struct tcphdr)
#define TOTAL_TCP_HEADER_LEN	54	// total header length

/* configrations */
#define BACKLOG_SIZE (32*1024)
#define MAX_PKT_SIZE (2*1024)
#define ETH_NUM 4

#define TCP_OPT_SACK_ENABLED        FALSE	/* not implemented */

#define LOCK_STREAM_QUEUE	FALSE
#define USE_SPIN_LOCK		TRUE
#define INTR_SLEEPING_MTCP	TRUE
#define PROMISCUOUS_MODE	TRUE

/* blocking api became obsolete */
#define BLOCKING_SUPPORT	FALSE

#ifndef MAX_CPUS
#define MAX_CPUS		128
#endif

#define MAX_PKT_BURST			64

/*----------------------------------------------------------------------------*/
/* enabled to piggyback payload-control-ack all together */
#define DATA_CTRL_PIGGYBACK			TRUE 
#ifdef ENABLE_UCTX
/* opportunistic resource allocation for TCP stream */
#define OPPORTUNISTIC_STREAM_ALLOC  TRUE
#if OPPORTUNISTIC_STREAM_ALLOC
int dpdk_get_wbuf_cnt(struct mtcp_thread_context *ctxt, int ifidx);
void dpdk_add_wbuf_len(struct mtcp_thread_context *ctxt, int ifidx,
					   int pktidx, int len);
#endif /* OPPORTUNISTIC_STREAM_ALLOC */
#endif /* ENABLE_UCTX */
/*----------------------------------------------------------------------------*/
/* Statistics */
#ifdef NETSTAT
#define NETSTAT_PERTHREAD	TRUE
#define NETSTAT_TOTAL		TRUE
#endif /* NETSTAT */
#define RTM_STAT			FALSE
/*----------------------------------------------------------------------------*/
/* Lock definitions for socket buffer */
#if USE_SPIN_LOCK
#define SBUF_LOCK_INIT(lock, errmsg, action);		\
	if (pthread_spin_init(lock, PTHREAD_PROCESS_PRIVATE)) {		\
		perror("pthread_spin_init" errmsg);			\
		action;										\
	}
#define SBUF_LOCK_DESTROY(lock)	pthread_spin_destroy(lock)
#define SBUF_LOCK(lock)			pthread_spin_lock(lock)
#define SBUF_UNLOCK(lock)		pthread_spin_unlock(lock)
#else
#define SBUF_LOCK_INIT(lock, errmsg, action);		\
	if (pthread_mutex_init(lock, NULL)) {			\
		perror("pthread_mutex_init" errmsg);		\
		action;										\
	}
#define SBUF_LOCK_DESTROY(lock)	pthread_mutex_destroy(lock)
#define SBUF_LOCK(lock)			pthread_mutex_lock(lock)
#define SBUF_UNLOCK(lock)		pthread_mutex_unlock(lock)
#endif /* USE_SPIN_LOCK */

/* add macro if it is not defined in /usr/include/sys/queue.h */
#ifndef TAILQ_FOREACH_SAFE
#define TAILQ_FOREACH_SAFE(var, head, field, tvar)                      \
	for ((var) = TAILQ_FIRST((head));                               \
	     (var) && ((tvar) = TAILQ_NEXT((var), field), 1);		\
	     (var) = (tvar))
#endif
/*----------------------------------------------------------------------------*/
struct eth_table
{
	char dev_name[128];
	int ifindex;
	int stat_print;
	unsigned char haddr[ETH_ALEN];
	uint32_t netmask;
//	unsigned char dst_haddr[ETH_ALEN];
	uint32_t ip_addr;
};
/*----------------------------------------------------------------------------*/
struct route_table
{
	uint32_t daddr;
	uint32_t mask;
	uint32_t masked;
	int prefix;
	int nif;
};
/*----------------------------------------------------------------------------*/
struct arp_entry
{
	uint32_t ip;
	int8_t prefix;
	uint32_t ip_mask;
	uint32_t ip_masked;
	unsigned char haddr[ETH_ALEN];
};
/*----------------------------------------------------------------------------*/
struct arp_table
{
	struct arp_entry *entry;
	struct arp_entry *gateway;
	int entries;
};
/*----------------------------------------------------------------------------*/
struct mtcp_config
{
	/* socket mode */
	int8_t socket_mode;

	/* network interface config */
	struct eth_table *eths;
	int *nif_to_eidx; // mapping physic port indexes to that of the configured port-list
	int eths_num;

	/* route config */
	struct route_table *rtable;		// routing table
	struct route_table *gateway;
	int routes;						// # of entries

	/* arp config */
	struct arp_table arp;

	int num_cores;
	int num_mem_ch;
	int max_concurrency;

	int max_num_buffers;
	int rcvbuf_size;
	int sndbuf_size;
	int iobuf_memsize;
	
	int tcp_timewait;
	int tcp_timeout;

	/* adding multi-process support */
	uint8_t multi_process;
	uint8_t multi_process_is_master;
	uint8_t multi_process_curr_core;
};
/*----------------------------------------------------------------------------*/
struct mtcp_context
{
	int cpu;
};
/*----------------------------------------------------------------------------*/
struct mtcp_sender
{
	int ifidx;

	/* TCP layer send queues */
	TAILQ_HEAD (control_head, tcp_stream) control_list;
	TAILQ_HEAD (send_head, tcp_stream) send_list;
	TAILQ_HEAD (ack_head, tcp_stream) ack_list;

	int control_list_cnt;
	int send_list_cnt;
	int ack_list_cnt;
};
/*----------------------------------------------------------------------------*/
struct mtcp_manager
{
	mem_pool_t flow_pool;		/* memory pool for tcp_stream */
	mem_pool_t rv_pool;			/* memory pool for recv variables */
	mem_pool_t sv_pool;			/* memory pool for send variables */
	mem_pool_t mv_pool;			/* memory pool for monitor variables */

	//mem_pool_t socket_pool;
	sb_manager_t rbm_snd;
	rb_manager_t rbm_rcv;
	struct hashtable *tcp_flow_table;

	uint32_t s_index:24;		/* stream index */
	socket_map_t smap;
	TAILQ_HEAD (, socket_map) free_smap;

	TAILQ_HEAD(, addr_pool) ap_list;	/* list of address pool */

	uint32_t g_id;			/* id space in a thread */
	uint32_t flow_cnt;		/* number of concurrent flows */

	struct mtcp_thread_context* ctx;

#ifdef ENABLE_LOGGER
	/* variables related to logger */
	int sp_fd;
	log_thread_context* logger;
	log_buff* w_buffer;
	FILE *log_fp;
#endif

	/* variables related to event */
	struct mtcp_epoll *ep;
	uint32_t ts_last_event;

	struct hashtable *listeners;

	stream_queue_t connectq;				/* streams need to connect */
	stream_queue_t sendq;				/* streams need to send data */
	stream_queue_t ackq;					/* streams need to send ack */

	stream_queue_t closeq;				/* streams need to close */
	stream_queue_int *closeq_int;		/* internally maintained closeq */
	stream_queue_t resetq;				/* streams need to reset */
	stream_queue_int *resetq_int;		/* internally maintained resetq */
	
	stream_queue_t destroyq;				/* streams need to be destroyed */

	struct mtcp_sender *g_sender;
	struct mtcp_sender *n_sender[ETH_NUM];

	/* lists related to timeout */
	struct rto_hashstore* rto_store;
	TAILQ_HEAD (timewait_head, tcp_stream) timewait_list;
	TAILQ_HEAD (timeout_head, tcp_stream) timeout_list;

	int rto_list_cnt;
	int timewait_list_cnt;
	int timeout_list_cnt;

#if BLOCKING_SUPPORT
	TAILQ_HEAD (rcv_br_head, tcp_stream) rcv_br_list;
	TAILQ_HEAD (snd_br_head, tcp_stream) snd_br_list;
	int rcv_br_list_cnt;
	int snd_br_list_cnt;
#endif

	uint32_t cur_ts;

	int wakeup_flag;
	int is_sleeping;

	/* statistics */
	struct bcast_stat bstat;
	struct timeout_stat tstat;
#ifdef NETSTAT
	struct net_stat nstat;
	struct net_stat p_nstat;
	uint32_t p_nstat_ts;

	struct run_stat runstat;
	struct run_stat p_runstat;

	struct time_stat rtstat;
#endif /* NETSTAT */
	
#if OPPORTUNISTIC_STREAM_ALLOC
	int cur_rx_inf;
	struct tcp_stream* cur_stream;
	int zc_unread_cnt; /* for delayed recv buffer alloc */
	int zc_active_cnt; /* for delayed send buffer alloc & hash table insertion */
#endif
	uint32_t offload_ctrl_ts;

	callback_t cb;
	
	struct io_module_func *iom;
};
/*----------------------------------------------------------------------------*/
typedef struct mtcp_manager* mtcp_manager_t;
/*----------------------------------------------------------------------------*/
mtcp_manager_t 
GetMTCPManager(mctx_t mctx);
/*----------------------------------------------------------------------------*/
struct mtcp_thread_context
{
	int cpu;
#ifndef ENABLE_UCTX
	pthread_t thread;
#else
    lthread_t thread;
#endif
	uint8_t done:1, 
			exit:1, 
#ifdef ENABLE_APP_INTERRUPT
            int_app:1,
            in_api:1,
            interrupt:1;

    timer_t timerid;
    uint32_t tick;
#else /* ENABLE_APP_INTERRUPT */
			interrupt:1;
#endif /* ENABLE_APP_INTERRUPT */

	struct mtcp_manager* mtcp_manager;

	void *io_private_context;
	pthread_mutex_t smap_lock;
	pthread_mutex_t flow_pool_lock;
	pthread_mutex_t socket_pool_lock;

#if LOCK_STREAM_QUEUE
#if USE_SPIN_LOCK
	pthread_spinlock_t connect_lock;
	pthread_spinlock_t close_lock;
	pthread_spinlock_t reset_lock;
	pthread_spinlock_t sendq_lock;
	pthread_spinlock_t ackq_lock;
	pthread_spinlock_t destroyq_lock;
#else
	pthread_mutex_t connect_lock;
	pthread_mutex_t close_lock;
	pthread_mutex_t reset_lock;
	pthread_mutex_t sendq_lock;
	pthread_mutex_t ackq_lock;
	pthread_mutex_t destroyq_lock;
#endif /* USE_SPIN_LOCK */
#endif /* LOCK_STREAM_QUEUE */
};
/*----------------------------------------------------------------------------*/
typedef struct mtcp_thread_context* mtcp_thread_context_t;
/*----------------------------------------------------------------------------*/
extern struct mtcp_manager *g_mtcp[MAX_CPUS];
extern struct mtcp_config CONFIG;
extern addr_pool_t ap[ETH_NUM];
/*----------------------------------------------------------------------------*/
struct tcp_timestamp
{
	uint32_t ts_val;
	uint32_t ts_ref;
};
/*----------------------------------------------------------------------------*/
/* offload-related metadata to be delivered between layers */
/* splice offload-related metadata for offloading to NICs */
struct mtcp_splice_meta 
{
	uint8_t  frontend_srcmac[ETH_ALEN];
	uint16_t frontend_nif;
	uint32_t frontend_srcip;
	uint32_t frontend_dstip;	
	uint32_t frontend_sdports;
	uint32_t seq_offset;
	uint32_t ack_offset;
};
struct mtcp_offload_meta 
{
	uint16_t offload_type;
	struct mtcp_splice_meta* splice_meta;
};
/*----------------------------------------------------------------------------*/
	


#endif /* __MTCP_H_ */
