#include "tcp_stream.h"
#include "fhash.h"
#include "tcp_in.h"
#include "tcp_out.h"
#include "tcp_ring_buffer.h"
#include "tcp_send_buffer.h"
#include "eventpoll.h"
#include "ip_out.h"
#include "timer.h"
#include "debug.h"

#define TCP_MAX_SEQ 4294967295

/*---------------------------------------------------------------------------*/
char *state_str[] = {"TCP_ST_CLOSED", 
	"TCP_ST_LISTEN", 
	"TCP_ST_SYN_SENT", 
	"TCP_ST_SYN_RCVD", 
	"TCP_ST_ESTABILSHED", 
	"TCP_ST_FIN_WAIT_1", 
	"TCP_ST_FIN_WAIT_2", 
	"TCP_ST_CLOSE_WAIT", 
	"TCP_ST_CLOSING", 
	"TCP_ST_LAST_ACK", 
	"TCP_ST_TIME_WAIT"
};
/*---------------------------------------------------------------------------*/
char *close_reason_str[] = {
	"NOT_CLOSED", 
	"CLOSE", 
	"CLOSED", 
	"CONN_FAIL", 
	"CONN_LOST", 
	"RESET", 
	"NO_MEM", 
	"DENIED", 
	"TIMEDOUT"
};
/*---------------------------------------------------------------------------*/
/* for rand_r() functions */
static __thread unsigned int next_seed;
/*---------------------------------------------------------------------------*/
inline char *
TCPStateToString(const tcp_stream *stream)
{
	return state_str[stream->state];
}
/*---------------------------------------------------------------------------*/
inline void
InitializeTCPStreamManager()
{
	next_seed = time(NULL);
}
/*---------------------------------------------------------------------------*/
unsigned int
HashFlow(const void *f)
{
	tcp_stream *flow = (tcp_stream *)f;
#if 0
	unsigned long hash = 5381;
	int c;
	int index;

	char *str = (char *)&flow->saddr;
	index = 0;

	while ((c = *str++) && index++ < 12) {
		if (index == 8) {
			str = (char *)&flow->sport;
		}
		hash = ((hash << 5) + hash) + c;
	}

	return hash & (NUM_BINS_FLOWS - 1);
#else
	unsigned int hash, i;
	char *key = (char *)&flow->saddr;

	for (hash = i = 0; i < 12; ++i) {
		hash += key[i];
		hash += (hash << 10);
		hash ^= (hash >> 6);
	}
	hash += (hash << 3);
	hash ^= (hash >> 11);
	hash += (hash << 15);

	return hash & (NUM_BINS_FLOWS - 1);
#endif
}
/*---------------------------------------------------------------------------*/
int
EqualFlow(const void *f1, const void *f2)
{
	tcp_stream *flow1 = (tcp_stream *)f1;
	tcp_stream *flow2 = (tcp_stream *)f2;

	return (flow1->saddr == flow2->saddr && 
			flow1->sport == flow2->sport &&
			flow1->daddr == flow2->daddr &&
			flow1->dport == flow2->dport);
}
/*---------------------------------------------------------------------------*/
inline void 
RaiseReadEvent(mtcp_manager_t mtcp, tcp_stream *stream)
{
	if (stream->socket) {
		if (stream->socket->epoll & MTCP_EPOLLIN) {
			AddEpollEvent(mtcp->ep, 
					MTCP_EVENT_QUEUE, stream->socket, MTCP_EPOLLIN);
#if BLOCKING_SUPPORT
		} else if (!(stream->socket->opts & MTCP_NONBLOCK)) {
			if (!stream->on_rcv_br_list) {
				stream->on_rcv_br_list = TRUE;
				TAILQ_INSERT_TAIL(&mtcp->rcv_br_list, stream, rcvvar->rcv_br_link);
				mtcp->rcv_br_list_cnt++;
			}
#endif
		}
	} else {
		TRACE_EPOLL("Stream %d: Raising read without a socket!\n", stream->id);
	}
}
/*---------------------------------------------------------------------------*/
inline void 
RaiseWriteEvent(mtcp_manager_t mtcp, tcp_stream *stream)
{
	if (stream->socket) {
		if (stream->socket->epoll & MTCP_EPOLLOUT) {
			AddEpollEvent(mtcp->ep, 
					MTCP_EVENT_QUEUE, stream->socket, MTCP_EPOLLOUT);
#if BLOCKING_SUPPORT
		} else if (!(stream->socket->opts & MTCP_NONBLOCK)) {
			if (!stream->on_snd_br_list) {
				stream->on_snd_br_list = TRUE;
				TAILQ_INSERT_TAIL(&mtcp->snd_br_list, stream, sndvar->snd_br_link);
				mtcp->snd_br_list_cnt++;
			}
#endif
		}
	} else {
		TRACE_EPOLL("Stream %d: Raising write without a socket!\n", stream->id);
	}
}
/*---------------------------------------------------------------------------*/
inline void 
RaiseCloseEvent(mtcp_manager_t mtcp, tcp_stream *stream)
{
	if (stream->socket) {
		if (stream->socket->epoll & MTCP_EPOLLRDHUP) {
			AddEpollEvent(mtcp->ep, 
					MTCP_EVENT_QUEUE, stream->socket, MTCP_EPOLLRDHUP);
		} else if (stream->socket->epoll & MTCP_EPOLLIN) {
			AddEpollEvent(mtcp->ep, 
					MTCP_EVENT_QUEUE, stream->socket, MTCP_EPOLLIN);
#if BLOCKING_SUPPORT
		} else if (!(stream->socket->opts & MTCP_NONBLOCK)) {
			//pthread_cond_signal(&stream->rcvvar->read_cond);
			//pthread_cond_signal(&stream->sndvar->write_cond);
			if (!stream->on_rcv_br_list) {
				stream->on_rcv_br_list = TRUE;
				TAILQ_INSERT_TAIL(&mtcp->rcv_br_list, stream, rcvvar->rcv_br_link);
				mtcp->rcv_br_list_cnt++;
			}
			if (!stream->on_snd_br_list) {
				stream->on_snd_br_list = TRUE;
				TAILQ_INSERT_TAIL(&mtcp->snd_br_list, stream, sndvar->snd_br_link);
				mtcp->snd_br_list_cnt++;
			}
#endif
		}
	} else {
		TRACE_EPOLL("Stream %d: Raising close without a socket!\n", stream->id);
	}
}
/*---------------------------------------------------------------------------*/
inline void 
RaiseErrorEvent(mtcp_manager_t mtcp, tcp_stream *stream)
{
	if (stream->socket) {
		if (stream->socket->epoll & MTCP_EPOLLERR) {
			AddEpollEvent(mtcp->ep, 
					MTCP_EVENT_QUEUE, stream->socket, MTCP_EPOLLERR);
#if BLOCKING_SUPPORT
		} else if (!(stream->socket->opts & MTCP_NONBLOCK)) {
			if (!stream->on_rcv_br_list) {
				stream->on_rcv_br_list = TRUE;
				TAILQ_INSERT_TAIL(&mtcp->rcv_br_list, stream, rcvvar->rcv_br_link);
				mtcp->rcv_br_list_cnt++;
			}
			if (!stream->on_snd_br_list) {
				stream->on_snd_br_list = TRUE;
				TAILQ_INSERT_TAIL(&mtcp->snd_br_list, stream, sndvar->snd_br_link);
				mtcp->snd_br_list_cnt++;
			}
#endif
		}
	} else {
		TRACE_EPOLL("Stream %d: Raising error without a socket!\n", stream->id);
	}
}
/*---------------------------------------------------------------------------*/
#if OPPORTUNISTIC_STREAM_ALLOC
tcp_stream *
CreateQuasiTCPStream(mtcp_manager_t mtcp, int type, 
					 uint32_t saddr, uint16_t sport, uint32_t daddr, uint16_t dport,
					 uint32_t seq, uint32_t ack_seq,
					 uint8_t *payload, int payloadlen)
{
	struct tcp_listener *listener;
	tcp_stream *stream;

	/* update listening socket */
	if (!(listener = (struct tcp_listener *)ListenerHTSearch(mtcp->listeners, &sport)))
		return NULL;

	stream = (tcp_stream *)MPAllocateChunk(mtcp->flow_pool);
	if (!stream) {
		TRACE_ERROR("Cannot allocate memory for the stream. "
				"CONFIG.max_concurrency: %d, concurrent: %u\n", 
				CONFIG.max_concurrency, mtcp->flow_cnt);
		return NULL;
	}
	memset(stream, 0, sizeof(tcp_stream));

	stream->id = mtcp->g_id++;
	stream->stream_type = type;
	
	stream->saddr = saddr;
	stream->sport = sport;
	stream->daddr = daddr;
	stream->dport = dport;

	stream->state = TCP_ST_ESTABLISHED;	
	stream->quasi_alloc = TRUE;
	//stream->teardown_offload = TRUE;

	stream->iss = ack_seq - 1;
	stream->irs = seq - 1;
	stream->snd_nxt = ack_seq;
	stream->rcv_nxt = seq + payloadlen;
	
	if (payloadlen > 0) {
		stream->zc_rbuf = payload;
		stream->zc_rbuf_len = payloadlen;
		mtcp->zc_unread_cnt++;
	}
	mtcp->zc_active_cnt++;
	stream->on_rto_idx = -1;

	/* add to acceptq and raise an event to the listening socket */
	if (StreamEnqueue(listener->acceptq, stream) < 0) {
		TRACE_ERROR("Stream %d: Failed to enqueue to the listen backlog!\n", stream->id);
		MPFreeChunk(mtcp->flow_pool, stream);
		return NULL;
	}
	if (listener->socket && (listener->socket->epoll & MTCP_EPOLLIN))
		AddEpollEvent(mtcp->ep, MTCP_EVENT_QUEUE, listener->socket, MTCP_EPOLLIN);

	mtcp->flow_cnt++;
	
	return stream;	
}
/*---------------------------------------------------------------------------*/
int
CreateTCPStreamRcvvar(mtcp_manager_t mtcp, tcp_stream* stream)
{
	if (!stream || stream->rcvvar)
		return FALSE;

	stream->rcvvar = (struct tcp_recv_vars *)MPAllocateChunk(mtcp->rv_pool);
	if (!stream->rcvvar)
		return FALSE;

	memset(stream->rcvvar, 0, sizeof(struct tcp_recv_vars));

	stream->rcvvar->rcv_wnd = TCP_INITIAL_WINDOW;
	//stream->irs = stream->rcv_nxt;	
	//stream->rcvvar->snd_wl1 = stream->rcvvar->irs - 1;
	
	return TRUE;
}
/*---------------------------------------------------------------------------*/
int
CreateTCPStreamSndvar(mtcp_manager_t mtcp, tcp_stream* stream)
{
	uint8_t is_external;
	
	if (!stream || stream->rcvvar)
		return FALSE;
	
	stream->sndvar = (struct tcp_send_vars *)MPAllocateChunk(mtcp->sv_pool);
	if (!stream->sndvar)
		return FALSE;
	
	memset(stream->sndvar, 0, sizeof(struct tcp_send_vars));

	stream->sndvar->ip_id = 0;
	stream->sndvar->mss = TCP_DEFAULT_MSS;	
	stream->sndvar->eff_mss = TCP_DEFAULT_MSS;
#if TCP_OPT_TIMESTAMP_ENABLED
	//stream->sndvar->eff_mss -= (TCP_OPT_TIMESTAMP_LEN + 2);
#endif
	stream->sndvar->wscale_mine = TCP_DEFAULT_WSCALE;
	stream->sndvar->wscale_peer = 0;
	stream->sndvar->nif_out = GetOutputInterface(stream->daddr, &is_external);
	stream->is_external = is_external;

	//stream->iss = stream->snd_nxt - 1;
	stream->sndvar->snd_una = stream->iss;
	stream->sndvar->snd_wnd = CONFIG.sndbuf_size;
	stream->sndvar->rto = TCP_INITIAL_RTO;

	stream->sndvar->cwnd = stream->sndvar->mss * 2;
	stream->sndvar->ssthresh = stream->sndvar->mss * 10;

	stream->sndvar->wscale_peer = TCP_DEFAULT_WSCALE;
	stream->sndvar->peer_wnd = (uint32_t)TCP_INITIAL_WINDOW << stream->sndvar->wscale_peer;
	
	return TRUE;
}
/*---------------------------------------------------------------------------*/
tcp_stream *
CreateTCPStreamFromQuasi(mtcp_manager_t mtcp, tcp_stream *stream, socket_map_t socket)
{
	int ret = StreamHTInsert(mtcp->tcp_flow_table, stream);
	if (ret < 0) {
		TRACE_ERROR("Stream %d: "
				"Failed to insert the stream into hash table.\n", stream->id);
		MPFreeChunk(mtcp->flow_pool, stream);
		return NULL;
	}
	stream->on_hash_table = TRUE;

	stream->quasi_alloc = FALSE;

	if (socket) {
		stream->socket = socket;
		socket->stream = stream;
	}

	CreateTCPStreamSndvar(mtcp, stream);
	CreateTCPStreamRcvvar(mtcp, stream);
	
	return stream;
}
#endif
/*---------------------------------------------------------------------------*/
tcp_stream *
CreateTCPStream(mtcp_manager_t mtcp, socket_map_t socket, int type, 
		uint32_t saddr, uint16_t sport, uint32_t daddr, uint16_t dport)
{
	tcp_stream *stream = NULL;
	int ret;

	uint8_t is_external;
	uint8_t *sa;
	uint8_t *da;
#ifndef ENABLE_UCTX	
	pthread_mutex_lock(&mtcp->ctx->flow_pool_lock);
#endif
	stream = (tcp_stream *)MPAllocateChunk(mtcp->flow_pool);
	if (!stream) {
		TRACE_ERROR("Cannot allocate memory for the stream. "
				"CONFIG.max_concurrency: %d, concurrent: %u\n", 
				CONFIG.max_concurrency, mtcp->flow_cnt);
#ifndef ENABLE_UCTX
		pthread_mutex_unlock(&mtcp->ctx->flow_pool_lock);
#endif
		return NULL;
	}
	memset(stream, 0, sizeof(tcp_stream));

	stream->rcvvar = (struct tcp_recv_vars *)MPAllocateChunk(mtcp->rv_pool);
	if (!stream->rcvvar) {
		MPFreeChunk(mtcp->flow_pool, stream);
#ifndef ENABLE_UCTX
		pthread_mutex_unlock(&mtcp->ctx->flow_pool_lock);
#endif
		return NULL;
	}
	stream->sndvar = (struct tcp_send_vars *)MPAllocateChunk(mtcp->sv_pool);
	if (!stream->sndvar) {
		MPFreeChunk(mtcp->rv_pool, stream->rcvvar);
		MPFreeChunk(mtcp->flow_pool, stream);
#ifndef ENABLE_UCTX
		pthread_mutex_unlock(&mtcp->ctx->flow_pool_lock);
#endif
		return NULL;
	}
	memset(stream->rcvvar, 0, sizeof(struct tcp_recv_vars));
	memset(stream->sndvar, 0, sizeof(struct tcp_send_vars));

	stream->id = mtcp->g_id++;
	stream->saddr = saddr;
	stream->sport = sport;
	stream->daddr = daddr;
	stream->dport = dport;

	ret = StreamHTInsert(mtcp->tcp_flow_table, stream);
	if (ret < 0) {
		TRACE_ERROR("Stream %d: "
				"Failed to insert the stream into hash table.\n", stream->id);
		MPFreeChunk(mtcp->flow_pool, stream);
#ifndef ENABLE_UCTX
		pthread_mutex_unlock(&mtcp->ctx->flow_pool_lock);
#endif
		return NULL;
	}
	stream->on_hash_table = TRUE;
	mtcp->flow_cnt++;

#ifndef ENABLE_UCTX
	pthread_mutex_unlock(&mtcp->ctx->flow_pool_lock);
#endif

	if (socket) {
		stream->socket = socket;
		socket->stream = stream;
	}

	stream->stream_type = type;
	stream->state = TCP_ST_LISTEN;

	stream->on_rto_idx = -1;
	
	stream->sndvar->ip_id = 0;
	stream->sndvar->mss = TCP_DEFAULT_MSS;
	stream->sndvar->eff_mss = TCP_DEFAULT_MSS;
#if TCP_OPT_TIMESTAMP_ENABLED
	stream->sndvar->eff_mss -= (TCP_OPT_TIMESTAMP_LEN + 2);
#endif
	stream->sndvar->wscale_mine = TCP_DEFAULT_WSCALE;
	stream->sndvar->wscale_peer = 0;
	stream->sndvar->nif_out = GetOutputInterface(stream->daddr, &is_external);
	stream->is_external = is_external;

	stream->iss = rand_r(&next_seed) % TCP_MAX_SEQ;
	stream->snd_nxt = stream->iss;
	stream->sndvar->snd_una = stream->iss;
	stream->sndvar->snd_wnd = CONFIG.sndbuf_size;
	stream->rcv_nxt = 0;
	stream->rcvvar->rcv_wnd = TCP_INITIAL_WINDOW;
	stream->rcvvar->snd_wl1 = stream->irs - 1;
	stream->sndvar->rto = TCP_INITIAL_RTO;
	
#if BLOCKING_SUPPORT
	if (pthread_cond_init(&stream->rcvvar->read_cond, NULL)) {
		perror("pthread_cond_init of read_cond");
		return NULL;
	}
	if (pthread_cond_init(&stream->sndvar->write_cond, NULL)) {
		perror("pthread_cond_init of write_cond");
		return NULL;
	}
#endif

#if USE_SPIN_LOCK
	if (pthread_spin_init(&stream->rcvvar->read_lock, PTHREAD_PROCESS_PRIVATE)) {
#else
	if (pthread_mutex_init(&stream->rcvvar->read_lock, NULL)) {
#endif
		perror("pthread_mutex_init of read_lock");
#if BLOCKING_SUPPORT
		pthread_cond_destroy(&stream->rcvvar->read_cond);
		pthread_cond_destroy(&stream->sndvar->write_cond);
#endif
		return NULL;
	}
#if USE_SPIN_LOCK
	if (pthread_spin_init(&stream->sndvar->write_lock, PTHREAD_PROCESS_PRIVATE)) {
		perror("pthread_spin_init of write_lock");
		pthread_spin_destroy(&stream->rcvvar->read_lock);
#else
	if (pthread_mutex_init(&stream->sndvar->write_lock, NULL)) {
		perror("pthread_mutex_init of write_lock");
		pthread_mutex_destroy(&stream->rcvvar->read_lock);
#endif
#if BLOCKING_SUPPORT
		pthread_cond_destroy(&stream->rcvvar->read_cond);
		pthread_cond_destroy(&stream->sndvar->write_cond);
#endif
		return NULL;
	}

	sa = (uint8_t *)&stream->saddr;
	da = (uint8_t *)&stream->daddr;
	TRACE_STREAM("CREATED NEW TCP STREAM %d: "
			"%u.%u.%u.%u(%d) -> %u.%u.%u.%u(%d) (ISS: %u)\n", stream->id, 
			sa[0], sa[1], sa[2], sa[3], ntohs(stream->sport), 
			da[0], da[1], da[2], da[3], ntohs(stream->dport), 
			stream->iss);

	UNUSED(da);
	UNUSED(sa);
	return stream;
}
/*---------------------------------------------------------------------------*/
void
DestroyTCPStream(mtcp_manager_t mtcp, tcp_stream *stream)
{
	struct sockaddr_in addr;
	int bound_addr = FALSE;
	int ret = 0;
	struct addr_pool *ap_walk = NULL;
	struct addr_pool *free_ap = NULL;

#ifdef DUMP_STREAM
	uint8_t *sa, *da;
	if (stream->close_reason != TCP_ACTIVE_CLOSE && 
			stream->close_reason != TCP_PASSIVE_CLOSE) {
		thread_printf(mtcp, mtcp->log_fp, 
				"Stream %d abnormally closed.\n", stream->id);
		DumpStream(mtcp, stream);
		DumpControlList(mtcp, mtcp->n_sender[0]);
	}

	sa = (uint8_t *)&stream->saddr;
	da = (uint8_t *)&stream->daddr;
	TRACE_STREAM("DESTROY TCP STREAM %d: "
			"%u.%u.%u.%u(%d) -> %u.%u.%u.%u(%d) (%s)\n", stream->id, 
			sa[0], sa[1], sa[2], sa[3], ntohs(stream->sport), 
			da[0], da[1], da[2], da[3], ntohs(stream->dport), 
			close_reason_str[stream->close_reason]);
#endif
	
	if (stream->sndvar) {
#ifdef DUMP_STREAM		
		if (stream->sndvar->sndbuf) {
			TRACE_FSTAT("Stream %d: send buffer "
						"cum_len: %lu, len: %u\n", stream->id, 
						stream->sndvar->sndbuf->cum_len, 
						stream->sndvar->sndbuf->len);
		}
#endif
#if RTM_STAT
		/* Triple duplicated ack stats */
		if (stream->sndvar->rstat.tdp_ack_cnt) {
			TRACE_FSTAT("Stream %d: triple duplicated ack: %u, "
						"retransmission bytes: %u, average rtm bytes/ack: %u\n", 
						stream->id, 
						stream->sndvar->rstat.tdp_ack_cnt, stream->sndvar->rstat.tdp_ack_bytes, 
						stream->sndvar->rstat.tdp_ack_bytes / stream->sndvar->rstat.tdp_ack_cnt);
		}

		/* Retransmission timeout stats */
		if (stream->sndvar->rstat.rto_cnt > 0) {
			TRACE_FSTAT("Stream %d: timeout count: %u, bytes: %u\n", stream->id, 
						stream->sndvar->rstat.rto_cnt, stream->sndvar->rstat.rto_bytes);
		}

		/* Recovery stats */
		if (stream->sndvar->rstat.ack_upd_cnt) {
			TRACE_FSTAT("Stream %d: snd_nxt update count: %u, "
						"snd_nxt update bytes: %u, average update bytes/update: %u\n", 
						stream->id, 
						stream->sndvar->rstat.ack_upd_cnt, stream->sndvar->rstat.ack_upd_bytes, 
						stream->sndvar->rstat.ack_upd_bytes / stream->sndvar->rstat.ack_upd_cnt);
		}
#if TCP_OPT_SACK_ENABLED
		if (stream->sndvar->rstat.sack_cnt) {
			TRACE_FSTAT("Selective ack count: %u, bytes: %u, "
						"average bytes/ack: %u\n", 
						stream->sndvar->rstat.sack_cnt, stream->sndvar->rstat.sack_bytes, 
						stream->sndvar->rstat.sack_bytes / stream->sndvar->rstat.sack_cnt);
		} else {
			TRACE_FSTAT("Selective ack count: %u, bytes: %u\n", 
						stream->sndvar->rstat.sack_cnt, stream->sndvar->rstat.sack_bytes);
		}
		if (stream->sndvar->rstat.tdp_sack_cnt) {
			TRACE_FSTAT("Selective tdp ack count: %u, bytes: %u, "
						"average bytes/ack: %u\n", 
						stream->sndvar->rstat.tdp_sack_cnt, stream->sndvar->rstat.tdp_sack_bytes, 
						stream->sndvar->rstat.tdp_sack_bytes / stream->sndvar->rstat.tdp_sack_cnt);
		} else {
			TRACE_FSTAT("Selective ack count: %u, bytes: %u\n", 
						stream->sndvar->rstat.tdp_sack_cnt, stream->sndvar->rstat.tdp_sack_bytes);
		}
#endif
#endif /* RTM_STAT */
#if BLOCKING_SUPPORT
		if (stream->on_snd_br_list) {
			stream->on_snd_br_list = FALSE;
			TAILQ_REMOVE(&mtcp->snd_br_list, stream, sndvar->snd_br_link);
			mtcp->snd_br_list_cnt--;
		}

		if (!stream->epoll) {
			pthread_cond_signal(&stream->sndvar->write_cond);
		}
		if (pthread_cond_destroy(&stream->sndvar->write_cond)) {
			perror("pthread_cond_destroy of write_cond");
		}
#endif
		SBUF_LOCK_DESTROY(&stream->sndvar->write_lock);
		/* free ring buffers */
		if (stream->sndvar->sndbuf) {
			SBFree(mtcp->rbm_snd, stream->sndvar->sndbuf);
			stream->sndvar->sndbuf = NULL;
		}

		RemoveFromControlList(mtcp, stream);
		RemoveFromSendList(mtcp, stream);
		RemoveFromACKList(mtcp, stream);	

		if (stream->on_rto_idx >= 0)
			RemoveFromRTOList(mtcp, stream);
		
		if (stream->on_timewait_list)
			RemoveFromTimewaitList(mtcp, stream);
		
		if (CONFIG.tcp_timeout > 0)
			RemoveFromTimeoutList(mtcp, stream);
		
	} /* if (stream->sndvar) */

	if (stream->rcvvar) {
#ifdef DUMP_STREAM
		if (stream->rcvvar->rcvbuf) {
			TRACE_FSTAT("Stream %d: recv buffer "
						"cum_len: %lu, merged_len: %u, last_len: %u\n", stream->id, 
						stream->rcvvar->rcvbuf->cum_len, 
						stream->rcvvar->rcvbuf->merged_len, 
						stream->rcvvar->rcvbuf->last_len);
		}
#endif
#if BLOCKING_SUPPORT
		if (stream->on_rcv_br_list) {
			stream->on_rcv_br_list = FALSE;
			TAILQ_REMOVE(&mtcp->rcv_br_list, stream, rcvvar->rcv_br_link);
			mtcp->rcv_br_list_cnt--;
		}

		if (!stream->epoll) {
			pthread_cond_signal(&stream->rcvvar->read_cond);
		}
		if (pthread_cond_destroy(&stream->rcvvar->read_cond)) {
			perror("pthread_cond_destroy of read_cond");
		}
#endif
		SBUF_LOCK_DESTROY(&stream->rcvvar->read_lock);
		if (stream->rcvvar->rcvbuf) {
			RBFree(mtcp->rbm_rcv, stream->rcvvar->rcvbuf);
			stream->rcvvar->rcvbuf = NULL;
		}	
		
	} /* if (stream->rcvvar) */

	if (stream->is_bound_addr) {
		bound_addr = TRUE;
		addr.sin_addr.s_addr = stream->saddr;
		addr.sin_port = stream->sport;
		TAILQ_FOREACH(ap_walk, &mtcp->ap_list, ap_link) {
			if (ap_walk->daddr == stream->daddr && ap_walk->dport == stream->dport) {
				free_ap = ap_walk;
				break;
			}
		}
	}
	
#ifndef ENABLE_UCTX
	pthread_mutex_lock(&mtcp->ctx->flow_pool_lock);
#endif

#if OPPORTUNISTIC_STREAM_ALLOC
	if (stream->quasi_alloc)
		mtcp->zc_active_cnt--;		
#endif
	
	/* remove from flow hash table */
	if (stream->on_hash_table) {
		StreamHTRemove(mtcp->tcp_flow_table, stream);
		stream->on_hash_table = FALSE;
	}
	mtcp->flow_cnt--;
	if (stream->rcvvar)
		MPFreeChunk(mtcp->rv_pool, stream->rcvvar);
	if (stream->sndvar)
		MPFreeChunk(mtcp->sv_pool, stream->sndvar);
	MPFreeChunk(mtcp->flow_pool, stream);
	
#ifndef ENABLE_UCTX
	pthread_mutex_unlock(&mtcp->ctx->flow_pool_lock);
#endif

	if (bound_addr) {
		if (free_ap) {
			ret = FreeAddress(free_ap, &addr);
		} else {
			uint8_t is_external;
			int nif = GetOutputInterface(addr.sin_addr.s_addr, &is_external);
			if (nif < 0) {
				TRACE_ERROR("nif is negative!\n");
				ret = -1;
			} else {
			        int eidx = CONFIG.nif_to_eidx[nif];
				ret = FreeAddress(ap[eidx], &addr);
			}
			UNUSED(is_external);
		}
		if (ret < 0) {
			TRACE_ERROR("(NEVER HAPPEN) Failed to free address.\n");
		}
	}

#ifdef NETSTAT
#if NETSTAT_PERTHREAD
	TRACE_STREAM("Destroyed. Remaining flows: %u\n", mtcp->flow_cnt);
#endif /* NETSTAT_PERTHREAD */
#endif /* NETSTAT */

}

void
DestroySpliceStream(mtcp_manager_t mtcp, tcp_stream *stream)
{
	struct sockaddr_in addr;
	int bound_addr = FALSE;
	int ret = 0;
	struct addr_pool *ap_walk = NULL;
	struct addr_pool *free_ap = NULL;

	
#ifdef DUMP_STREAM
	uint8_t *sa, *da;
	if (stream->close_reason != TCP_ACTIVE_CLOSE && 
			stream->close_reason != TCP_PASSIVE_CLOSE) {
		thread_printf(mtcp, mtcp->log_fp, 
				"Stream %d abnormally closed.\n", stream->id);
		DumpStream(mtcp, stream);
		DumpControlList(mtcp, mtcp->n_sender[0]);
	}

	sa = (uint8_t *)&stream->saddr;
	da = (uint8_t *)&stream->daddr;
	TRACE_STREAM("DESTROY TCP STREAM %d: "
			"%u.%u.%u.%u(%d) -> %u.%u.%u.%u(%d) (%s)\n", stream->id, 
			sa[0], sa[1], sa[2], sa[3], ntohs(stream->sport), 
			da[0], da[1], da[2], da[3], ntohs(stream->dport), 
			close_reason_str[stream->close_reason]);
#endif
	
	if (stream->sndvar) {
#ifdef DUMP_STREAM		
		if (stream->sndvar->sndbuf) {
			TRACE_FSTAT("Stream %d: send buffer "
						"cum_len: %lu, len: %u\n", stream->id, 
						stream->sndvar->sndbuf->cum_len, 
						stream->sndvar->sndbuf->len);
		}
#endif
#if RTM_STAT
		/* Triple duplicated ack stats */
		if (stream->sndvar->rstat.tdp_ack_cnt) {
			TRACE_FSTAT("Stream %d: triple duplicated ack: %u, "
						"retransmission bytes: %u, average rtm bytes/ack: %u\n", 
						stream->id, 
						stream->sndvar->rstat.tdp_ack_cnt, stream->sndvar->rstat.tdp_ack_bytes, 
						stream->sndvar->rstat.tdp_ack_bytes / stream->sndvar->rstat.tdp_ack_cnt);
		}

		/* Retransmission timeout stats */
		if (stream->sndvar->rstat.rto_cnt > 0) {
			TRACE_FSTAT("Stream %d: timeout count: %u, bytes: %u\n", stream->id, 
						stream->sndvar->rstat.rto_cnt, stream->sndvar->rstat.rto_bytes);
		}

		/* Recovery stats */
		if (stream->sndvar->rstat.ack_upd_cnt) {
			TRACE_FSTAT("Stream %d: snd_nxt update count: %u, "
						"snd_nxt update bytes: %u, average update bytes/update: %u\n", 
						stream->id, 
						stream->sndvar->rstat.ack_upd_cnt, stream->sndvar->rstat.ack_upd_bytes, 
						stream->sndvar->rstat.ack_upd_bytes / stream->sndvar->rstat.ack_upd_cnt);
		}
#if TCP_OPT_SACK_ENABLED
		if (stream->sndvar->rstat.sack_cnt) {
			TRACE_FSTAT("Selective ack count: %u, bytes: %u, "
						"average bytes/ack: %u\n", 
						stream->sndvar->rstat.sack_cnt, stream->sndvar->rstat.sack_bytes, 
						stream->sndvar->rstat.sack_bytes / stream->sndvar->rstat.sack_cnt);
		} else {
			TRACE_FSTAT("Selective ack count: %u, bytes: %u\n", 
						stream->sndvar->rstat.sack_cnt, stream->sndvar->rstat.sack_bytes);
		}
		if (stream->sndvar->rstat.tdp_sack_cnt) {
			TRACE_FSTAT("Selective tdp ack count: %u, bytes: %u, "
						"average bytes/ack: %u\n", 
						stream->sndvar->rstat.tdp_sack_cnt, stream->sndvar->rstat.tdp_sack_bytes, 
						stream->sndvar->rstat.tdp_sack_bytes / stream->sndvar->rstat.tdp_sack_cnt);
		} else {
			TRACE_FSTAT("Selective ack count: %u, bytes: %u\n", 
						stream->sndvar->rstat.tdp_sack_cnt, stream->sndvar->rstat.tdp_sack_bytes);
		}
#endif
#endif /* RTM_STAT */
#if BLOCKING_SUPPORT
		if (stream->on_snd_br_list) {
			stream->on_snd_br_list = FALSE;
			TAILQ_REMOVE(&mtcp->snd_br_list, stream, sndvar->snd_br_link);
			mtcp->snd_br_list_cnt--;
		}

		if (!stream->epoll) {
			pthread_cond_signal(&stream->sndvar->write_cond);
		}
		if (pthread_cond_destroy(&stream->sndvar->write_cond)) {
			perror("pthread_cond_destroy of write_cond");
		}
#endif
		SBUF_LOCK_DESTROY(&stream->sndvar->write_lock);
		/* free ring buffers */
		if (stream->sndvar->sndbuf) {
			SBFree(mtcp->rbm_snd, stream->sndvar->sndbuf);
			stream->sndvar->sndbuf = NULL;
		}

		RemoveFromControlList(mtcp, stream);
		RemoveFromSendList(mtcp, stream);
		RemoveFromACKList(mtcp, stream);	

		if (stream->on_rto_idx >= 0)
			RemoveFromRTOList(mtcp, stream);
		
		if (stream->on_timewait_list)
			RemoveFromTimewaitList(mtcp, stream);
		
		if (CONFIG.tcp_timeout > 0)
			RemoveFromTimeoutList(mtcp, stream);
		
	} /* if (stream->sndvar) */

	if (stream->rcvvar) {
#ifdef DUMP_STREAM
		if (stream->rcvvar->rcvbuf) {
			TRACE_FSTAT("Stream %d: recv buffer "
						"cum_len: %lu, merged_len: %u, last_len: %u\n", stream->id, 
						stream->rcvvar->rcvbuf->cum_len, 
						stream->rcvvar->rcvbuf->merged_len, 
						stream->rcvvar->rcvbuf->last_len);
		}
#endif
#if BLOCKING_SUPPORT
		if (stream->on_rcv_br_list) {
			stream->on_rcv_br_list = FALSE;
			TAILQ_REMOVE(&mtcp->rcv_br_list, stream, rcvvar->rcv_br_link);
			mtcp->rcv_br_list_cnt--;
		}

		if (!stream->epoll) {
			pthread_cond_signal(&stream->rcvvar->read_cond);
		}
		if (pthread_cond_destroy(&stream->rcvvar->read_cond)) {
			perror("pthread_cond_destroy of read_cond");
		}
#endif
		SBUF_LOCK_DESTROY(&stream->rcvvar->read_lock);
		if (stream->rcvvar->rcvbuf) {
			RBFree(mtcp->rbm_rcv, stream->rcvvar->rcvbuf);
			stream->rcvvar->rcvbuf = NULL;
		}	
		
	} /* if (stream->rcvvar) */

	if (stream->is_bound_addr) {
		bound_addr = TRUE;
		addr.sin_addr.s_addr = stream->saddr;
		addr.sin_port = stream->sport;
		TAILQ_FOREACH(ap_walk, &mtcp->ap_list, ap_link) {
			if (ap_walk->daddr == stream->daddr && ap_walk->dport == stream->dport) {
				free_ap = ap_walk;
				break;
			}
		}
	}
	
#ifndef ENABLE_UCTX
	pthread_mutex_lock(&mtcp->ctx->flow_pool_lock);
#endif

#if OPPORTUNISTIC_STREAM_ALLOC
	if (stream->quasi_alloc)
		mtcp->zc_active_cnt--;		
#endif
	
	/* remove from flow hash table */
	if (stream->on_hash_table) {
		StreamHTRemove(mtcp->tcp_flow_table, stream);
		stream->on_hash_table = FALSE;
	}
	mtcp->flow_cnt--;
	if (stream->rcvvar)
		MPFreeChunk(mtcp->rv_pool, stream->rcvvar);
	if (stream->sndvar)
		MPFreeChunk(mtcp->sv_pool, stream->sndvar);
	MPFreeChunk(mtcp->flow_pool, stream);
	
#ifndef ENABLE_UCTX
	pthread_mutex_unlock(&mtcp->ctx->flow_pool_lock);
#endif

	if (bound_addr) {
		if (free_ap) {
			ret = MoveAddressToSplice(free_ap, &addr);
		} else {
			uint8_t is_external;
			int nif = GetOutputInterface(addr.sin_addr.s_addr, &is_external);
			if (nif < 0) {
				TRACE_ERROR("nif is negative!\n");
				ret = -1;
			} else {
			        int eidx = CONFIG.nif_to_eidx[nif];
				ret = MoveAddressToSplice(ap[eidx], &addr);
			}
			UNUSED(is_external);
		}
		if (ret < 0) {
			TRACE_ERROR("(NEVER HAPPEN) Failed to free address.\n");
		}
	}

#ifdef NETSTAT
#if NETSTAT_PERTHREAD
	TRACE_STREAM("Destroyed. Remaining flows: %u\n", mtcp->flow_cnt);
#endif /* NETSTAT_PERTHREAD */
#endif /* NETSTAT */

}

#ifdef ENABLE_LOGGER
/*---------------------------------------------------------------------------*/
void 
DumpStream(mtcp_manager_t mtcp, tcp_stream *stream)
{
	uint8_t *sa, *da;
	struct tcp_send_vars *sndvar = stream->sndvar;
	struct tcp_recv_vars *rcvvar = stream->rcvvar;

	sa = (uint8_t *)&stream->saddr;
	da = (uint8_t *)&stream->daddr;
	thread_printf(mtcp, mtcp->log_fp, "========== Stream %u: "
			"%u.%u.%u.%u(%u) -> %u.%u.%u.%u(%u) ==========\n", stream->id, 
			sa[0], sa[1], sa[2], sa[3], ntohs(stream->sport), 
			da[0], da[1], da[2], da[3], ntohs(stream->dport));
	thread_printf(mtcp, mtcp->log_fp, 
			"Stream id: %u, type: %u, state: %s, close_reason: %s\n",  
			stream->id, stream->stream_type, 
			TCPStateToString(stream), close_reason_str[stream->close_reason]);
	if (stream->socket) {
		socket_map_t socket = stream->socket;
		thread_printf(mtcp, mtcp->log_fp, "Socket id: %d, type: %d, opts: %u\n"
				"epoll: %u (IN: %u, OUT: %u, ERR: %u, RDHUP: %u, ET: %u)\n"
				"events: %u (IN: %u, OUT: %u, ERR: %u, RDHUP: %u, ET: %u)\n", 
				socket->id, socket->socktype, socket->opts, 
				socket->epoll, socket->epoll & MTCP_EPOLLIN, 
				socket->epoll & MTCP_EPOLLOUT, socket->epoll & MTCP_EPOLLERR, 
				socket->epoll & MTCP_EPOLLRDHUP, socket->epoll & MTCP_EPOLLET, 
				socket->events, socket->events & MTCP_EPOLLIN, 
				socket->events & MTCP_EPOLLOUT, socket->events & MTCP_EPOLLERR, 
				socket->events & MTCP_EPOLLRDHUP, socket->events & MTCP_EPOLLET);
	} else {
		thread_printf(mtcp, mtcp->log_fp, "Socket: (null)\n");
	}

	thread_printf(mtcp, mtcp->log_fp, 
			"on_hash_table: %u, on_control_list: %u (wait: %u), on_send_list: %u, "
			"on_ack_list: %u, is_wack: %u, ack_cnt: %u\n"
			"on_rto_idx: %d, on_timewait_list: %u, on_timeout_list: %u, "
			"on_rcv_br_list: %u, on_snd_br_list: %u\n"
			"on_sendq: %u, on_ackq: %u, closed: %u, on_closeq: %u, "
			"on_closeq_int: %u, on_resetq: %u, on_resetq_int: %u\n"
			"have_reset: %u, is_fin_sent: %u, is_fin_ackd: %u, "
			"saw_timestamp: %u, sack_permit: %u, "
			"is_bound_addr: %u, need_wnd_adv: %u\n", stream->on_hash_table, 
			sndvar->on_control_list, stream->control_list_waiting, sndvar->on_send_list, 
			sndvar->on_ack_list, sndvar->is_wack, sndvar->ack_cnt, 
			stream->on_rto_idx, stream->on_timewait_list, stream->on_timeout_list, 
			stream->on_rcv_br_list, stream->on_snd_br_list, 
			sndvar->on_sendq, sndvar->on_ackq, 
			stream->closed, sndvar->on_closeq, sndvar->on_closeq_int, 
			sndvar->on_resetq, sndvar->on_resetq_int, 
			stream->have_reset, sndvar->is_fin_sent, 
			sndvar->is_fin_ackd, stream->saw_timestamp, stream->sack_permit, 
			stream->is_bound_addr, stream->need_wnd_adv);

	thread_printf(mtcp, mtcp->log_fp, "========== Send variables ==========\n");
	thread_printf(mtcp, mtcp->log_fp, 
			"ip_id: %u, mss: %u, eff_mss: %u, wscale (me, peer): (%u, %u), "
			"nif_out: %d\n", 
			sndvar->ip_id, sndvar->mss, sndvar->eff_mss, 
			sndvar->wscale_mine, sndvar->wscale_peer, sndvar->nif_out);
	thread_printf(mtcp, mtcp->log_fp, 
			"snd_nxt: %u, snd_una: %u, iss: %u, fss: %u\nsnd_wnd: %u, "
			"peer_wnd: %u, cwnd: %u, ssthresh: %u\n", 
			stream->snd_nxt, sndvar->snd_una, stream->iss, sndvar->fss, 
			sndvar->snd_wnd, sndvar->peer_wnd, sndvar->cwnd, sndvar->ssthresh);

	if (sndvar->sndbuf) {
		thread_printf(mtcp, mtcp->log_fp, 
				"Send buffer: init_seq: %u, head_seq: %u, "
				"len: %d, cum_len: %lu, size: %d\n", 
				sndvar->sndbuf->init_seq, sndvar->sndbuf->head_seq, 
				sndvar->sndbuf->len, sndvar->sndbuf->cum_len, sndvar->sndbuf->size);
	} else {
		thread_printf(mtcp, mtcp->log_fp, "Send buffer: (null)\n");
	}
	thread_printf(mtcp, mtcp->log_fp, 
			"nrtx: %u, max_nrtx: %u, rto: %u, ts_rto: %u, "
			"ts_lastack_sent: %u\n", sndvar->nrtx, sndvar->max_nrtx, 
			sndvar->rto, sndvar->ts_rto, sndvar->ts_lastack_sent);

	thread_printf(mtcp, mtcp->log_fp, 
			"========== Receive variables ==========\n");
	thread_printf(mtcp, mtcp->log_fp, 
			"rcv_nxt: %u, irs: %u, rcv_wnd: %u, "
			"snd_wl1: %u, snd_wl2: %u\n", 
			stream->rcv_nxt, stream->irs, 
			rcvvar->rcv_wnd, rcvvar->snd_wl1, rcvvar->snd_wl2);
	if (rcvvar->rcvbuf) {
		thread_printf(mtcp, mtcp->log_fp, 
				"Receive buffer: init_seq: %u, head_seq: %u, "
				"merged_len: %d, cum_len: %lu, last_len: %d, size: %d\n", 
				rcvvar->rcvbuf->init_seq, rcvvar->rcvbuf->head_seq, 
				rcvvar->rcvbuf->merged_len, rcvvar->rcvbuf->cum_len, 
				rcvvar->rcvbuf->last_len, rcvvar->rcvbuf->size);
	} else {
		thread_printf(mtcp, mtcp->log_fp, "Receive buffer: (null)\n");
	}
	thread_printf(mtcp, mtcp->log_fp, "last_ack_seq: %u, dup_acks: %u\n", 
			rcvvar->last_ack_seq, rcvvar->dup_acks);
	thread_printf(mtcp, mtcp->log_fp, 
			"ts_recent: %u, ts_lastack_rcvd: %u, ts_last_ts_upd: %u, "
			"ts_tw_expire: %u\n", rcvvar->ts_recent, rcvvar->ts_lastack_rcvd, 
			rcvvar->ts_last_ts_upd, rcvvar->ts_tw_expire);
	thread_printf(mtcp, mtcp->log_fp, 
			"srtt: %u, mdev: %u, mdev_max: %u, rttvar: %u, rtt_seq: %u\n", 
			rcvvar->srtt, rcvvar->mdev, rcvvar->mdev_max, 
			rcvvar->rttvar, rcvvar->rtt_seq);
}
#endif
