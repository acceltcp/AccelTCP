#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <time.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/queue.h>
#include <assert.h>
#include <limits.h>

#include <mtcp_api.h>
#include <mtcp_epoll.h>

#include <numa.h>
#include <sys/stat.h>
#include "util.h"

#ifndef TRUE
#define TRUE (1)
#endif

#ifndef FALSE
#define FALSE (0)
#endif

#ifndef ERROR
#define ERROR (-1)
#endif

#define MAX_FLOW_NUM (100000)

#define RCVBUF_SIZE (8192)
#define SNDBUF_SIZE (8192)
#define BUF_SIZE (8192)

#define MAX_CPUS 16

#define IP_RANGE 1
#define MAX_IP_STR 32
#define MIN_PORT_NO 1025
#define MAX_PORT_NO 65535
#define IP_PRINT_MASK 0xFF

#define CONN_AT_ONCE 16
/* this controls the connection rate for stability */
#define RATE_CONTROL FALSE
/* this decides whether to print connection stats */
#define PRINT_STAT   FALSE

#define TIMEVAL_TO_MSEC(t)		((t.tv_sec * 1000) + (t.tv_usec / 1000))
#define TIMEVAL_TO_USEC(t)		((t.tv_sec * 1000000) + (t.tv_usec))
#define TIMEVAL_DIFF(t2, t1)	((t2.tv_sec - t1.tv_sec) * 1000000 + t2.tv_usec - t1.tv_usec)
#define TS_GT(a,b)				((int64_t)((a)-(b)) > 0)

/*----------------------------------------------------------------------------*/
int mtcp_abort(mctx_t mctx, int sockid);
/*----------------------------------------------------------------------------*/
static pthread_t app_thread[MAX_CPUS];
static mctx_t g_mctx[MAX_CPUS];
static int done[MAX_CPUS];
/*----------------------------------------------------------------------------*/
static int num_cores;
static int core_limit;
/*----------------------------------------------------------------------------*/
static char host[MAX_IP_STR + 1];
static in_addr_t daddr;
static in_port_t dport;
static in_addr_t saddr;
/*----------------------------------------------------------------------------*/
static int max_pending = 512;
static int message_size = 64;
static int num_messages = 1;
static int instant_close = 0;
/*----------------------------------------------------------------------------*/
static int g_trans[MAX_CPUS];
static int g_trans_prev;
/*----------------------------------------------------------------------------*/
void
PrintTransactions()
{
	int total_trans;
	int i;

	total_trans = 0;
	for (i = 0; i < num_cores; i++) {
		total_trans += g_trans[i];
	}
	fprintf(stdout, "[ALL] Transactions/s: %d\n", total_trans - g_trans_prev);
	fflush(stdout);
	g_trans_prev = total_trans;
}
/*----------------------------------------------------------------------------*/
struct thread_context
{
	int core;

	mctx_t mctx;
	int ep;
};
typedef struct thread_context* thread_context_t;
/*----------------------------------------------------------------------------*/
thread_context_t 
CreateContext(int core)
{
	thread_context_t ctx;

	ctx = (thread_context_t)malloc(sizeof(struct thread_context));
	if (!ctx) {
		perror("malloc");
		TRACE_ERROR("Failed to allocate memory for thread context.\n");
		return NULL;
	}
	ctx->core = core;

	ctx->mctx = mtcp_create_context(core);
	if (!ctx->mctx) {
		TRACE_ERROR("Failed to create mtcp context.\n");
		return NULL;
	}
	g_mctx[core] = ctx->mctx;

	return ctx;
}
/*----------------------------------------------------------------------------*/
inline int 
CreateConnection(thread_context_t ctx)
{
	mctx_t mctx = ctx->mctx;
	struct mtcp_epoll_event ev;
	struct sockaddr_in addr;
	int sockid;
	int ret;

	sockid = mtcp_socket(mctx, AF_INET, SOCK_STREAM, 0);
	if (sockid < 0) {
		TRACE_INFO("Failed to create socket!\n");
		return -1;
	}
	ret = mtcp_setsock_nonblock(mctx, sockid);
	if (ret < 0) {
		TRACE_ERROR("Failed to set socket in nonblocking mode.\n");
		exit(-1);
	}

	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = daddr;
	addr.sin_port = dport;

	ret = mtcp_connect(mctx, sockid, 
			(struct sockaddr *)&addr, sizeof(struct sockaddr_in));
	if (ret < 0) {
		if (errno != EINPROGRESS) {
			TRACE_INFO("Connection failed.\n");
			return -1;
		}
	}

	TRACE_APP("Connecting stream %d\n", sockid);

	ev.events = MTCP_EPOLLIN | MTCP_EPOLLOUT | MTCP_EPOLLET;
	ev.data.sockid = sockid;
	mtcp_epoll_ctl(mctx, ctx->ep, MTCP_EPOLL_CTL_ADD, sockid, &ev);

	return sockid;
}
/*----------------------------------------------------------------------------*/
void
RunMsgTestContext(void *arg)
{
	thread_context_t ctx;
	mctx_t mctx;
	int core;
	int n = MAX_FLOW_NUM;			/* number of concurrent flows */
	int ep;
	struct mtcp_epoll_event *events;
	int nevents;
	int maxevents;
	int i;

	int conn_once;
	int conn, conn_prev;
	int completes, completes_prev;
#if PRINT_STAT
	int epoll_calls = 0, epoll_calls_prev = 0;
	int epoll_events = 0, epoll_events_prev = 0;
	struct timeval tv_before_wait, tv_after_wait;
	int64_t time_inside_wait, time_outside_wait;
	int64_t sum_inside_wait, sum_outside_wait;
	int64_t cnt_inside_wait, cnt_outside_wait;
#endif
	struct timeval cur_tv, prev_tv;
	uint64_t cur_ts, prev_ts;
	uint64_t last_epoll_ts;

	int conn_at_once = CONN_AT_ONCE;
	char buf[BUF_SIZE];
	int ret;

#if RATE_CONTROL
	int pending;
#endif
	ctx = (thread_context_t) arg;
	mctx = ctx->mctx;
	core = ctx->core;

	/* build address pool */
	mtcp_init_rss(mctx, saddr, IP_RANGE, daddr, dport);

	/* Initialization */
	maxevents = n * 3;
	ep = mtcp_epoll_create(mctx, maxevents);
	if (ep < 0) {
		TRACE_ERROR("Failed to create epoll struct!\n");
		exit(EXIT_FAILURE);
	}
	ctx->ep = ep;
	events = (struct mtcp_epoll_event *)
			calloc(maxevents, sizeof(struct mtcp_epoll_event));
	if (!events) {
		TRACE_ERROR("Failed to allocate events!\n");
		exit(EXIT_FAILURE);
	}
	
	conn = conn_prev = 0;
	completes = completes_prev = 0;

	gettimeofday(&cur_tv, NULL);
	prev_tv = cur_tv;
	cur_ts = prev_ts = last_epoll_ts = TIMEVAL_TO_USEC(cur_tv);
#if PRINT_STAT
	cnt_inside_wait = cnt_outside_wait = 0;
	sum_inside_wait = sum_outside_wait = 0;
#endif

	while (!done[core]) {
		gettimeofday(&cur_tv, NULL);
		cur_ts = TIMEVAL_TO_USEC(cur_tv);
		if (TS_GT(cur_ts, prev_ts + 10)) {
			prev_ts = cur_ts;
			conn_once = 0;
			while (conn - completes < max_pending && conn_once < conn_at_once) {

				ret = CreateConnection(ctx);
				if (ret < 0) {
					break;
				}

				conn++;
				conn_once++;
			}
		}

#if RATE_CONTROL
		/* connection rate control */
		pending = conn - completes;
		if (pending >= max_pending) {
			conn_at_once = 0;
		} else 	if (pending >= max_pending / 2) {
			conn_at_once = CONN_AT_ONCE / 2;
		} else if (pending < max_pending / 2) {
			conn_at_once = CONN_AT_ONCE;
		}
#endif

#if 1
		if (conn == completes) {
			usleep(1000);
			continue;
		}
#endif

#if PRINT_STAT
		gettimeofday(&tv_before_wait, NULL);
		/* calculate time outside the wait by tv_before_wait - tv_after_wait */
		time_outside_wait = TIMEVAL_DIFF(tv_before_wait, tv_after_wait);
		cnt_outside_wait++;
		sum_outside_wait += time_outside_wait;
#endif
		nevents = mtcp_epoll_wait(mctx, ep, events, maxevents, 10);
#if PRINT_STAT
		gettimeofday(&tv_after_wait, NULL);
		time_inside_wait = TIMEVAL_DIFF(tv_after_wait, tv_before_wait);
		cnt_inside_wait++;
		sum_inside_wait += time_inside_wait;
		epoll_calls++;
#endif

#if 0
		/* alarm if waiting time is more than 1 ms */
		if (TS_GT(cur_ts, last_epoll_ts + 1000)) {
			fprintf(stderr, "[CPU%2d] Inter-epoll_wait() delay over 1 ms: %lu us\n", 
					core, cur_ts - last_epoll_ts);
		}
#endif
		last_epoll_ts = cur_ts;
			
		if (nevents < 0) {
			TRACE_ERROR("mtcp_epoll_wait failed! ret: %d\n", nevents);
			break;
		} else {
#if PRINT_STAT
			epoll_events += nevents;
#endif
		}

		for (i = 0; i < nevents; i++) {

			if (events[i].events == MTCP_EPOLLOUT) {
				TRACE_APP("Established for stream %d\n", events[i].data.sockid);
				buf[0] = 1;
				buf[1] = 0;
				mtcp_write(mctx, events[i].data.sockid, buf, message_size);

			} else if (events[i].events == MTCP_EPOLLIN) {
				ret = mtcp_read(mctx, events[i].data.sockid, buf, BUF_SIZE);
				if (ret < 0 && errno != EAGAIN) {
					TRACE_INFO("Socket %d: mtcp_read() error: %s.\n", 
							events[i].data.sockid, strerror(errno));
					if (instant_close) {
						mtcp_abort(mctx, events[i].data.sockid);
					} else {
						mtcp_close(mctx, events[i].data.sockid);
					}
				} else if (ret == 0) {
					TRACE_INFO("Socket %d: connection closed "
							"by remote host.\n", events[i].data.sockid);
					
					if (instant_close) {
						mtcp_abort(mctx, events[i].data.sockid);
					} else {
						mtcp_close(mctx, events[i].data.sockid);
					}
				} else {
					assert(ret == message_size);
					g_trans[core]++;	
					if ((buf[0] + 128 * buf[1]) < num_messages) {
						if (buf[0] == 127){
							buf[0] = 0;
							buf[1]++;
						}
						else
							buf[0]++;
						mtcp_write(mctx, 
								events[i].data.sockid, buf, message_size);

					} else {
						completes++;
						mtcp_epoll_ctl(mctx, ep, MTCP_EPOLL_CTL_DEL, 
								events[i].data.sockid, NULL);
						
						if (instant_close) {
							mtcp_abort(mctx, events[i].data.sockid);
						} else {
							mtcp_close(mctx, events[i].data.sockid);
						}
					}
				}
			} else {
				TRACE_INFO("Stream %d: event: %s\n", events[i].data.sockid, 
						EventToString(events[i].events));
			}
		}

		if (cur_tv.tv_sec > prev_tv.tv_sec) {
			if (core == 0) {
				PrintTransactions();
			}
#if PRINT_STAT
			int epoll_calls_df = epoll_calls - epoll_calls_prev;
			int epoll_events_df = epoll_events - epoll_events_prev;

			fprintf(stderr, "[CPU%2d] Created: %6d, Completed: %6d, "
					"Epoll calls: %5d, events: %5d (events/call: %d)\n", core, 
					conn - conn_prev, completes - completes_prev, 
					epoll_calls_df, epoll_events_df, (epoll_events_df / epoll_calls_df));
#if 0
			fprintf(stderr, "[CPU%2d] time_inside_wait: %lu us (cnt: %lu), "
					"time_outside_wait: %lu us (cnt: %lu)\n", 
					core, sum_inside_wait, cnt_inside_wait, 
					sum_outside_wait, cnt_outside_wait);
#endif
			epoll_calls_prev = epoll_calls;
			epoll_events_prev = epoll_events;

			cnt_inside_wait = cnt_outside_wait = 0;
			sum_inside_wait = sum_outside_wait = 0;
#endif
			conn_prev = conn;
			completes_prev = completes;
			prev_tv = cur_tv;
		}
	}

	TRACE_DBG("Application thread %d out of loop.\n", core);
	mtcp_destroy_context(mctx);

	TRACE_DBG("Application thread %d finished.\n", core);
	pthread_exit(NULL);
}
/*----------------------------------------------------------------------------*/
void *
RunMsgTest(void *arg)
{
	int core;
	thread_context_t ctx;

	core = *(int *) arg;	
	mtcp_core_affinitize(core);

	/* initialization */
	ctx = CreateContext(core);
	if (!ctx) {
		return NULL;
	}

#ifdef ENABLE_UCTX
	mtcp_create_app_context(ctx->mctx, (mtcp_app_func_t) RunMsgTestContext, (void *) ctx);	
	mtcp_run_app();
#else
	RunMsgTestContext(ctx);
#endif
	
	/* destroy mtcp context: this will kill the mtcp thread */
	mtcp_destroy_context(ctx->mctx);
	pthread_exit(NULL);
	
	return NULL;
}
/*----------------------------------------------------------------------------*/
void sigint_handler(int signum)
{
	int i;

	for (i = 0; i < core_limit; i++) {
		done[i] = TRUE;
	}
}
/*----------------------------------------------------------------------------*/
int 
main(int argc, char **argv)
{
	struct mtcp_conf mcfg;
	int cores[MAX_CPUS];
	int ret;
	int i;

	if (argc < 2) {
		TRACE_CONFIG("Too few arguments!\n");
		TRACE_CONFIG("Usage: %s server_ip [-c # cores] [-s message_size] "
				"[-n # messages (per connection) [-p # pending]\n", argv[0]);
		return FALSE;
	}

	if (strlen(argv[1]) > MAX_IP_STR) {
		TRACE_CONFIG("Too long server IP!\n");
		return FALSE;
	}

	strncpy(host, argv[1], MAX_IP_STR);
	daddr = inet_addr(host);
	dport = htons(80);
	saddr = INADDR_ANY;

	num_cores = sysconf(_SC_NPROCESSORS_ONLN);
	core_limit = num_cores;
	for (i = 2; i < argc - 1; i++) {
		if (strcmp(argv[i], "-c") == 0) {
			core_limit = mystrtol(argv[i + 1], 10);
		} else if (strcmp(argv[i], "-s") == 0) {
			message_size = mystrtol(argv[i + 1], 10);
		} else if (strcmp(argv[i], "-n") == 0) {
			num_messages = mystrtol(argv[i + 1], 10);
		} else if (strcmp(argv[i], "-p") == 0) {
			max_pending = mystrtol(argv[i + 1], 10);
		}
	}
	for (i = 1; i < argc; i++) {
		if (strcmp(argv[i], "--conn-reset") == 0) {
			instant_close = 1;
		}
	}

	if (core_limit > num_cores || core_limit < 1) {
		TRACE_CONFIG("core limit should be in range (1 - %d).\n", num_cores);
		return FALSE;
	}

	TRACE_CONFIG("Application configuration:\n");
	TRACE_CONFIG("Destination: %s\n", host);
	TRACE_CONFIG("Number of cores: %d\n", core_limit);
	TRACE_CONFIG("Number of messages per connection: %d\n", num_messages);
	TRACE_CONFIG("Message size: %d\n", message_size);
	TRACE_CONFIG("Max pending connections: %d\n", max_pending);

	ret = mtcp_init("config/mtcp.conf");
	if (ret) {
		TRACE_ERROR("Failed to initialize mtcp.\n");
		exit(EXIT_FAILURE);
	}
	mtcp_getconf(&mcfg);
	mcfg.max_concurrency = mcfg.max_num_buffers = MAX_FLOW_NUM;
	mcfg.rcvbuf_size = RCVBUF_SIZE;
	mcfg.sndbuf_size = SNDBUF_SIZE;
	mtcp_setconf(&mcfg);
	mtcp_register_signal(SIGINT, sigint_handler);

	for (i = 0; i < core_limit; i++) {
		cores[i] = i;
		done[i] = FALSE;

		if (pthread_create(&app_thread[i], 
					NULL, RunMsgTest, (void *)&cores[i])) {
			perror("pthread_create");
			TRACE_ERROR("Failed to create msg_test thread.\n");
			exit(-1);
		}
	}

	for (i = 0; i < core_limit; i++) {
		pthread_join(app_thread[i], NULL);
		TRACE_INFO("Message test thread %d joined.\n", i);
	}

	mtcp_destroy();
	return 0;
}
/*----------------------------------------------------------------------------*/
