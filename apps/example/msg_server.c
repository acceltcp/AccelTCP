#define _LARGEFILE64_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <dirent.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include <signal.h>
#include <limits.h>

#include <mtcp_api.h>
#include <mtcp_epoll.h>

#include <numa.h>
#include <sys/stat.h>
#include "util.h"

#define MAX_FLOW_NUM  (10000)

#define RCVBUF_SIZE (8192)
#define SNDBUF_SIZE (8192)
#define BUF_SIZE (8192)

#define MAX_EVENTS (MAX_FLOW_NUM * 3)

#define MAX_CPUS 16

#ifndef TRUE
#define TRUE (1)
#endif

#ifndef FALSE
#define FALSE (0)
#endif

#ifndef ERROR
#define ERROR (-1)
#endif

/*----------------------------------------------------------------------------*/
int mtcp_abort(mctx_t mctx, int sockid);
/*----------------------------------------------------------------------------*/
static int num_cores;
static int core_limit;
static int nic_offload = 0;
static int instant_close = 0;
static int close_by_server = 1;
static pthread_t app_thread[MAX_CPUS];
static int done[MAX_CPUS];
/*----------------------------------------------------------------------------*/
static int g_trans[MAX_CPUS];
static int g_trans_prev;
/*----------------------------------------------------------------------------*/
void 
PrintStats()
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
struct thread_context {
	int cpu;
	mctx_t mctx;
};

void
RunServerContext(void *arg)
{
	mctx_t mctx;
	int cpu;
	struct sockaddr_in saddr;
	int listener;

	int sockid = -1;
	int ep;
	struct mtcp_epoll_event *events;
	struct mtcp_epoll_event ev;
	int maxevents;
	int nevents;
	int i;
	char buf[BUF_SIZE];
	int ret;
	int tot_read;
	int optval = nic_offload;

	int trans, trans_prev;
	struct timeval cur_tv, prev_tv;

	/* parse passed arguments*/
	mctx = ((struct thread_context *) arg)->mctx;
	cpu = ((struct thread_context *) arg)->cpu;

	listener = mtcp_socket(mctx, AF_INET, SOCK_STREAM, 0);
	if (listener < 0) {
		TRACE_ERROR("Failed to create listening socket!\n");
		exit(-1);
	}
	ret = mtcp_setsock_nonblock(mctx, listener);
	if (ret < 0) {
		TRACE_ERROR("Failed to set socket in nonblocking mode.\n");
		exit(-1);
	}
	
	saddr.sin_family = AF_INET;
	saddr.sin_addr.s_addr = INADDR_ANY;
	saddr.sin_port = htons(80);
	
	ret = mtcp_bind(mctx, listener, 
			(struct sockaddr *)&saddr, sizeof(struct sockaddr_in));
	if (ret < 0) {
		TRACE_ERROR("Failed to bind to the listening socket!\n");
		exit(-1);
	}

	ret = mtcp_listen(mctx, listener, 4096);
	if (ret < 0) {
		TRACE_ERROR("mtcp_listen() failed!\n");
		exit(-1);
	}

	ret = mtcp_setsockopt(mctx, listener, IPPROTO_TCP, TCP_SETUP_OFFLOAD,
						  &optval, sizeof(optval));
	if (ret < 0) {
		TRACE_ERROR("Failed to set socket option (TCP_SETUP_OFFLOAD)\n");
		exit(-1);
	}

	maxevents = MAX_FLOW_NUM * 3;
	ep = mtcp_epoll_create(mctx, maxevents);
	if (ep < 0) {
		TRACE_ERROR("Failed to create epoll struct!n");
		exit(EXIT_FAILURE);
	}

	events = (struct mtcp_epoll_event *)
			calloc(maxevents, sizeof(struct mtcp_epoll_event));
	if (!events) {
		TRACE_ERROR("Failed to allocate events!\n");
		exit(EXIT_FAILURE);
	}

	ev.events = MTCP_EPOLLIN;
	ev.data.sockid = listener;
	mtcp_epoll_ctl(mctx, ep, MTCP_EPOLL_CTL_ADD, listener, &ev);

	trans = trans_prev = 0;
	gettimeofday(&cur_tv, NULL);
	prev_tv = cur_tv;

	while (!done[cpu]) {
		
		nevents = mtcp_epoll_wait(mctx, ep, events, maxevents, -1);
		TRACE_APP("mtcp_epoll_wait returned %d events.\n", nevents);
		if (nevents < 0) {
			TRACE_APP("mtcp_epoll_wait failed! ret: %d\n", nevents);
			break;
		}

		int do_accept = FALSE;
		for (i = 0; i < nevents; i++) {
			if (events[i].events & MTCP_EPOLLERR) {
				mtcp_epoll_ctl(mctx, ep, 
						MTCP_EPOLL_CTL_DEL, events[i].data.sockid, 0);

				mtcp_close(mctx, events[i].data.sockid);
				continue;
			}

			
			if (events[i].events & MTCP_EPOLLIN) {
				if (events[i].data.sockid == listener) {
					do_accept = TRUE;
					continue;
				}

				tot_read = 0;
				while ((ret = mtcp_read(mctx, 
								events[i].data.sockid, buf, BUF_SIZE)) > 0) {
					TRACE_APP("Socket %d: Read %d bytes\n", events[i].data.sockid, ret);
					if (ret > 0) {
						tot_read += ret;
					}
				}
				if (ret == 0) {
					mtcp_epoll_ctl(mctx, ep, 
							MTCP_EPOLL_CTL_DEL, events[i].data.sockid, 0);
					if (instant_close) {
						mtcp_abort(mctx, events[i].data.sockid);
					} else {
						mtcp_close(mctx, events[i].data.sockid);
					}
				} else if (ret < 0 && errno != EAGAIN) {
					TRACE_ERROR("mtcp_read() error: %d\n", errno);
					if (instant_close) {
						mtcp_abort(mctx, events[i].data.sockid);
					} else {
						mtcp_close(mctx, events[i].data.sockid);
					}
				}

				if (tot_read > 0) {
					trans++;
					g_trans[cpu]++;
					ret = mtcp_write(mctx, 
							events[i].data.sockid, buf, tot_read);
					TRACE_APP("Socket %d: Write %d bytes\n", 
							events[i].data.sockid, ret);
					if (close_by_server && ret == tot_read) {
						if (instant_close) {
							mtcp_abort(mctx, events[i].data.sockid);
						} else {
							mtcp_close(mctx, events[i].data.sockid);
						}
					}
				}
			}

		}
		if (do_accept) {
			while (1) {
				sockid = mtcp_accept(mctx, listener, NULL, NULL);
				if (sockid >= 0) {
					TRACE_APP("New connection %d accepted.\n", sockid);
					ev.events = MTCP_EPOLLIN;
					ev.data.sockid = sockid;
					mtcp_setsock_nonblock(mctx, sockid);
					mtcp_epoll_ctl(mctx, ep, 
							MTCP_EPOLL_CTL_ADD, sockid, &ev);

					ret = mtcp_setsockopt(mctx, sockid, IPPROTO_TCP, TCP_TEARDOWN_OFFLOAD,
										  &optval, sizeof(optval));
					if (ret < 0) {
						TRACE_ERROR("Failed to set socket option (TCP_TEARDOWN_OFFLOAD)\n");
						exit(-1);
					}
					
				} else {
					if (errno != EAGAIN) {
						TRACE_ERROR("mtcp_accept() error %s\n", 
								strerror(errno));
					}
					break;
				}
			}
		}

		if (cpu == 0) {
			gettimeofday(&cur_tv, NULL);
			if (cur_tv.tv_sec > prev_tv.tv_sec) {
				PrintStats();
				prev_tv = cur_tv;
			}
		}
	}

	mtcp_destroy_context(mctx);
	pthread_exit(NULL);
}
/*****************************************************************************/
void *
RunServerThread(void *arg)
{
	mctx_t mctx;
	struct thread_context ctx;
	int cpu;

	/* Initialization */
	cpu = *(int *) arg;
	mtcp_core_affinitize(cpu);

	mctx = mtcp_create_context(cpu);
	if (!mctx) {
		TRACE_ERROR("Failed to create mtcp context!\n");
		exit(EXIT_FAILURE);
	}

	ctx.cpu = cpu;
	ctx.mctx = mctx;

#ifdef ENABLE_UCTX
	mtcp_create_app_context(mctx, (mtcp_app_func_t) RunServerContext, (void *) &ctx);	
	mtcp_run_app();	
#else
	RunServerContext(&ctx);
#endif

	/* destroy mtcp context: this will kill the mtcp thread */
	mtcp_destroy_context(mctx);
	pthread_exit(NULL);
	
	return NULL;
}
/*----------------------------------------------------------------------------*/
void
sigint_handler(int signum)
{
	int i;

	for (i = 0; i < core_limit; i++) {
		if (app_thread[i] == pthread_self()) {
			//TRACE_INFO("Server thread %d got SIGINT\n", i);
			done[i] = TRUE;
		} else {
			if (!done[i]) {
				pthread_kill(app_thread[i], signum);
			}
		}
	}
}
/*----------------------------------------------------------------------------*/
int 
main(int argc, char **argv)
{
	struct mtcp_conf mcfg;
	int cpus[MAX_CPUS];
	int ret;
	int i;

	for (i = 1; i < argc; i++) {
		if (strcmp(argv[i], "--conn-reset") == 0) {
			instant_close = 1;
		}
		if (strcmp(argv[i], "--client-close") == 0) {
			close_by_server = 0;
		}		
		if (strcmp(argv[i], "--nic-offload") == 0) {
			nic_offload = 1;
		}
	}

	num_cores = sysconf(_SC_NPROCESSORS_ONLN);
	core_limit = num_cores;

	for (i = 1; i < argc - 1; i++) {
		if (strcmp(argv[i], "-c") == 0) {
			core_limit = mystrtol(argv[i + 1], 10);
		}
	}

	if (core_limit > num_cores || core_limit < 1) {
		printf("core limit should be in range (1 - %d).\n", num_cores);
		return FALSE;
	}

	mtcp_getconf(&mcfg);
	mcfg.num_cores = core_limit;
	mtcp_setconf(&mcfg);

	printf("Configurations:\n");
	printf("Number of cores: %d\n", core_limit);
	printf("Instant close: %d\n", instant_close);

	ret = mtcp_init("config/mtcp.conf");
	if (ret) {
		TRACE_ERROR("Failed to initialize mtcp\n");
		exit(EXIT_FAILURE);
	}

	mtcp_getconf(&mcfg);
	mcfg.num_cores = core_limit;
	mtcp_setconf(&mcfg);

	mtcp_register_signal(SIGINT, sigint_handler);

	TRACE_INFO("Application initialization finished.\n");

	for (i = 0; i < core_limit; i++) {
		cpus[i] = i;
		done[i] = FALSE;

		if (pthread_create(&app_thread[i], 
					NULL, RunServerThread, (void *)&cpus[i])) {
			perror("pthread_create");
			TRACE_ERROR("Failed to create server thread.\n");
			exit(-1);
		}
	}

	for (i = 0; i < core_limit; i++) {
		pthread_join(app_thread[i], NULL);
	}

	mtcp_destroy();
	return 0;
}
