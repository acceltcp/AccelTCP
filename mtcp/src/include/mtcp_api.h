#ifndef __MTCP_API_H_
#define __MTCP_API_H_

#include <stdint.h>
#include <netinet/in.h>
#include <sys/uio.h>

#ifndef UNUSED
#define UNUSED(x)	(void)x
#endif

#ifndef INPORT_ANY
#define INPORT_ANY	(uint16_t)0
#endif

#ifdef __cplusplus
extern "C" {
#endif

enum socket_type
{
	MTCP_SOCK_UNUSED, 
	MTCP_SOCK_STREAM, 
	MTCP_SOCK_PROXY, 
	MTCP_SOCK_LISTENER, 
	MTCP_SOCK_EPOLL, 
	MTCP_SOCK_PIPE, 
};

struct mtcp_conf
{
	int num_cores;
	int max_concurrency;

	int max_num_buffers;
	int rcvbuf_size;
	int sndbuf_size;

	int tcp_timewait;
	int tcp_timeout;

	struct route_table *rtable;
	int routes;
};

typedef struct mtcp_context *mctx_t;
int 
mtcp_init(const char *config_file);

void 
mtcp_destroy();

int 
mtcp_getconf(struct mtcp_conf *conf);

int 
mtcp_setconf(const struct mtcp_conf *conf);

int 
mtcp_core_affinitize(int cpu);

mctx_t 
mtcp_create_context(int cpu);

#ifdef ENABLE_UCTX
typedef void (*mtcp_app_func_t) (void *); 
int
mtcp_create_app_context(mctx_t mctx, mtcp_app_func_t func, void *arg);

void
mtcp_run_app();
#endif
void 
mtcp_destroy_context(mctx_t mctx);

typedef void (*mtcp_sighandler_t)(int);

mtcp_sighandler_t 
mtcp_register_signal(int signum, mtcp_sighandler_t handler);

int 
mtcp_pipe(mctx_t mctx, int pipeid[2]);

int 
mtcp_getsockopt(mctx_t mctx, int sockid, int level, 
		int optname, void *optval, socklen_t *optlen);

int 
mtcp_setsockopt(mctx_t mctx, int sockid, int level, 
		int optname, const void *optval, socklen_t optlen);

int 
mtcp_setsock_nonblock(mctx_t mctx, int sockid);

/* mtcp_socket_ioctl: similar to ioctl, 
   but only FIONREAD is supported currently */
int 
mtcp_socket_ioctl(mctx_t mctx, int sockid, int request, void *argp);

int 
mtcp_socket(mctx_t mctx, int domain, int type, int protocol);

int 
mtcp_bind(mctx_t mctx, int sockid, 
		const struct sockaddr *addr, socklen_t addrlen);

int 
mtcp_listen(mctx_t mctx, int sockid, int backlog);

int 
mtcp_accept(mctx_t mctx, int sockid, struct sockaddr *addr, socklen_t *addrlen);

int 
mtcp_init_rss(mctx_t mctx, in_addr_t saddr_base, int num_addr, 
		in_addr_t daddr, in_addr_t dport);

int 
mtcp_connect(mctx_t mctx, int sockid, 
		const struct sockaddr *addr, socklen_t addrlen);

int 
mtcp_close(mctx_t mctx, int sockid);

/** Returns the current address to which the socket sockfd is bound
 * @param [in] mctx: mtcp context
 * @param [in] addr: address buffer to be filled
 * @param [in] addrlen: amount of space pointed to by addr
 * @return 0 on success, -1 on error
 */
int
mtcp_getsockname(mctx_t mctx, int sock, struct sockaddr *addr, socklen_t *addrlen);
	
int
mtcp_getpeername(mctx_t mctx, int sockid, struct sockaddr *addr,
		 socklen_t *addrlen);

//inline ssize_t
ssize_t
mtcp_read(mctx_t mctx, int sockid, char *buf, size_t len);

ssize_t
mtcp_recv(mctx_t mctx, int sockid, char *buf, size_t len, int flags);

/* readv should work in atomic */
int
mtcp_readv(mctx_t mctx, int sockid, const struct iovec *iov, int numIOV);

ssize_t
mtcp_write(mctx_t mctx, int sockid, const char *buf, size_t len);

/* writev should work in atomic */
int
mtcp_writev(mctx_t mctx, int sockid, const struct iovec *iov, int numIOV);

#define TCP_SETUP_OFFLOAD 0x10
#define TCP_TEARDOWN_OFFLOAD 0x11

typedef struct nsplice_meta
{
	uint32_t ip_addr;		/* the ip address of client-side spliced connection */
	uint16_t port;			/* the port of client-side spliced connection */
	uint32_t dst_addr;
	uint16_t dst_port;
	uint16_t close_reason;	/* the reason of spliced connection close */
} nsplice_meta_t;
	
typedef void (*callback_t)(nsplice_meta_t *meta);
int
mtcp_splice(mctx_t mctx, int sock_from, int sock_to, callback_t cb);
	
#ifdef __cplusplus
};
#endif

#endif /* __MTCP_API_H_ */
