/* private definitions shared amongst the underlying network I/O libraries.
 * these are used only by the network I/O layer; they are not intended
 * for higher layer use.
 */

#ifndef __NETWORK_IO_SOCKET_H__
#define __NETWORK_IO_SOCKET_H__

#include <assert.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "mysock.h"
#include "mysock_impl.h"
#include "network_io.h"

typedef int socket_t;

/* socket-based network layer additional state.
 * this is pointed to by impl_data in the network_context_t structure.
 */
typedef struct
{
    pthread_t          recv_thread;
    bool_t             recv_thread_started;

    socket_t           socket;  /* socket used for communication to peer */
    int                exit_pipe[2];    /* used to wake up read thread */
} network_context_socket_t;

typedef struct
{
    network_context_socket_t base;

    /* additional state required by TCP-based network layer */
    mysock_context_t *sock_ctx;
    socket_t          new_socket;   /* temporary result of accept() */
    pthread_mutex_t   connect_lock;
    bool_t            connected;
} network_context_socket_tcp_t;


#define closesocket(s) close(s)

#define GET_SOCKET(ctx) ((network_context_socket_t *) ctx->impl_data)->socket
#define VERIFY_SOCKET(ctx) assert(ctx->impl_data && GET_SOCKET(ctx) >= 0)

#ifdef __GNUC__
#define DEBUG_PEER(ctx) \
    DEBUG_LOG(("%s peer:  %s:%d\n", __FUNCTION__, \
              inet_ntoa(((struct sockaddr_in *) &ctx->peer_addr)->sin_addr), \
              (int) ntohs(((struct sockaddr_in *) &ctx->peer_addr)->sin_port)))
#else
#define DEBUG_PEER(ctx)
#endif


int _network_init_socket(mysock_context_t  *sock_ctx,
                         network_context_t *net_ctx,
                         int                type,
                         size_t             ctx_len);

void _network_close_socket(network_context_t *net_ctx);

int _network_bind_socket(network_context_t *ctx,
                         struct sockaddr   *addr,
                         int                addrlen);


/* this is not called directly.  use network_start_recv_thread() and
 * network_stop_recv_thread() instead.
 */
ssize_t _network_recv_packet(network_context_t *ctx,
                             void *dst, size_t max_len);


#endif  /* __NETWORK_IO_SOCKET_H__ */

