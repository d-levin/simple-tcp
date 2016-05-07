/* routines shared amongst TCP/UDP versions of the network layer */

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>
#include <unistd.h>
#include <poll.h>
#include <assert.h>
#include "mysock_impl.h"
#include "network_io.h"
#include "network_io_socket.h"
#include "connection_demux.h"

#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>



#define EXIT_PIPE_READ_INDEX  0
#define EXIT_PIPE_WRITE_INDEX 1

#ifndef MAXHOSTNAMELEN
#ifdef HOST_NAME_MAX
#define MAXHOSTNAMELEN HOST_NAME_MAX
#else
#define MAXHOSTNAMELEN 256
#endif
#endif  /*!MAXHOSTNAMELEN*/


static network_context_socket_t *
    _network_alloc_context_socket(int socket_type, size_t ctx_len);
static void _network_destroy_context_socket(network_context_socket_t *ctx);
static void *network_recv_thread_func(void *arg_ptr);



/* clean up the network subsystem */
void _network_close_socket(network_context_t *ctx)
{
    assert(ctx);

    _network_destroy_context_socket(
        (network_context_socket_t *) ctx->impl_data);
    ctx->impl_data = 0;
}

/* return the local port associated with the given network layer context, in
 * network byte order, or 0 (reserved) on error.
 */
int _network_get_port(network_context_t *ctx)
{
    struct sockaddr_in sin;
    socklen_t sin_len = sizeof(sin);

    assert(ctx);
    VERIFY_SOCKET(ctx);

    if (getsockname(GET_SOCKET(ctx), (struct sockaddr *) &sin, &sin_len) < 0)
    {
        assert(0);
        return 0;
    }

    assert(sin.sin_family == AF_INET);
    return sin.sin_port;
}

/* return the address associated with the interface over which packets
 * to/from the given peer (network byte order) are delivered.  this is
 * completely broken for multi-homed hosts; it should consult the local
 * routing table in that case.
 */
uint32_t _network_get_interface_ip(uint32_t peer_addr)
{
    char hostname[MAXHOSTNAMELEN+1];
    struct hostent *h, result;
    int err_rc;
    char buf[512];

    if (gethostname(hostname, sizeof(hostname)) < 0)
    {
        perror("gethostname");
        assert(0);
        return 0;
    }

#if defined(SOLARIS)
    if (!(h = gethostbyname_r(hostname, &result, buf, sizeof(buf), &err_rc)))
#elif defined(LINUX)
    if (gethostbyname_r(hostname, &result, buf, sizeof(buf), &h, &err_rc))
#else
#error needs implementing
#endif
    {
        perror("gethostbyname_r");
        assert(0);
        return 0;
    }

    /* Solaris sometimes sets errno=EINVAL even on a successful return
     * from gethostbyname_r...
     */
    errno = 0;
    assert(h == &result);
    return ((struct in_addr *) *h->h_addr_list)->s_addr;
}

int _network_start_recv_thread(mysock_context_t *ctx)
{
    network_context_socket_t *net_ctx =
        (network_context_socket_t *) ctx->network_state.impl_data;

    assert(net_ctx);

    if (signal(SIGPIPE, SIG_IGN) == SIG_ERR)
    {
        perror("signal(SIGPIPE)");
        assert(0);
        return -1;
    }

    net_ctx->recv_thread = _mysock_create_thread(network_recv_thread_func,
                                                 ctx, FALSE);
    net_ctx->recv_thread_started = TRUE;
    return 0;
}

/* block until the network receive thread completes */
void _network_stop_recv_thread(mysock_context_t *ctx)
{
    network_context_socket_t *net_ctx =
        (network_context_socket_t *) ctx->network_state.impl_data;

    DEBUG_LOG(("stopping receive thread\n"));
    assert(net_ctx);


    if (net_ctx->recv_thread_started)
    {
        char dummy = 'X';
        if (write(net_ctx->exit_pipe[EXIT_PIPE_WRITE_INDEX],
                  &dummy, sizeof(dummy)) < 0)
        {
            assert(0);
            abort();
        }


        PTHREAD_CALL(pthread_join(net_ctx->recv_thread, NULL));
        net_ctx->recv_thread_started = FALSE;
    }
    DEBUG_LOG(("stopped receive thread\n"));
}


/* initialise the network subsystem.  this function should be called before
 * making use of any of the other network layer functions.
 */
int _network_init_socket(mysock_context_t  *sock_ctx,
                         network_context_t *net_ctx,
                         int                type,
                         size_t             ctx_len)
{
    assert(sock_ctx && net_ctx);
    assert(ctx_len >= sizeof(network_context_socket_t));

    memset(net_ctx, 0, sizeof(*net_ctx));
    net_ctx->random_seed = 0x632a;

    if (!(net_ctx->impl_data = _network_alloc_context_socket(type, ctx_len)))
    {
        assert(0);
        return -1;
    }

    return 0;
}

/* set the local port associated with the given network layer context */
int _network_bind_socket(network_context_t *ctx,
                         struct sockaddr   *addr,
                         int                addrlen)
{
    assert(ctx && addr);
    VERIFY_SOCKET(ctx);
    return bind(GET_SOCKET(ctx), addr, addrlen);
}


/* process network input.
 * this just loops around, waiting for data to arrive, and buffering it
 * for later consumption by network_recv().  (outgoing data is sent
 * immediately via network_send(), and so does not require its own thread).
 * 
 * this runs in its own thread, mostly because the transport layer needs to
 * wait with a timeout for incoming data from the peer.  [usual mechanisms
 * for I/O with timeouts such as poll(), select(), or asynchronous I/O
 * don't work with all underlying I/O mechanisms we might support (e.g.
 * VNS).  so we implement the timeout in a more generic (I/O-independent)
 * manner using the pthreads API instead].
 */
static void *network_recv_thread_func(void *arg_ptr)
{
    char packet_buf[MAX_IP_PAYLOAD_LEN];
    mysock_context_t *ctx;
    network_context_socket_t *net_ctx;

    DEBUG_LOG(("started receive thread\n"));
    ctx = (mysock_context_t *) arg_ptr;
    assert(ctx);

    net_ctx = (network_context_socket_t *) ctx->network_state.impl_data;
    assert(net_ctx);

    for (;;)
    {
        ssize_t bytes_read;
        bool_t packet_ready = FALSE;
        bool_t done = FALSE;
        struct pollfd fds[] =
        {
            { net_ctx->exit_pipe[EXIT_PIPE_READ_INDEX], POLLIN, 0 },
            { net_ctx->socket, POLLIN, 0 }
        };


        while (!packet_ready && !done)
        {
            switch (poll(fds, sizeof(fds) / sizeof(fds[0]), -1))
            {
            case -1:
                assert(errno == EINTR);
                break;

            case 0:
                assert(0);
                break;

            default:
                assert(!(fds[0].revents & POLLERR));
                assert(!(fds[1].revents & POLLERR));

                if (fds[0].revents)
                    done = TRUE;
                if (fds[1].revents)
                    packet_ready = TRUE;
                break;
            }
        }

        if (done)
            break;

        /* block, waiting for network input.  (the system call will be
         * interrupted by the transport layer thread if we're to exit).
         */
        if ((bytes_read = _network_recv_packet(&ctx->network_state,
                                               packet_buf,
                                               sizeof(packet_buf))) <= 0)
        {
            DEBUG_LOG(("_network_recv_packet interrupted, errno=%d\n", errno));
            //signal an error to the transport layer
            _mysock_enqueue_buffer(ctx, &ctx->network_recv_queue, NULL, 0);
            break;
        }

        assert(bytes_read <= (int)sizeof(packet_buf));
        if (ctx->listening)
        {
            /* if the socket was accepting new connections, incoming
             * packets need to be demultiplexed and dispatched to the
             * appropriate mysocket context.
             */
            _mysock_enqueue_connection(ctx, packet_buf, bytes_read,
                                       &ctx->network_state.peer_addr,
                                       ctx->network_state.peer_addr_len, NULL);
        }
        else
        {
            /* enqueue the packet directly for this context */
            _mysock_enqueue_buffer(ctx, &ctx->network_recv_queue,
                                   packet_buf, bytes_read);
        }
    }

    return NULL;
}

static network_context_socket_t *
_network_alloc_context_socket(int socket_type, size_t ctx_len)
{
    network_context_socket_t *ctx =
        (network_context_socket_t *) calloc(1, ctx_len);

    assert(ctx);


    /* create the actual socket used for communication to the peer */
    if ((ctx->socket = socket(AF_INET, socket_type, 0)) < 0)
    {
        perror("socket");
        assert(0);
        _network_destroy_context_socket(ctx);
        ctx = NULL;
    }

    ctx->exit_pipe[0] = ctx->exit_pipe[1] = -1;
    if (pipe(ctx->exit_pipe) < 0)
    {
        perror("pipe");
        assert(0);
        _network_destroy_context_socket(ctx);
        ctx = NULL;
    }

    return ctx;
}

static void _network_destroy_context_socket(network_context_socket_t *ctx)
{
    assert(ctx);
    if (ctx->socket >= 0)
    {
        DEBUG_LOG(("socket network layer, closing socket %d\n",
                   (int) ctx->socket));
        closesocket(ctx->socket);
        ctx->socket = -1;
    }

    if (ctx->exit_pipe[0] >= 0)
    {
        close(ctx->exit_pipe[0]);
        ctx->exit_pipe[0] = -1;
    }

    if (ctx->exit_pipe[1] >= 0)
    {
        close(ctx->exit_pipe[1]);
        ctx->exit_pipe[1] = -1;
    }

    free(ctx);
}


