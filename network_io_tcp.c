/* network_io_tcp.c: TCP instantiation of the underlying
 * datagram service.
 */

#include <assert.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdlib.h>
#include <alloca.h>
#include "mysock_impl.h"
#include "network_io.h"
#include "network_io_socket.h"


#define MAX_NUM_PENDING_CONNECTIONS 10

typedef ssize_t (*io_func_t)(socket_t sd, void *buf, size_t count);

static int _tcp_io(socket_t, void *, size_t, io_func_t);
static int _tcp_connect(network_context_t *ctx);


/* a few words about using TCP to emulate the underlying datagram
 * service...
 *
 * the STCP/mysocket implementation was designed based on using either UDP
 * or IP (the latter via VNS) as the underlying network layer.  using TCP
 * instead (for reliability during grading) is accomplished as follows:
 *   - each mysocket has a TCP socket over which it reads/writes
 *   - on an STCP SYN, the active side establishes a TCP connection with
 *     the passive side, for the purpose of sending the SYN packet.
 *   - the passive side dispatches the SYN packet to the right STCP
 *     context, and updates the new context's TCP socket to be that of the
 *     newly accepted (real TCP) connection.
 */


/* initialise the network subsystem.  this function should be called before
 * making use of any of the other network layer functions.
 */
int _network_init(mysock_context_t *sock_ctx, network_context_t *net_ctx)
{
    network_context_socket_tcp_t *tcp_io_ctx;
    int rc;

    assert(sock_ctx && net_ctx);
    if ((rc = _network_init_socket(sock_ctx,
                                   net_ctx,
                                   SOCK_STREAM,
                                   sizeof(network_context_socket_tcp_t))) < 0)
        return rc;

    tcp_io_ctx = (network_context_socket_tcp_t *) net_ctx->impl_data;
    assert(tcp_io_ctx);

    tcp_io_ctx->sock_ctx = sock_ctx;
    tcp_io_ctx->new_socket = -1;
    tcp_io_ctx->connected = FALSE;

    PTHREAD_CALL(pthread_mutex_init(&tcp_io_ctx->connect_lock, NULL));

    return 0;
}

void _network_close(network_context_t *ctx)
{
    network_context_socket_tcp_t *tcp_io_ctx;

    assert(ctx);

    tcp_io_ctx = (network_context_socket_tcp_t *) ctx->impl_data;
    assert(tcp_io_ctx);

    if (tcp_io_ctx->new_socket != -1)
    {
        DEBUG_LOG(("closing TCP network layer socket %d...\n",
                   (int) tcp_io_ctx->new_socket));
        closesocket(tcp_io_ctx->new_socket);
    }

    PTHREAD_CALL(pthread_mutex_destroy(&tcp_io_ctx->connect_lock));

    _network_close_socket(ctx);
}

/* set the local port associated with the given network layer context */
int _network_bind(network_context_t *ctx, struct sockaddr *addr, int addrlen)
{
    assert(ctx && addr);
    VERIFY_SOCKET(ctx);

    return _network_bind_socket(ctx, addr, addrlen);
}

int _network_listen(network_context_t *ctx, int backlog)
{
    assert(ctx);
    VERIFY_SOCKET(ctx);

    return listen(GET_SOCKET(ctx), backlog);
}

void _network_update_passive_state(network_context_t *new_ctx,
                                   network_context_t *accept_ctx,
                                   void *user_data,
                                   const void *syn_packet, size_t syn_len)
{
    network_context_socket_tcp_t *new_tcp_ctx;
    network_context_socket_tcp_t *accept_tcp_ctx;

    assert(new_ctx && accept_ctx && syn_packet);
    assert(!user_data);

    new_tcp_ctx = (network_context_socket_tcp_t *) new_ctx->impl_data;
    accept_tcp_ctx = (network_context_socket_tcp_t *) accept_ctx->impl_data;

    assert(new_tcp_ctx && accept_tcp_ctx);

    /* result of accept() in listening socket is used for reading/writing
     * by the new context.
     */
    assert(!new_tcp_ctx->sock_ctx->listening);
    assert(!new_tcp_ctx->sock_ctx->is_active);
    closesocket(new_tcp_ctx->base.socket);
    new_tcp_ctx->base.socket = accept_tcp_ctx->new_socket;
    new_tcp_ctx->connected = TRUE;
    accept_tcp_ctx->new_socket = -1;
    DEBUG_LOG(("passed accepted socket %d on to new context...\n",
               new_tcp_ctx->base.socket));
}


/* send the given packet to the peer */
ssize_t _network_send_packet(network_context_t *ctx,
                             const void *src, size_t len)
{
    network_context_socket_tcp_t *tcp_io_ctx;
    uint16_t packet_len;    /* network byte order */

    assert(ctx && src);
    assert(ctx->peer_addr_len > 0);

    tcp_io_ctx = (network_context_socket_tcp_t *) ctx->impl_data;
    assert(tcp_io_ctx);

    VERIFY_SOCKET(ctx);
    DEBUG_PEER(ctx);

    if (_tcp_connect(ctx) < 0)
        return -1;

    packet_len = htons(len);
    if (_tcp_io(GET_SOCKET(ctx), &packet_len, sizeof(packet_len),
                (io_func_t) write) < 0 ||
        _tcp_io(GET_SOCKET(ctx), (void *) src, len, (io_func_t) write) < 0)
        return -1;

    return len;
}

/* read a packet from the peer */
ssize_t _network_recv_packet(network_context_t *ctx, void *dst, size_t max_len)
{
    network_context_socket_tcp_t *tcp_io_ctx;
    uint16_t packet_len;
    socket_t io_socket;
    int rc;

    assert(ctx && dst);

    tcp_io_ctx = (network_context_socket_tcp_t *) ctx->impl_data;
    assert(tcp_io_ctx);
    assert(tcp_io_ctx->sock_ctx);

    VERIFY_SOCKET(ctx);
    io_socket = tcp_io_ctx->base.socket;

    if (tcp_io_ctx->sock_ctx->is_active && _tcp_connect(ctx) < 0)
        return -1;

    if (tcp_io_ctx->sock_ctx->listening/* ||
        (tcp_io_ctx->sock_ctx->is_active && !tcp_io_ctx->connected)*/)
    {
        socket_t tmp_sd;

        ctx->peer_addr_len = sizeof(ctx->peer_addr);
        if ((tmp_sd = accept(GET_SOCKET(ctx),
                             &ctx->peer_addr,
                             &ctx->peer_addr_len)) < 0)
        {
            perror("accept (network_io_tcp)");
            return tmp_sd;
        }

        DEBUG_LOG(("accepted from peer, tmp_sd=%d...\n", (int) tmp_sd));

        /* keep listening socket open for futher connection requests */
        /* we will not reenter this function until this SYN packet has
         * been dispatched to the right context, and that context's
         * socket updated to be 'new_socket'
         */
        assert(tcp_io_ctx->new_socket == -1);
        tcp_io_ctx->new_socket = tmp_sd;
        io_socket = tmp_sd;
    }

    DEBUG_PEER(ctx);

#ifdef DEBUG
    if (getpeername(io_socket, &ctx->peer_addr, &ctx->peer_addr_len) < 0)
    {
        DEBUG_LOG(("getpeername failed (errno=%d)\n", errno));
        return -1;
    }
#endif

    if ((rc = _tcp_io(io_socket, &packet_len, sizeof(packet_len), read)) <= 0)
    {
        DEBUG_LOG(("couldn't read packet len: %d\n", rc));
        return rc;
    }

    packet_len = ntohs(packet_len);
    if ((rc = _tcp_io(io_socket, dst, MIN(packet_len, max_len), read)) <= 0)
    {
        DEBUG_LOG(("couldn't read packet: %d\n", rc));
        return rc;
    }

    if (packet_len > max_len)
    {
        /* discard unread remainder of packet */
        char *dummy = (char *) alloca(packet_len - max_len);
        (void) _tcp_io(io_socket, dummy, packet_len - max_len, read);
    }

    return packet_len;
}


/* read/write count bytes into/from buf */
static int _tcp_io(socket_t tcp_sd, void *buf, size_t count, io_func_t io_func)
{
    char *cbuf = (char *) buf;
    size_t bytes_remaining;

    assert(buf && io_func);
    for (bytes_remaining = count; bytes_remaining > 0; )
    {
        int rc;

        if ((rc = io_func(tcp_sd, cbuf, bytes_remaining)) <= 0)
        {
            DEBUG_LOG(("_tcp_io rc: %d\n", rc));
            return rc;
        }

        assert(rc <= (int)bytes_remaining);
        bytes_remaining -= rc;
        cbuf += rc;
    }

    return count;
}

static int _tcp_connect(network_context_t *ctx)
{
    network_context_socket_tcp_t *tcp_io_ctx;

    assert(ctx);

    tcp_io_ctx = (network_context_socket_tcp_t *) ctx->impl_data;
    assert(tcp_io_ctx);

    PTHREAD_CALL(pthread_mutex_lock(&tcp_io_ctx->connect_lock));
    if (!tcp_io_ctx->connected)
    {
        assert(ctx->peer_addr_valid);
        assert(ctx->peer_addr.sa_family == AF_INET);
        assert(((struct sockaddr_in *) &ctx->peer_addr)->sin_port > 0);

        DEBUG_LOG(("_tcp_connect (my_sd=%d): connecting on socket %d...\n",
                   tcp_io_ctx->sock_ctx->my_sd, (int)GET_SOCKET(ctx)));
        if ((connect(GET_SOCKET(ctx), &ctx->peer_addr,
                     sizeof(ctx->peer_addr))) < 0)
        {
            perror("connect (_tcp_connect)");
            fprintf(stderr, "(errno=%d)\n", errno);
	    PTHREAD_CALL(pthread_mutex_unlock(&tcp_io_ctx->connect_lock));
            return -1;
        }

        tcp_io_ctx->connected = TRUE;
    }
    PTHREAD_CALL(pthread_mutex_unlock(&tcp_io_ctx->connect_lock));

    return 0;
}

