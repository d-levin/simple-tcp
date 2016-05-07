/* mysock_api.c--application interface to the mysocket layer */

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "mysock.h"
#include "mysock_impl.h"
#include "network_io.h"
#include "connection_demux.h"


/* MYSOCK_CHECK(cond,rc) checks that 'cond' is true; if it isn't, error
 * 'rc' is indicated to the caller.
 */
#define MYSOCK_ERROR_EXIT(rc) { errno = rc; return -1; }
#define MYSOCK_CHECK(cond,rc)   { if (!(cond)) MYSOCK_ERROR_EXIT(rc); }


/* create a new mysocket; returns the corresponding mysocket descriptor */
mysocket_t mysocket()
{
    return _mysock_new_mysocket();
}

/* simply a wrapper around bind() */
int mybind(mysocket_t sd, struct sockaddr *addr, int addrlen)
{
    mysock_context_t *ctx = _mysock_get_context(sd);
    assert(addr);

    MYSOCK_CHECK(ctx != NULL, EBADF);
    MYSOCK_CHECK(addr->sa_family == AF_INET, EADDRNOTAVAIL);

    /* mybind() must precede mylisten() */
    assert(!ctx->listening);
    ctx->bound = TRUE;
    ctx->network_state.local_addr = *addr;
    return _network_bind(&ctx->network_state, addr, addrlen);
}

/* connect to the address specified in name on the mysocket sd */
int myconnect(mysocket_t sd, struct sockaddr *name, int namelen)
{
    mysock_context_t *ctx = _mysock_get_context(sd);

    MYSOCK_CHECK(ctx != NULL, EINVAL);
    MYSOCK_CHECK((ctx->network_state.peer_addr_len == 0), EISCONN);

#ifdef DEBUG
    struct sockaddr_in *sin = (struct sockaddr_in *) name;
    fprintf(stderr, "\n####Initiating a new connection to %s:%u#### (sd=%d)\n",
            inet_ntoa(sin->sin_addr), ntohs(sin->sin_port), sd);
    fflush(stderr);
#endif  /*DEBUG*/

    ctx->network_state.peer_addr       = *name;
    ctx->network_state.peer_addr_len   = namelen;
    ctx->network_state.peer_addr_valid = TRUE;

    /* record connection setup for demultiplexing */
    if (!ctx->bound)
    {
        int rc;

        /* we need to find the local port number to set up demultiplexing
         * before we send the SYN.  (this is really only required in the VNS
         * case--we have to demultiplex only on listening sockets for the
         * UDP/TCP network layer--but it doesn't do any harm here in
         * general).
         */
        if ((rc = _mysock_bind_ephemeral(ctx)) < 0)
            return rc;
    }

    /* time for kick off */
    _mysock_transport_init(sd, TRUE);

    /* block until connection is established, or we hit an error */
    return _mysock_wait_for_connection(ctx);
}

mysocket_t myaccept(mysocket_t sd, struct sockaddr *addr, int *addrlen)
{
    mysock_context_t *accept_ctx = _mysock_get_context(sd);
    mysock_context_t *ctx;

    MYSOCK_CHECK(accept_ctx != NULL, EBADF);
    MYSOCK_CHECK(accept_ctx->listening, EINVAL);

#ifdef DEBUG
    fprintf(stderr, "\n####Accepting a new connection at port# %hu#### "
            "(sd=%d)\n",
            ntohs(_network_get_port(&accept_ctx->network_state)), sd);
    fflush(stderr);
#endif  /*DEBUG*/

    /* the new socket is created on an incoming SYN.  block here until we
     * establish a connection, or STCP indicates an error condition.
     */
    _mysock_dequeue_connection(accept_ctx, &ctx);
    assert(ctx);

    if (!ctx->stcp_errno)
    {
        /* fill in addr, addrlen with address of peer */
        assert(ctx->network_state.peer_addr_len > 0);

        if (addr && addrlen)
        {
            *addr    = ctx->network_state.peer_addr;
            *addrlen = ctx->network_state.peer_addr_len;
        }
    }

    assert(ctx->listen_sd == sd);
    DEBUG_LOG(("***myaccept(%d) returning new sd %d***\n", sd, ctx->my_sd));
    return (errno = ctx->stcp_errno) ? -1 : ctx->my_sd;
}

/* in this implementation, mylisten() is assumed to follow mybind() */
int mylisten(mysocket_t sd, int backlog)
{
    mysock_context_t *ctx = _mysock_get_context(sd);

    assert(ctx->bound);

    MYSOCK_CHECK(ctx != NULL, EBADF);
    MYSOCK_CHECK(ctx->bound, EINVAL);

    /* set up the socket for demultiplexing */
    ctx->listening = TRUE;
    _mysock_set_backlog(ctx, backlog);

    if (_network_listen(&ctx->network_state, backlog) < 0)
        return -1;

    /* since we don't spawn an STCP worker thread for passive sockets
     * (there's no transport layer related work to do, so
     * _mysock_transport_init() is never called for such sockets), we
     * begin receiving network packets here...
     */
    if (_network_start_recv_thread(ctx) < 0)
    {
        assert(0);
        return -1;
    }

    return 0;
}

/* close the given mysocket.  note that the semantics of myclose() differ
 * slightly from a regular close(); STCP doesn't implement TIME_WAIT, so
 * myclose() simply discards all knowledge of the connection once the
 * connection is terminated.
 */
int myclose(mysocket_t sd)
{
    mysock_context_t *ctx = _mysock_get_context(sd);

    DEBUG_LOG(("***myclose(%d)***\n", sd));
    MYSOCK_CHECK(ctx != NULL, EBADF);

    /* stcp_wait_for_event() needs to wake up on a socket close request */
    PTHREAD_CALL(pthread_mutex_lock(&ctx->data_ready_lock));
    ctx->close_requested = TRUE;
    PTHREAD_CALL(pthread_mutex_unlock(&ctx->data_ready_lock));
    PTHREAD_CALL(pthread_cond_broadcast(&ctx->data_ready_cond));

    /* block until STCP thread exits */
    if (ctx->transport_thread_started)
    {
        assert(!ctx->listening);
        assert(ctx->is_active || ctx->listen_sd != -1);
        PTHREAD_CALL(pthread_join(ctx->transport_thread, NULL));
        ctx->transport_thread_started = FALSE;
    }

    _network_stop_recv_thread(ctx);

    if (ctx->listening)
    {
        /* remove entry from SYN demultiplexing table */
        _mysock_close_passive_socket(ctx);
    }

    /* free all resources associated with this mysocket */
    _mysock_free_context(ctx);

    DEBUG_LOG(("myclose(%d) returning...\n", sd));
    return 0;
}

int mywrite(mysocket_t sd, const void *buf, size_t buf_len)
{
    mysock_context_t *ctx = _mysock_get_context(sd);

    MYSOCK_CHECK(ctx != NULL, EBADF);
    MYSOCK_CHECK(!ctx->listening, EINVAL);

    assert(!ctx->close_requested);
    _mysock_enqueue_buffer(ctx, &ctx->app_recv_queue, buf, buf_len);

    /* XXX: all bytes are queued, irrespective of current sender window */
    return buf_len;
}

int myread(mysocket_t sd, void *buf, size_t buf_len)
{
    mysock_context_t *ctx = _mysock_get_context(sd);
    int len;

    MYSOCK_CHECK(ctx != NULL, EBADF);
    MYSOCK_CHECK(!ctx->listening, EINVAL);

    assert(!ctx->close_requested);

    if (ctx->eof)
        return 0;

    if ((len = _mysock_dequeue_buffer(ctx, &ctx->app_send_queue,
                                      buf, buf_len, TRUE)) == 0)
    {
        /* make sure repeated calls to myread() return 0 on EOF */
        ctx->eof = TRUE;
    }

    return len;
}

/* fills in addr with current port associated with the mysocket descriptor.
 * like the regular getsockname(), this does not fill in the local IP
 * address unless it's known.
 */
int mygetsockname(mysocket_t sd, struct sockaddr *addr, socklen_t *addrlen)
{
    mysock_context_t *ctx = _mysock_get_context(sd);

    assert(addr && addrlen);

    MYSOCK_CHECK(ctx != NULL, EBADF);
    MYSOCK_CHECK(addr != NULL && addrlen != NULL, EFAULT);

    *addr = ctx->network_state.local_addr;
    assert(!addr->sa_family || addr->sa_family == AF_INET);

    addr->sa_family = AF_INET;
    ((struct sockaddr_in *) addr)->sin_port =
        _network_get_port(&ctx->network_state);

    if (ctx->network_state.peer_addr_valid)
    {
        /* XXX: if local address has been bound, and local_addr is set,
         * we probably shouldn't override it here... although this
         * shouldn't really affect anything...
         */
        ((struct sockaddr_in *) addr)->sin_addr.s_addr =
            _network_get_local_addr(&ctx->network_state);
    }

    return 0;
}

int mygetpeername(mysocket_t sd, struct sockaddr *name, socklen_t *namelen)
{
    mysock_context_t *ctx = _mysock_get_context(sd);

    assert(name && namelen);
    MYSOCK_CHECK(name != NULL && namelen != NULL, EFAULT);

    memcpy(name, &ctx->network_state.peer_addr,
           MIN(*namelen, (socklen_t)ctx->network_state.peer_addr_len));

    MYSOCK_CHECK((*namelen = ctx->network_state.peer_addr_len) > 0, ENOTCONN);
    return 0;
}

/* returns IP address of interface on which packets to/from network address
 * peer_addr (network byte order) are delivered.
 */
uint32_t mylocalip(uint32_t peer_addr)
{
    return _network_get_interface_ip(peer_addr);
}

