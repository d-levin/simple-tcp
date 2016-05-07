/* stcp_api.c--transport layer interfaces to the mysock and network layers */

#include <pthread.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <netinet/in.h>
#include "mysock.h"
#include "mysock_impl.h"
#include "stcp_api.h"
#include "network_io.h"
#include "network.h"
#include "connection_demux.h"
#include "tcp_sum.h"
#include "transport.h"


/* called by the transport layer thread to unblock the calling application,
 * e.g. when the connection is complete, or when an error is detected while
 * attempting to make the connection.  before calling this, the STCP layer may
 * set errno as it wishes to indicate any error to the calling application.
 */

/* TODO: pass in errno as argument.  several libc calls on Solaris set this
 * even on successful operation.
 */
void stcp_unblock_application(mysocket_t sd)
{
    mysock_context_t *ctx = _mysock_get_context(sd);

    /* pthread_mutex_lock sometimes sets errno even on successful operation */
    int stcp_errno = errno;

    PTHREAD_CALL(pthread_mutex_lock(&ctx->blocking_lock));
    assert(ctx->blocking);
    ctx->blocking = FALSE;
    if ((ctx->stcp_errno = stcp_errno) == EINTR)
        ctx->stcp_errno = 0;
    PTHREAD_CALL(pthread_mutex_unlock(&ctx->blocking_lock));
    PTHREAD_CALL(pthread_cond_signal(&ctx->blocking_cond));

    if (!ctx->is_active)
    {
        /* move from incomplete to completed connection queue */
        _mysock_passive_connection_complete(ctx);
    }
}


/* called by the transport layer to wait for new data, either from the network
 * or from the application, or for the application to request that the
 * mysocket be closed, depending on the value of flags.  abstime is the
 * absolute time at which the function should quit waiting; if NULL, it blocks
 * indefinitely until data arrives.
 *
 * sd is the mysocket descriptor for the connection of interest.
 *
 * returns bit vector corresponding to application/network data being ready,
 * of the same format as the flags passed (see the enum in stcp_api.h).
 */
unsigned int stcp_wait_for_event(mysocket_t             sd,
                                 unsigned int           flags,
                                 const struct timespec *abstime)
{
    unsigned int rc = 0;
    mysock_context_t *ctx = _mysock_get_context(sd);

    PTHREAD_CALL(pthread_mutex_lock(&ctx->data_ready_lock));
    for (;;)
    {
        if ((flags & APP_DATA) && (ctx->app_recv_queue.head != NULL))
            rc |= APP_DATA;

        if ((flags & NETWORK_DATA) && (ctx->network_recv_queue.head != NULL))
            rc |= NETWORK_DATA;

        if (/*(flags & APP_CLOSE_REQUESTED) &&*/
            ctx->close_requested && (ctx->app_recv_queue.head == NULL))
        {
            /* we should only wake up on this event once.  also, we don't
             * pass the close event down to STCP until we've already passed
             * it all outstanding data from the app.
             */
            ctx->close_requested = FALSE;
            rc |= APP_CLOSE_REQUESTED;
        }

        if (rc)
            break;

        if (abstime)
        {
            /* wait with timeout */
            switch (pthread_cond_timedwait(&ctx->data_ready_cond,
                                           &ctx->data_ready_lock,
                                           abstime))
            {
            case 0: /* some data might be available */
            case EINTR:
                break;

            case ETIMEDOUT: /* no data arrived in the specified time */
                goto done;

            case EINVAL:
                assert(0);
                break;

            default:
                assert(0);
                break;
            }
        }
        else
        {
            /* block indefinitely */
            PTHREAD_CALL(pthread_cond_wait(&ctx->data_ready_cond,
                                           &ctx->data_ready_lock));
        }
    }

done:
    PTHREAD_CALL(pthread_mutex_unlock(&ctx->data_ready_lock));

    return rc;
}

/* allow STCP implementation to establish a context for a given mysocket
 * descriptor.  this context should contain any information that needs to be
 * tracked for the given mysocket, e.g. sequence numbers, retransmission
 * timers, etc.  it would typically be malloc()ed in transport_init() (or even
 * just allocated on the stack), and freed on connection close.
 */
void stcp_set_context(mysocket_t sd, const void *stcp_state)
{
    mysock_context_t *ctx = _mysock_get_context(sd);
    ctx->stcp_state = (void *) stcp_state;
}

void *stcp_get_context(mysocket_t sd)
{
    mysock_context_t *ctx = _mysock_get_context(sd);
    return ctx->stcp_state;
}

/* stcp_network_recv
 *
 * Receive a datagram from the peer.  The call blocks until data is
 * available.
 *
 * sd       Mysocket descriptor.
 * dst      A pointer to a buffer to receive the data.
 * max_len  The size in bytes of the buffer pointed to by dst.
 *
 * This call returns the actual amount of data read into dst.
 */
ssize_t stcp_network_recv(mysocket_t sd, void *dst, size_t max_len)
{
    ssize_t len = _network_recv(sd, dst, max_len);

    /* checksum should have been verified by underlying network layer in
     * this implementation.
     */
    assert(len <= 0 ||
           _mysock_verify_checksum(_mysock_get_context(sd), dst, len));
    return len;
}

/* stcp_network_send()
 *
 * Send data to the peer.
 *
 * sd           Mysocket descriptor
 * src          A pointer to the data to send
 * src_len      The length in bytes of the buffer
 *
 * This function takes data in multiple segments and sends them as a single
 * TCP packet. The buffer and length parameters may be repeated an arbitrary
 * number of times; a NULL pointer signifies the end of buffer/length pairs.
 * For example:
 *
 * stcp_network_send(mysd, buf1, len1, buf2, len2, NULL);
 *
 * Returns the number of bytes transferred on success, or -1 on failure.
 *
 */
ssize_t stcp_network_send(mysocket_t sd, const void *src, size_t src_len, ...)
{
    mysock_context_t *ctx = _mysock_get_context(sd);
    char              packet[MAX_IP_PAYLOAD_LEN];
    size_t            packet_len;
    const void       *next_buf;
    va_list           argptr;
    struct tcphdr    *header;

    assert(ctx && src);

    assert(src_len <= sizeof(packet));
    memcpy(packet, src, src_len);
    packet_len = src_len;

    va_start(argptr, src_len);
    while ((next_buf = va_arg(argptr, const void *)))
    {
        size_t next_len = va_arg(argptr, size_t);

        assert(packet_len + next_len <= sizeof(packet));
        memcpy(packet + packet_len, next_buf, next_len);
        packet_len += next_len;
    }
    va_end(argptr);

    /* fill in fields in the TCP header that aren't handled by students */
    assert(packet_len >= sizeof(struct tcphdr));
    header = (struct tcphdr *) packet;

    header->th_sport = _network_get_port(&ctx->network_state);
    /* N.B. assert(header->th_sport > 0) fires in the UDP SYN-ACK case */

    assert(ctx->network_state.peer_addr.sa_family == AF_INET);
    header->th_dport =
        ((struct sockaddr_in *) &ctx->network_state.peer_addr)->sin_port;
    assert(header->th_dport > 0);

    header->th_sum = 0; /* set below */
    header->th_urp = 0; /* ignored */

    _mysock_set_checksum(ctx, packet, packet_len);
    return _network_send(sd, packet, packet_len);
}

/* receive data from the application (sent to us using mywrite()).
 * the call blocks until data is available.
 */
size_t stcp_app_recv(mysocket_t sd, void *dst, size_t max_len)
{
    mysock_context_t *ctx = _mysock_get_context(sd);
    assert(ctx && dst);

    /* app may have passed in data of arbitrary length; all of it must be
     * passed down to the transport layer.  if it doesn't fit in the specified
     * buffer, any left over is kept for the next call to app_recv().
     */
    return _mysock_dequeue_buffer(ctx, &ctx->app_recv_queue,
                                  dst, max_len, TRUE);
}

/* pass data up to the application for consumption by myread() */
void stcp_app_send(mysocket_t sd, const void *src, size_t src_len)
{
    mysock_context_t *ctx = _mysock_get_context(sd);
    assert(ctx && src);
    if (src_len > 0)
    {
        DEBUG_LOG(("stcp_app_send(%d):  sending %u bytes up to app\n",
                   sd, src_len));
        _mysock_enqueue_buffer(ctx, &ctx->app_send_queue, src, src_len);
    }
}

void stcp_fin_received(mysocket_t sd)
{
    mysock_context_t *ctx = _mysock_get_context(sd);
    assert(ctx);
    DEBUG_LOG(("stcp_fin_received(%d):  setting eof flag\n", sd));
    _mysock_enqueue_buffer(ctx, &ctx->app_send_queue, NULL, 0);
}

