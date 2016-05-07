/* mysock.c--socket layer implementation */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <assert.h>
#include <netinet/in.h>
#include <pthread.h>
#include "mysock.h"
#include "mysock_impl.h"
#include "network_io.h"
#include "stcp_api.h"
#include "transport.h"


#ifdef NDEBUG
    #define ASSERT_VALID_MYSOCKET_DESCRIPTOR(ctx, sd)
#else
    #define ASSERT_VALID_MYSOCKET_DESCRIPTOR(ctx, sd) \
        verify_mysocket_descriptor(ctx, sd)
#endif  /*NDEBUG*/


/* helper functions to start transport layer and network receive threads */
static void *transport_thread_func(void *arg);

static void verify_mysocket_descriptor(mysock_context_t *comp_ctx,
                                       mysocket_t        my_sd);
static mysock_context_t *_mysock_allocate_context(void);
static bool_t _mysock_free_queue(mysock_context_t *ctx, packet_queue_t *pq);


/* mysocket descriptor table, one entry per STCP connection */
static mysock_context_t *global_ctx[MAX_NUM_CONNECTIONS];


/* create a new mysocket, and find space in our mysocket descriptor table */
mysocket_t _mysock_new_mysocket()
{
    mysock_context_t *connection_context = _mysock_allocate_context();
    int k;

    if (!connection_context)
    {
        assert(0);
        return -1;
    }

    /* search for a free mysocket descriptor */
    for (k = 0; k < MAX_NUM_CONNECTIONS; ++k)
    {
        if (!global_ctx[k])
        {
            global_ctx[k] = connection_context;
            connection_context->my_sd = k;
            return k;
        }
    }

    _mysock_free_context(connection_context);
    errno = EMFILE;
    return -1;
}

/* obtain a pointer to the connection context for the given mysocket
 * descriptor.
 */
mysock_context_t *_mysock_get_context(mysocket_t sd)
{
    ASSERT_VALID_MYSOCKET_DESCRIPTOR(NULL, sd);
    return (sd >= 0 && sd < (int)ARRAY_DIM(global_ctx))
        ? global_ctx[sd] : NULL;
}

/* initiate a new STCP connection; called by myconnect() and myaccept() */
void _mysock_transport_init(mysocket_t sd, bool_t is_active)
{
    mysock_context_t *connection_context = _mysock_get_context(sd);

    assert(!connection_context->listening);
    connection_context->is_active = is_active;

    /* start a new network thread; this handles incoming data, passing it
     * up to the transport layer.  (the network input is threaded so we can
     * keep track of timeouts/when data arrives, in a portable manner
     * independent of the underlying network I/O functionality).
     */
    if (_network_start_recv_thread(connection_context) < 0)
    {
        assert(0);
        abort();
    }

    /* start a new transport layer thread */
    connection_context->transport_thread = _mysock_create_thread(
        transport_thread_func,
        connection_context,
        FALSE);
    connection_context->transport_thread_started = TRUE;
}

int _mysock_wait_for_connection(mysock_context_t *ctx)
{
    assert(ctx);

    /* block until we either connect to the peer, or hit an error */
    PTHREAD_CALL(pthread_mutex_lock(&ctx->blocking_lock));
    while (ctx->blocking)
    {
        PTHREAD_CALL(pthread_cond_wait(&ctx->blocking_cond,
                                       &ctx->blocking_lock));
    }
    PTHREAD_CALL(pthread_mutex_unlock(&ctx->blocking_lock));

    return (errno = ctx->stcp_errno) ? -1 : 0;
}


/* add an incoming buffer (packet) to a queue for this connection; it will be
 * dequeued by stcp_network_recv() or myread() when the transport layer or
 * application is ready to use it, depending on the queue to which
 * the buffer (or packet) is added.
 *
 * in the interest of simplicity (and since we aren't writing a high
 * performance TCP stack), this just copies the specified buffer for its own
 * use, so the calling code can do whatever it wants with the packet
 * afterwards.  the copied buffer is freed later by dequeue_buffer().
 */
void _mysock_enqueue_buffer(mysock_context_t *ctx,
                            packet_queue_t   *pq,
                            const void       *packet,
                            size_t            packet_len)
{
    packet_queue_node_t *node;

    assert(ctx && pq && (packet || !packet_len));

    node = (packet_queue_node_t *) calloc(1, sizeof(packet_queue_node_t));
    assert(node);

    node->data = (char *) malloc(packet_len * sizeof(char));
    assert(node->data);

    if (packet_len > 0)
        memcpy(node->data, packet, packet_len);
    node->data_len = packet_len;

    PTHREAD_CALL(pthread_mutex_lock(&ctx->data_ready_lock));
    if (!pq->head)
    {
        assert(!pq->tail);
        pq->head = pq->tail = node;
    }
    else
    {
        assert(pq->tail);
        assert(!pq->tail->next);
        assert(!node->next);
        pq->tail->next = node;
        pq->tail = node;
    }
    PTHREAD_CALL(pthread_mutex_unlock(&ctx->data_ready_lock));
    PTHREAD_CALL(pthread_cond_broadcast(&ctx->data_ready_cond));
}

/* remove one packet from the head of the waiting packet queue, copying the
 * packet's payload into the specified buffer.  returns the number of bytes
 * copied.  if remove_partial is true, and there is insufficient room in the
 * destination buffer for the packet at the head of the queue, it is only
 * partially dequeued, and the remaining contents remain at the queue's head
 * for a subsequent call to dequeue_buffer().
 */
size_t _mysock_dequeue_buffer(mysock_context_t *ctx,
                              packet_queue_t   *pq,
                              void             *dst,
                              size_t            max_len,
                              bool_t            remove_partial)
{
    packet_queue_node_t *node;
    size_t               packet_len;

    assert(ctx && pq && dst);

    /* block until queue is non-empty */
    PTHREAD_CALL(pthread_mutex_lock(&ctx->data_ready_lock));
    while (!pq->head)
    {
        PTHREAD_CALL(pthread_cond_wait(&ctx->data_ready_cond,
                                       &ctx->data_ready_lock));
    }

    node = pq->head;
    assert(node && node->data);

    if (node->data_len > max_len && remove_partial)
    {
        /* remove only a portion of the packet at the head of the queue,
         * leaving the rest around for the next call to dequeue_buffer().
         */
        PTHREAD_CALL(pthread_mutex_unlock(&ctx->data_ready_lock));

        memcpy(dst, node->data, max_len);
        memmove(node->data, node->data + max_len, node->data_len - max_len);
        node->data_len -= max_len;
        packet_len = max_len;
    }
    else
    {
        /* dequeue the entire packet at the head of the queue */
        if (!(pq->head = pq->head->next))
        {
            assert(pq->tail == node);
            pq->tail = NULL;
        }
        PTHREAD_CALL(pthread_mutex_unlock(&ctx->data_ready_lock));

        memcpy(dst, node->data, MIN(max_len, node->data_len));
        packet_len = node->data_len;

        free(node->data);

        memset(node, 0, sizeof(*node));
        free(node);
    }

    return packet_len;
}

/* free any last buffers in the specified queue, discarding the contents.
 * this is called only when the mysocket context is being deallocated, so
 * there are no concerns about thread safety here.  returns TRUE if
 * non-zero-length buffers were deallocated, FALSE otherwise.
 */
static bool_t _mysock_free_queue(mysock_context_t *ctx, packet_queue_t *pq)
{
    packet_queue_node_t *node;
    bool_t result = FALSE;

    assert(ctx && pq);
    result = (pq->head != NULL);
    for (node = pq->head; node; )
    {
        packet_queue_node_t *next = node->next;

        if (node->data_len > 0)
            result = TRUE;

        free(node->data);
        free(node);
        node = next;
    }

    pq->head = pq->tail = NULL;
    return result;
}

/* allocate a new connection context.  this keeps track of the working state
 * between the transport and network layers for a particular connection.  the
 * context is subsequently freed on the network layer's exit.
 */
static mysock_context_t *_mysock_allocate_context(void)
{
    mysock_context_t *ctx = 0;

    ctx = (mysock_context_t *) calloc(1, sizeof(mysock_context_t));
    assert(ctx);

    /* by default, sockets are active */
    ctx->listen_sd = -1;

    /* initialise connection condition variable.  this is signaled when the
     * connection is established, i.e. myconnect() or myaccept() should
     * unblock and return to the calling application.
     */
    PTHREAD_CALL(pthread_cond_init(&ctx->blocking_cond, NULL));
    PTHREAD_CALL(pthread_mutex_init(&ctx->blocking_lock, NULL));

    /* initialise data ready condition variable.  this is signaled when
     * data is ready from the application or the network.
     */
    PTHREAD_CALL(pthread_cond_init(&ctx->data_ready_cond, NULL));
    PTHREAD_CALL(pthread_mutex_init(&ctx->data_ready_lock, NULL));

    ctx->blocking = TRUE;   /* we unblock once we're connected */


    /* initialise underlying network state.  this includes creating the actual
     * socket used for communication to the peer--this is analogous to the
     * underlying raw IP socket used by a real TCP implementation.
     */
    if (_network_init(ctx, &ctx->network_state) < 0)
    {
        _mysock_free_context(ctx);
        return NULL;
    }

    return ctx;
}

/* destroy a connection context previously created with allocate_context().
 * this is invoked only if and when the network and transport threads are
 * done.
 */
void _mysock_free_context(mysock_context_t *ctx)
{
    int sd;

    assert(ctx);

    PTHREAD_CALL(pthread_cond_destroy(&ctx->blocking_cond));
    PTHREAD_CALL(pthread_mutex_destroy(&ctx->blocking_lock));

    PTHREAD_CALL(pthread_cond_destroy(&ctx->data_ready_cond));
    PTHREAD_CALL(pthread_mutex_destroy(&ctx->data_ready_lock));

    /* free any last buffers that might be lying around (e.g. retransmitted
     * packets from the peer).  normally, the application from/to queues
     * should be empty by this point; the network receive queue may
     * legitimately have retransmitted packets, so silently discard these.
     */
    (void) _mysock_free_queue(ctx, &ctx->network_recv_queue);
    (void) _mysock_free_queue(ctx, &ctx->app_recv_queue);
    (void) _mysock_free_queue(ctx, &ctx->app_send_queue);

    _network_close(&ctx->network_state);

    /* clear mysocket descriptor table entry */
    sd = ctx->my_sd;
    if (global_ctx[sd] == ctx)
        global_ctx[sd] = 0;

    memset(ctx, 0, sizeof(*ctx));
    free(ctx);
}

/* transport layer thread; transport_init() should not return until the
 * transport layer finishes (i.e. the connection is over).
 */
static void *transport_thread_func(void *arg_ptr)
{
    mysock_context_t *ctx = (mysock_context_t *) arg_ptr;
    char eof_packet;

    assert(ctx);
    ASSERT_VALID_MYSOCKET_DESCRIPTOR(ctx, ctx->my_sd);

    /* enter the STCP control loop.  transport_init() doesn't return until the
     * connection's finished.  that function should first signal establishment
     * of the connection after SYN/SYN-ACK (or an error condition if the
     * connection couldn't be established) to the application by using
     * stcp_unblock_application(); as the name suggests, this unblocks the
     * calling code.  transport_init() then handles the connection,
     * returning only after the connection is closed.
     */
    transport_init(ctx->my_sd, ctx->is_active);

    /* transport_init() has returned; both sides have closed the connection,
     * do some final cleanup here...
     */

    PTHREAD_CALL(pthread_mutex_lock(&ctx->blocking_lock));
    if (ctx->blocking)
    {
        /* if we're still blocked, STCP must not have indicated the
         * connection completed.  pass the error up to the application.
         */
        if (errno == 0 || errno == EINTR)
        {
            /* this is a bit of a kludge--this should really be set by STCP
             * itself, but it's a reasonable guess if for some reason (e.g.
             * oversight) the transport layer hasn't announced why it
             * bailed out...
             */
            errno = (ctx->is_active) ? ECONNREFUSED : ECONNABORTED;
        }
        PTHREAD_CALL(pthread_mutex_unlock(&ctx->blocking_lock));
        stcp_unblock_application(ctx->my_sd);
    }
    else
    {
        PTHREAD_CALL(pthread_mutex_unlock(&ctx->blocking_lock));
    }

    /* force final myread() to return 0 bytes (this should have been done
     * by the transport layer already in response to the peer's FIN).
     */
    _mysock_enqueue_buffer(ctx, &ctx->app_send_queue, &eof_packet, 0);
    return NULL;
}


/* perform some basic sanity checks on the given mysocket descriptor.  if
 * comp_ctx is non-NULL, it is checked against the context found for the given
 * descriptor to make sure they match.
 */
static void verify_mysocket_descriptor(mysock_context_t *comp_ctx,
                                       mysocket_t        my_sd)
{
    mysock_context_t *ctx;

    assert(my_sd >= 0 && my_sd < (int)ARRAY_DIM(global_ctx));
    ctx = global_ctx[my_sd];

    assert(ctx);
    assert(ctx->my_sd == my_sd);
    assert(!comp_ctx || comp_ctx == ctx);
}

/* obtain ephemeral port for the given mysocket */
int _mysock_bind_ephemeral(mysock_context_t *ctx)
{
    struct sockaddr_in sin;
    int rc;

    assert(ctx && !ctx->bound);

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = 0;
    sin.sin_addr.s_addr = htonl(INADDR_ANY);

    if ((rc = _network_bind(&ctx->network_state,
                            (struct sockaddr *) &sin, sizeof(sin))) < 0)
    {
        perror("network_bind");
        assert(0);
        return rc;
    }

    ctx->bound = TRUE;
    return 0;
}

/* create a detached thread */
pthread_t _mysock_create_thread(void *(*start)(void *args), void *args,
                                bool_t create_detached)
{
    pthread_t thread_id;

    assert(start);
    PTHREAD_CALL(pthread_create(&thread_id, NULL, start, args));
    if (create_detached)
        PTHREAD_CALL(pthread_detach(thread_id));

    return thread_id;
}

