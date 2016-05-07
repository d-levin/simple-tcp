/* connection_demux.c--demultiplex connection requests on a listening socket */

#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <assert.h>
#include "mysock_impl.h"
#include "mysock_hash.h"
#include "network_io.h"
#include "transport.h"
#include "connection_demux.h"



/* state maintained per single pending connection */
typedef struct
{
    /* the connecting peer's address */
    struct sockaddr peer_addr;
    int             peer_addr_len;

    /* new mysocket associated with connection */
    mysocket_t sd;

    /* network layer data associated with connection request */
    void *user_data;
} connect_request_t;

/* queue entry for a completed connection */
typedef struct completed_connect
{
    connect_request_t        *request;
    struct completed_connect *next;
} completed_connect_t;

/* connection backlog maintained per listening socket */
typedef struct
{
    unsigned int         local_port;    /* host byte order */
    unsigned int         max_len;       /* # of allowed pending requests */
    unsigned int         cur_len;       /* curent # of pending requests */

    /* connection_queue contains up to max_len pending connections that
     * have not been accepted by the application yet.  completed entries in
     * the queue are pointed to by completed_queue.
     */
    connect_request_t   *connection_queue;
    completed_connect_t *completed_queue;
    pthread_cond_t       connection_cond;
    pthread_mutex_t      connection_lock;
} listen_queue_t;

#define INVALIDATE_CONNECT_REQUEST(r) \
    { \
        memset(r, 0, sizeof(connect_request_t)); \
        (r)->sd = -1; \
    }

/* maintains queue of pending connections per listening socket.
 * there is one entry in listen_table per passive (listening) socket.
 */
HASH_TABLE_DECLARE(listen_table, mysocket_t, listen_queue_t *,
                   MAX_NUM_CONNECTIONS);
static pthread_rwlock_t listen_lock; /* XXX: see notes in network_io_vns.c */

static listen_queue_t *_get_connection_queue(mysock_context_t *ctx);


/* called by myaccept() to grab the first completed connection off the
 * given mysocket's connection queue, or block until one completes.
 */
void _mysock_dequeue_connection(mysock_context_t  *accept_ctx,
                                mysock_context_t **new_ctx)
{
    listen_queue_t *q;
    completed_connect_t *r;

    assert(accept_ctx && new_ctx);
    assert(accept_ctx->listening && accept_ctx->bound);

    DEBUG_LOG(("waiting for new connection...\n"));
    PTHREAD_CALL(pthread_rwlock_rdlock(&listen_lock));
    q = _get_connection_queue(accept_ctx);
    assert(q);

    PTHREAD_CALL(pthread_mutex_lock(&q->connection_lock));
    while (!q->completed_queue)
    {
        PTHREAD_CALL(pthread_cond_wait(&q->connection_cond,
                                       &q->connection_lock));
    }

    r = q->completed_queue;
    q->completed_queue = q->completed_queue->next;

    DEBUG_LOG(("dequeueing established connection from %s:%hu\n",
               inet_ntoa(((struct sockaddr_in *)
                          &r->request->peer_addr)->sin_addr),
               ntohs(((struct sockaddr_in *)
                      &r->request->peer_addr)->sin_port)));

    assert(r->request);
    *new_ctx = _mysock_get_context(r->request->sd);
    assert(*new_ctx);

    /* free up this entry from the listen queue */
    INVALIDATE_CONNECT_REQUEST(r->request);
    memset(r, 0, sizeof(*r));
    free(r);

    assert(q->cur_len > 0);
    --q->cur_len;

    PTHREAD_CALL(pthread_mutex_unlock(&q->connection_lock));
    PTHREAD_CALL(pthread_rwlock_unlock(&listen_lock));
}

static void _debug_print_connection(const char *msg, const char *reason,
                                    const mysock_context_t *ctx,
                                    const struct sockaddr *peer_addr)
{
    assert(msg && reason && ctx && peer_addr);
    assert(peer_addr->sa_family == AF_INET);

    DEBUG_LOG(("%s from %s:%hu for local port %hu %s\n", msg,
               inet_ntoa(((struct sockaddr_in *) peer_addr)->sin_addr),
               ntohs(((struct sockaddr_in *) peer_addr)->sin_port),
               ntohs(_network_get_port((network_context_t *)
                                       &ctx->network_state)), reason));
}

/* new connection requests for the given mysocket are queued to the
 * corresponding listen queue if one exists and there's sufficient
 * space, or dropped otherwise.  ctx is the context associated with
 * a mysocket for which myaccept() will be called (i.e., a listening
 * socket).
 *
 * returns TRUE if the new connection has been queued, FALSE otherwise.
 */
bool_t _mysock_enqueue_connection(mysock_context_t      *ctx,
                                  const void            *packet,
                                  size_t                 packet_len,
                                  const struct sockaddr *peer_addr,
                                  int                    peer_addr_len,
                                  void                  *user_data)
{
    listen_queue_t *q;
    connect_request_t *queue_entry = NULL;
    unsigned int k;

    assert(ctx && ctx->listening && ctx->bound);
    assert(packet && peer_addr);
    assert(peer_addr_len > 0);

#define DEBUG_CONNECTION_MSG(msg, reason) \
    _debug_print_connection(msg, reason, ctx, peer_addr)

    PTHREAD_CALL(pthread_rwlock_rdlock(&listen_lock));
    if (packet_len < sizeof(struct tcphdr) ||
        !(((struct tcphdr *) packet)->th_flags & TH_SYN))
    {
        DEBUG_CONNECTION_MSG("received non-SYN packet", "(ignoring)");
        goto done;  /* not a connection setup request */
    }

    if (!(q = _get_connection_queue(ctx)))
    {
        DEBUG_CONNECTION_MSG("dropping SYN packet", "(socket not listening)");
        goto done;  /* the socket was closed or not listening */
    }

    /* see if this is a retransmission of an existing request */
    for (k = 0; k < q->max_len; ++k)
    {
        connect_request_t *r = &q->connection_queue[k];

        assert(r->sd == -1 ||
               peer_addr_len == r->peer_addr_len);  /* both are sockaddr_in */
        if (!memcmp(&r->peer_addr, peer_addr, peer_addr_len))
        {
            DEBUG_CONNECTION_MSG("dropping SYN packet",
                                 "(retransmission of queued request)");
            goto done;  /* retransmission */
        }
    }

    /* if it's not a retransmission, find an empty slot in the incomplete
     * connection table
     */
    if (q->cur_len < q->max_len)
    {
        for (k = 0; k < q->max_len && !queue_entry; ++k)
        {
            if (q->connection_queue[k].sd < 0)
                queue_entry = &q->connection_queue[k];
        }

        assert(queue_entry);
        ++q->cur_len;
    }

    if (queue_entry)
    {
        mysock_context_t *new_ctx;

        /* establish the connection */
        assert(queue_entry->sd == -1);
        if ((queue_entry->sd =
             _mysock_new_mysocket()) < 0)
        {
            DEBUG_CONNECTION_MSG("dropping SYN packet",
                                 "(couldn't allocate new mysocket)");
            INVALIDATE_CONNECT_REQUEST(queue_entry);
            --q->cur_len;
            queue_entry = NULL;
            goto done;
        }

        new_ctx = _mysock_get_context(queue_entry->sd);
        new_ctx->listen_sd = ctx->my_sd;

        new_ctx->network_state.peer_addr       = *peer_addr;
        new_ctx->network_state.peer_addr_len   = peer_addr_len;
        new_ctx->network_state.peer_addr_valid = TRUE;

        queue_entry->peer_addr     = *peer_addr;
        queue_entry->peer_addr_len = peer_addr_len;
        queue_entry->user_data     = (void *) user_data;

        DEBUG_CONNECTION_MSG("establishing connection", "");

        /* update any additional network layer state based on the initial
         * packet, e.g. remapped sequence numbers, etc.
         */
        _network_update_passive_state(&new_ctx->network_state,
                                      &ctx->network_state,
                                      user_data, packet, packet_len);

        _mysock_transport_init(queue_entry->sd, FALSE);

        /* pass the SYN packet on to the main STCP code */
        _mysock_enqueue_buffer(new_ctx, &new_ctx->network_recv_queue,
                               packet, packet_len);
    }
    else
    {
        /* the packet is dropped (maximum backlog reached) */
        DEBUG_CONNECTION_MSG("dropping SYN packet", "(queue full)");
    }

done:
    PTHREAD_CALL(pthread_rwlock_unlock(&listen_lock));
    return (queue_entry != NULL);

#undef DEBUG_CONNECTION_MSG
}

void _mysock_passive_connection_complete(mysock_context_t *ctx)
{
    listen_queue_t *q;

    assert(ctx);

    PTHREAD_CALL(pthread_rwlock_rdlock(&listen_lock));
    assert(ctx->listen_sd >= 0);
    if ((q = _get_connection_queue(_mysock_get_context(ctx->listen_sd))))
    {
        completed_connect_t *tail, *new_entry;
        connect_request_t *connection_req = NULL;
        unsigned int k;

        /* find this connection in the incomplete connection queue */
        for (k = 0; k < q->max_len && !connection_req; ++k)
        {
            if (q->connection_queue[k].sd == ctx->my_sd)
                connection_req = &q->connection_queue[k];
        }

        assert(connection_req);

        new_entry = (completed_connect_t *)malloc(sizeof(completed_connect_t));
        assert(new_entry);

        new_entry->request = connection_req;
        new_entry->next = NULL;

        PTHREAD_CALL(pthread_mutex_lock(&q->connection_lock));

        /* add established connection to tail of completed connection queue */
        for (tail = q->completed_queue; tail && tail->next; tail = tail->next)
            ;

        if (tail)
            tail->next = new_entry;
        else
            q->completed_queue = new_entry;

        PTHREAD_CALL(pthread_mutex_unlock(&q->connection_lock));
        PTHREAD_CALL(pthread_cond_signal(&q->connection_cond));
    }
    PTHREAD_CALL(pthread_rwlock_unlock(&listen_lock));
}

/* called by mylisten() to specify the number of pending connection
 * requests permitted for a listening socket.  a backlog of zero
 * specifies at most one pending connection is permitted for the socket.
 */
void _mysock_set_backlog(mysock_context_t *ctx, unsigned int backlog)
{
    unsigned int k, max_len = backlog + 1;
    uint16_t local_port;
    listen_queue_t *q;

    assert(ctx && ctx->listening && ctx->bound);

    local_port = ntohs(_network_get_port(&ctx->network_state));
    assert(local_port > 0);

    PTHREAD_CALL(pthread_rwlock_wrlock(&listen_lock));
    if ((q = _get_connection_queue(ctx)) == NULL)
    {
        /* first backlog specified for new listening socket */
        DEBUG_LOG(("allocating connection queue for local port %hu\n",
                   local_port));

        q = (listen_queue_t *) calloc(1, sizeof(listen_queue_t));
        assert(q);

        q->local_port = local_port;

        PTHREAD_CALL(pthread_cond_init(&q->connection_cond, NULL));
        PTHREAD_CALL(pthread_mutex_init(&q->connection_lock, NULL));
        HASH_INSERT(listen_table, ctx->my_sd, q);
    }

    assert(q);
    assert(q->local_port == local_port);

    if (max_len > q->max_len)
    {
        q->connection_queue = (connect_request_t *)
            realloc(q->connection_queue,
                    max_len * sizeof(connect_request_t));
        assert(q->connection_queue);

        memset(q->connection_queue + q->max_len, 0,
               (max_len - q->max_len) * sizeof(connect_request_t));
    }

    for (k = q->max_len; k < max_len; ++k)
        q->connection_queue[k].sd = -1;
    q->max_len = max_len;

    PTHREAD_CALL(pthread_rwlock_unlock(&listen_lock));
}

/* called by myclose() on a passive socket */
void _mysock_close_passive_socket(mysock_context_t *ctx)
{
    listen_queue_t *q;

    assert(ctx && ctx->listening && ctx->bound);

    PTHREAD_CALL(pthread_rwlock_wrlock(&listen_lock));
    if ((q = _get_connection_queue(ctx)) != NULL)
    {
        /* close any queued connections that haven't been passed up to the
         * user via myaccept()...
         */
        unsigned int k;
        completed_connect_t *connect_iter;

        for (k = 0; k < q->max_len; ++k)
        {
            if (q->connection_queue[k].sd != -1)
                myclose(q->connection_queue[k].sd);
        }
        free(q->connection_queue);

        for (connect_iter = q->completed_queue; connect_iter; )
        {
            /* note: socket was closed by the preceding loop */
            completed_connect_t *next = connect_iter->next;
            free(connect_iter);
            connect_iter = next;
        }

        PTHREAD_CALL(pthread_cond_destroy(&q->connection_cond));
        PTHREAD_CALL(pthread_mutex_destroy(&q->connection_lock));

        HASH_DELETE(listen_table, ctx->my_sd);
        memset(q, 0, sizeof(*q));
        free(q);
    }
    PTHREAD_CALL(pthread_rwlock_unlock(&listen_lock));
}

/* assumes calling code has locked the listen table */
static listen_queue_t *_get_connection_queue(mysock_context_t *ctx)
{
    assert(ctx && ctx->listening && ctx->bound);
    return HASH_LOOKUP_PTR(listen_table, ctx->my_sd);
}

