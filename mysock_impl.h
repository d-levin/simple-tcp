/* mysocket implementation internal header.
 * these data structures and interfaces must *not* be used by the transport
 * layer.
 */

#ifndef __MYSOCK_INTERNAL_H__
#define __MYSOCK_INTERNAL_H__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <pthread.h>
#include "mysock.h"
#include "network_io.h"

#ifdef __GNUC__
    #define INLINE __inline__
#else
    #define INLINE
#endif

static INLINE void _pthread_call(int pthread_retval)
{
    if (pthread_retval != 0)
    {
        fprintf(stderr, "thread call error %d: %s\n",
                pthread_retval, strerror(pthread_retval));
        assert(0);
        abort();
    }
}

#define PTHREAD_CALL(rc) _pthread_call(rc)

#define ARRAY_DIM(a) (sizeof(a) / sizeof(a[0]))

#ifndef MIN
    #define MIN(a,b)    ((a) < (b) ? (a) : (b))
#endif

#ifdef DEBUG
    /* usage:  DEBUG_LOG((fmt string, args, ...)) */
    #define DEBUG_LOG(args) { printf args; fflush(stdout); }
#else
    #define DEBUG_LOG(args)
#endif


/* packet/buffer queue */
typedef struct packet_queue_node
{
    char                     *data;
    size_t                    data_len;
    struct packet_queue_node *next;
} packet_queue_node_t;

typedef struct
{
    packet_queue_node_t *head;
    packet_queue_node_t *tail;
} packet_queue_t;

/* mysocket context (and the arguments provided to the transport layer
 * thread).  most of this is mysock/network layer working state, with STCP
 * working state maintained separately by the student.  there is one instance
 * of this structure per mysocket.
 */
typedef struct mysock_context
{
    /* connection parameters */
    int is_active;      /* true if we're connect()ing, false if accept()ing */

    /* student's STCP implementation working state */
    void *stcp_state;

    /* network layer working state */
    network_context_t network_state;
    bool_t            bound;        /* true if bound to a local address */
    bool_t            listening;    /* true if mysocket used for myaccept() */

    /* mysocket descriptor (index into our context table) */
    mysocket_t my_sd;

    /* for passive sockets, mysocket descriptor of listening socket from
     * whence we came.  this is unused for active sockets.
     */
    mysocket_t listen_sd;

    /* block application until connected (or an error) */
    pthread_cond_t  blocking_cond;
    pthread_mutex_t blocking_lock;
    bool_t          blocking;
    int             stcp_errno;

    /* STCP thread */
    pthread_t       transport_thread;
    bool_t          transport_thread_started;

    /* is data ready from either network or the app? */
    pthread_cond_t  data_ready_cond;
    pthread_mutex_t data_ready_lock;
    bool_t          close_requested;    /* myclose() called by app? */
    bool_t          eof;                /* true once peer finishes writing */

    /* data sent to peer is sent immediately, so no queue is needed for that
     * case.  we keep a queue for the other three cases:  data coming from
     * peer, data sent to the app for consumption with myread(), and data
     * coming from the app via mywrite().
     */
    packet_queue_t  network_recv_queue; /* data coming from peer */
    packet_queue_t  app_send_queue; /* data to be passed up to app */
    packet_queue_t  app_recv_queue; /* data coming from app */
} mysock_context_t;


/* mysock.c */
mysocket_t _mysock_new_mysocket();

mysock_context_t *_mysock_get_context(mysocket_t sd);

void _mysock_transport_init(mysocket_t sd, bool_t is_active);

int _mysock_wait_for_connection(mysock_context_t *ctx);

void _mysock_free_context(mysock_context_t *ctx);

void _mysock_enqueue_buffer(mysock_context_t *ctx,
                            packet_queue_t   *pq,
                            const void       *packet,
                            size_t            packet_len);

size_t _mysock_dequeue_buffer(mysock_context_t *ctx,
                              packet_queue_t   *pq,
                              void             *dst,
                              size_t            max_len,
                              bool_t            remove_partial);

int _mysock_bind_ephemeral(mysock_context_t *ctx);

pthread_t _mysock_create_thread(void *(*start)(void *args), void *args,                                         bool_t create_detached);

#endif  /* __MYSOCK_INTERNAL_H__ */

