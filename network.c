/* network.c--api for network layer packet transmission */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <netinet/in.h>
#include "mysock_impl.h"
#include "network.h"
#include "network_io.h"
#include "transport.h"  /* for dprintf() */




/* helper function for stcp_network_send(); */
int _network_send(mysocket_t sd, const void *buf, size_t len)
{
    mysock_context_t *sock_ctx = _mysock_get_context(sd);
    network_context_t *ctx;

    assert(sock_ctx && buf);
    ctx = &sock_ctx->network_state;

    return _network_send_packet(ctx, buf, len);
}

/* helper function for stcp_network_recv() */
int _network_recv(mysocket_t sd, void *dst, size_t max_len)
{
    int len;
    mysock_context_t *ctx = _mysock_get_context(sd);

    assert(ctx && dst);
    len = _mysock_dequeue_buffer(ctx, &ctx->network_recv_queue,
                                 dst, max_len, FALSE);

    return len;
}

