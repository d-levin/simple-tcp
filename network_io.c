/* network_io.c:  routines shared amongst all network layer instantiations */

#include <assert.h>
#include <netinet/in.h>
#include "mysock_impl.h"
#include "network_io.h"


/* return local IP address associated with the given mysocket.
 *
 * this requires that the peer address be known; on the active side,
 * this implies that this function must not be called until myconnect()
 * has been called, while on the passive side, it must not be called
 * until the first packet arrives from the peer.  (this is not too
 * onerous a restriction, as this interface is used only in the TCP
 * checksum calculation, which satisfies the aforementioned
 * requirements).
 */

uint32_t _network_get_local_addr(network_context_t *ctx)
{
    assert(ctx);

    assert(ctx->peer_addr_valid);
    assert(ctx->peer_addr_len > 0);
    assert(ctx->peer_addr.sa_family == AF_INET);

    return _network_get_interface_ip(
        ((struct sockaddr_in *) &ctx->peer_addr)->sin_addr.s_addr);
}

