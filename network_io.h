/* interfaces exported by the underlying network I/O libraries.
 * these are used only by the mysocket layer; they are not intended
 * for application or the STCP layer's use.
 */

#ifndef __NETWORK_IO_H__
#define __NETWORK_IO_H__

#ifdef LINUX
#include <stdint.h>
#endif
#include "mysock.h"

#define MAX_IP_PAYLOAD_LEN 1500


struct mysock_context;

/* network layer context, one instance per mysocket */
typedef struct
{
    /* local address, if known */
    struct sockaddr local_addr;

    /* address of peer */
    struct sockaddr peer_addr;
    socklen_t       peer_addr_len;
    bool_t          peer_addr_valid;

    /* additional (opaque) data used by underlying I/O implementation */
    void *impl_data;

    /* packet reordering/duplication simulation */
    unsigned int random_seed;
    bool_t       copied;
    char         copy_buffer[MAX_IP_PAYLOAD_LEN];
    size_t       copy_buf_len;
} network_context_t;


/* open/close network layer resources for a mysocket */
int _network_init(struct mysock_context *ctx, network_context_t *net_ctx);
void _network_close(network_context_t *ctx);

/* bind a local port to the given mysocket */
int _network_bind(network_context_t *ctx, struct sockaddr *addr, int addrlen);

/* specify backlog for passive socket */
int _network_listen(network_context_t *ctx, int backlog);

/* returns local port associated with mysocket, in network byte order */
int _network_get_port(network_context_t *ctx);

/* returns local address associated with mysocket, in network byte order.
 * this is only valid once the peer is known.
 */
uint32_t _network_get_local_addr(network_context_t *ctx);

/* return local address associated with whichever interface delivers
 * packets to/from peer_addr (network byte order).
 */
uint32_t _network_get_interface_ip(uint32_t peer_addr);

/* send an STCP packet to our peer */
ssize_t _network_send_packet(network_context_t *ctx,
                             const void *src, size_t len);

/* start/stop per-mysocket network receive thread.  the stop() interface
 * must not return until the network receive thread has exited.
 */
int _network_start_recv_thread(struct mysock_context *ctx);
void _network_stop_recv_thread(struct mysock_context *ctx);

/* called when a SYN packet is dequeued on a passive socket, to update any
 * state in the network layer.
 */
void _network_update_passive_state(network_context_t *new_ctx,
                                   network_context_t *accept_ctx,
                                   void *user_data,
                                   const void *syn_packet, size_t syn_len);

#endif  /* __NETWORK_IO_H__ */

