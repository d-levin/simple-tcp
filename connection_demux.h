/* connection_demux.h--demultiplex SYN requests on a listening socket.
 * this is an internal header, used only by the mysocket layer.
 */

#ifndef __CONNECTION_DEMUX_H__
#define __CONNECTION_DEMUX_H__

struct mysock_context;

void _mysock_dequeue_connection(struct mysock_context  *accept_ctx,
                                struct mysock_context **new_ctx);

bool_t _mysock_enqueue_connection(struct mysock_context *ctx,
                                  const void            *packet,
                                  size_t                 packet_len,
                                  const struct sockaddr *peer_addr,
                                  int                    peer_addr_len,
                                  void                  *user_data);

void _mysock_set_backlog(struct mysock_context *ctx, unsigned int backlog);
void _mysock_close_passive_socket(struct mysock_context *ctx);

void _mysock_passive_connection_complete(struct mysock_context *new_ctx);

#endif  /* __CONNECTION_DEMUX_H__ */

