/* internal header--TCP checksum support */

#ifndef __TCP_CHECKSUM_H__
#define __TCP_CHECKSUM_H__

#include "mysock.h"

struct mysock_context;

uint16_t _mysock_tcp_checksum(uint32_t src_addr /*network byte order*/,
                              uint32_t dst_addr /*network byte order*/,
                              const void *packet,
                              size_t len /*host byte order*/);

void _mysock_set_checksum(const struct mysock_context *ctx,
                          void *packet, size_t len);

bool_t _mysock_verify_checksum(const mysock_context_t *ctx,
                               const void *packet, size_t len);

#endif  /* __TCP_CHECKSUM_H__ */

