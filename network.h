/* this is an internal header, used only by
 * the simulated network layer.
 */

#ifndef __NETWORK_H__
#define __NETWORK_H__

#include "mysock.h"

int _network_send(mysocket_t sd, const void *buf, size_t len);
int _network_recv(mysocket_t sd, void *dst, size_t max_len);

#endif  /* __NETWORK_H__ */

