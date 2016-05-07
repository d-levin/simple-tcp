/* mysock.h--mysocket application interface */

#ifndef __MYSOCK_H__
#define __MYSOCK_H__

#if defined(LINUX)
#include <stdint.h>
#elif defined(SOLARIS)
#include <inttypes.h>
#else
#error need to define uint32_t
#endif

#include <sys/types.h>
#include <sys/socket.h>


#ifndef FALSE
#define FALSE 0
#endif

#ifndef TRUE
#define TRUE 1
#endif

typedef int bool_t;
typedef int mysocket_t;     /* mysocket descriptor */


/* maximum number of mysockets per process */
#define MAX_NUM_CONNECTIONS 64

#if (MAX_NUM_CONNECTIONS & (MAX_NUM_CONNECTIONS - 1)) != 0
    #error MAX_NUM_CONNECTIONS should be a power of two
#endif


extern mysocket_t mysocket();
extern int mybind(mysocket_t sd, struct sockaddr *addr, int addrlen);
extern int mylisten(mysocket_t sd, int backlog);
extern int myconnect(mysocket_t sd, struct sockaddr* name, int namelen);
extern int myaccept(mysocket_t sd, struct sockaddr* addr, int *addrlen);
extern int myclose(mysocket_t sd);
extern int myread(mysocket_t sd, void *buffer, size_t length);
extern int mywrite(mysocket_t sd, const void *buffer, size_t length);
extern int mygetsockname(mysocket_t sd, struct sockaddr *addr,
                         socklen_t *addrlen);
extern int mygetpeername(mysocket_t sd, struct sockaddr *addr,
                         socklen_t *addrlen);

/* return IP address of interface on which packets to/from peer_addr are
 * delivered.  peer_addr is in network byte order.
 */
extern uint32_t mylocalip(uint32_t peer_addr);

#endif  /* __MYSOCK_H__ */

