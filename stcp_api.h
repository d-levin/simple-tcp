/* stcp_api.h--transport layer interfaces to the mysock and network layers.
 * these are the only interfaces to the stub code you're permitted to call
 * from your transport layer!
 */

#ifndef __STCP_API_H__
#define __STCP_API_H__

#include <time.h>   /* timespec */
#include "mysock.h" /* mysocket_t */


/* stcp_wait_for_event() flags */
typedef enum
{
    TIMEOUT             = 0,
    APP_DATA            = 1,
    NETWORK_DATA        = 2,
    APP_CLOSE_REQUESTED = 4,
    ANY_EVENT           = APP_DATA | NETWORK_DATA | APP_CLOSE_REQUESTED
} stcp_event_type_t;


/* called by the transport layer thread to unblock the calling application,
 * e.g. when the connection is established, or when an error is detected
 * while attempting to make the connection.  the STCP layer may set errno
 * as it likes to indicate any error to the calling application.
 */
void stcp_unblock_application(mysocket_t sd);

/* called by the transport layer to wait for new data, either from the network
 * or from the application, or for the application to request that the
 * socket be closed via myclose(), depending on the value of wait_flags.
 * abstime is the absolute time at which the function should quit waiting
 * (i.e., the value of the system clock at which the timeout should be
 * indicated; it has the same origin as time(2) and gettimeofday(2), so a
 * structure containing all zeros corresponds to 00:00:00 GMT, January 1,
 * 1970); if the timeout pointer is NULL, the function blocks indefinitely
 * until data arrives.  the close event is triggered only once, once all
 * pending data has been dequeued from the application.
 *
 * sd is the mysocket descriptor for the connection of interest.
 *
 * the function returns a bit mask corresponding to an application data
 * arriving/network data arriving/close event, of the same format as the flags
 * passed (see the stcp_event_type_t enum above).  one or more bits may be
 * set, if multiple events have occurred.
 *
 * if an event has occurred since the last call to stcp_wait_for_event(), or
 * the system time has already reached the absolute time specified to the
 * call, the function will return immediately.  events are queued, so, for
 * example, if multiple packets have arrived from the peer, after dequeueing a
 * single such event with stcp_network_recv(), a subsequent call to
 * stcp_wait_for_event() (with appropriate flags) would return immediately
 * with a pending event to be processed.  similarly, if you read only some
 * of the data waiting to be sent by the application, a subsequent call to
 * stcp_wait_for_event() (again with appropriate flags) will return
 * immediately with a pending event to be processed.
 */
unsigned int stcp_wait_for_event(mysocket_t             sd,
                                 unsigned int           wait_flags,
                                 const struct timespec *abstime);

/* allow STCP implementation to establish a context for a given mysocket
 * descriptor.  this context should contain any information that needs to be
 * tracked for the given mysocket, e.g. sequence numbers, retransmission
 * timers, etc.  it would typically be malloc()ed in transport_init() (or even
 * just allocated on the stack), and freed on connection close.  you may
 * or may not need to use these functions depending on your implementation.
 */
void stcp_set_context(mysocket_t sd, const void *stcp_state);
void *stcp_get_context(mysocket_t my_sd);

/* Receive a datagram from the peer.
 *
 * sd       Mysocket descriptor.
 * dst      A pointer to a buffer to receive the data.
 * max_len  The size in bytes of the buffer pointed to by dst.
 *
 * This call returns the actual amount of data read into dst.
 */
ssize_t stcp_network_recv(mysocket_t sd, void *dst, size_t max_len);

/* Send data to the peer.
 *
 * sd           Mysocket descriptor
 * src          A pointer to the data to send
 * src_len      The length in bytes of the buffer
 *
 * This function takes data in multiple segments and sends them as a single
 * datagram. The buffer and length parameters may be repeated an arbitrary
 * number of times; a NULL pointer signifies the end of buffer/length pairs.
 * For example:
 *
 * stcp_network_send(mysd, buf1, len1, buf2, len2, NULL);
 *
 * Returns the number of bytes transferred on success, or -1 on failure.
 */
ssize_t stcp_network_send(mysocket_t sd, const void *src, size_t src_len, ...);

/* receive data from the application (sent to us using mywrite()) */
size_t stcp_app_recv(mysocket_t sd, void *dst, size_t max_len);

/* pass data up to the application for consumption by myread() */
void stcp_app_send(mysocket_t sd, const void *src, size_t src_len);

/* once you receive a FIN segment from the peer, we need to let the
 * application know there's no more data arriving (by returning 0 bytes for
 * subsequent myread() calls).  call stcp_fin_received() to indicate the
 * mysocket is closed for reading.  the mysocket will be fully closed once the
 * app subsequently calls myclose().
 */
void stcp_fin_received(mysocket_t sd);

#endif  /* __STCP_API_H__ */

