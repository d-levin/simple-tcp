/* TCP checksum support--this is not used directly by students */

#include <stddef.h>
#include <assert.h>
#include <netinet/in.h>
#include "mysock_impl.h"
#include "transport.h"
#include "tcp_sum.h"


/* computes checksum for TCP segment, based on description in RFCs 793 and
 * 1071, and Berkeley in_cksum().
 */
uint16_t _mysock_tcp_checksum(uint32_t src_addr /*network byte order*/,
                              uint32_t dst_addr /*network byte order*/,
                              const void *packet,
                              size_t len /*host byte order*/)
{
    struct
    {
        uint32_t src_addr;
        uint32_t dst_addr;
        uint8_t  zero;
        uint8_t  protocol;
        uint16_t len;
    } __attribute__ ((packed)) pseudo_header =
    {
        src_addr, dst_addr, 0, IPPROTO_TCP, htons(len)
    };

    unsigned int k;
    int32_t sum = 0;

    assert(packet && len >= sizeof(struct tcphdr));
    assert(sizeof(pseudo_header) == 12);


    assert(src_addr > 0);
    assert(dst_addr > 0);

    /* process 96-bit pseudo header */
    for (k = 0; k < sizeof(pseudo_header) / sizeof(uint16_t); ++k)
        sum += ((uint16_t *) &pseudo_header)[k];

    /* process TCP header and payload */
    assert(((long)packet & 2) == 0);
    assert((offsetof(struct tcphdr, th_sum) & 2) == 0);
    for (k = 0; k < (len >> 1); ++k)
    {
        if (k == (offsetof(struct tcphdr, th_sum) >> 1))
            continue;   /* th_sum == 0 during checksum computation */
        sum += ((uint16_t *) packet)[k];
    }

    if (len & 1)
    {
        uint16_t tmp = 0;
        *(uint8_t *) &tmp = ((uint8_t *) packet)[len - 1];
        sum += tmp;
    }

    /* fold 32-bit sum to 16 bits */
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);

    return (uint16_t) ~sum;
}

/* update checksum in the given STCP segment */
void _mysock_set_checksum(const mysock_context_t *ctx,
                          void *packet, size_t len)
{
    assert(ctx && packet);
    assert(len >= sizeof(struct tcphdr));

    assert(ctx->network_state.peer_addr.sa_family == AF_INET);

    ((struct tcphdr *) packet)->th_sum = _mysock_tcp_checksum(
        _network_get_local_addr((network_context_t *)
                                &ctx->network_state), /*src*/
        ((struct sockaddr_in *) &ctx->network_state.peer_addr)-> /*dst*/
            sin_addr.s_addr,
        packet, len);
}

/* returns TRUE if checksum is correct, FALSE otherwise */
bool_t _mysock_verify_checksum(const mysock_context_t *ctx,
                               const void *packet, size_t len)
{
    uint16_t my_sum;

    assert(ctx && packet);
    assert(len >= sizeof(struct tcphdr));

    assert(ctx->network_state.peer_addr.sa_family == AF_INET);

    my_sum = _mysock_tcp_checksum(
        ((struct sockaddr_in *) &ctx->network_state.peer_addr)-> /*src*/
            sin_addr.s_addr,
        _network_get_local_addr((network_context_t *)
                                &ctx->network_state), /*dst*/
        packet, len);

    return my_sum == ((struct tcphdr *) packet)->th_sum;
}

