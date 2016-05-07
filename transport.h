/* header file for the transport layer */

#ifndef __TRANSPORT_H__
#define __TRANSPORT_H__

#ifdef _NETINET_TCP_H
    #error <netinet/tcp.h> conflicts with STCP definitions.
    #error Include only transport.h in the STCP project.
#endif

#include <stdio.h>  /* for perror */
#include <errno.h>
#include "mysock.h"


/* For some reason, Linux redefines tcphdr unless one compiles with only
 * _BSD_SOURCE defined--but doing this causes problems with some of the
 * other system headers, which require other conflicting defines (such as
 * _POSIX_SOURCE and _XOPEN_SOURCE).  For simplicity, since the TCP header
 * format is well-defined, we just define this again here.
 *
 * You can ignore the following fields in tcphdr:  th_sport, th_dport,
 * th_sum, th_urp.  stcp_network_send() will take care of filling those
 * in.
 */

/* XXX: ugh, clean this up some time */
#if defined(SOLARIS)
    #define __LITTLE_ENDIAN 1234
    #define __BIG_ENDIAN 4321
    #define __BYTE_ORDER __BIG_ENDIAN
#elif defined(LINUX)	/* cppp replaced: elif */
    #ifndef __BYTE_ORDER
        #error huh?  Linux has not defined endianness.
    #endif
#else
    #error Unrecognised system type.
#endif

typedef uint32_t tcp_seq;

typedef struct tcphdr
{
    uint16_t th_sport;  /* source port */
    uint16_t th_dport;  /* destination port */
    tcp_seq  th_seq;    /* sequence number */
    tcp_seq  th_ack;    /* acknowledgement number */
#if __BYTE_ORDER == __LITTLE_ENDIAN
    uint8_t  th_x2:4;   /* unused */
    uint8_t  th_off:4;  /* data offset */
#elif __BYTE_ORDER == __BIG_ENDIAN
    uint8_t  th_off:4;  /* data offset */
    uint8_t  th_x2:4;   /* unused */
#else
#error __BYTE_ORDER must be defined as __LITTLE_ENDIAN or __BIG_ENDIAN!
#endif
    uint8_t  th_flags;
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04    /* you don't have to handle this */
#define TH_PUSH 0x08    /* ...or this */
#define TH_ACK  0x10
#define TH_URG  0x20    /* ...or this */
    uint16_t th_win;    /* window */
    uint16_t th_sum;    /* checksum */
    uint16_t th_urp;    /* urgent pointer (unused in STCP) */
} __attribute__ ((packed)) STCPHeader;


/* starting byte position of data in TCP packet p */
#define TCP_DATA_START(p) (((STCPHeader *) p)->th_off * sizeof(uint32_t))

/* length of options (in bytes) in TCP packet p */
#define TCP_OPTIONS_LEN(p) (TCP_DATA_START(p) - sizeof(struct tcphdr))

/* STCP maximum segment size */
#define STCP_MSS 536


#ifndef MIN
    #define MIN(x,y)  ((x) <= (y) ? (x) : (y))
#endif

#ifndef MAX
    #define MAX(x,y)  ((x) >= (y) ? (x) : (y))
#endif


#ifdef DEBUG
    #ifdef LINUX
        #include <string.h> /* Linux, for strerror_r() */
    #else
        extern char *sys_errlist[];
        #define strerror_r(num,buf,len) strncpy(buf, sys_errlist[num], len)
    #endif

    extern void our_dprintf(const char *format, ...);

    #define dprintf our_dprintf
    #define dperror(head) \
        { \
            if (errno >= 0) \
            { \
                char err_buf[255]; \
                dprintf("%s: %s\n", (head), \
                        strerror_r(errno, err_buf, sizeof(err_buf))); \
            } \
        }
#else
    #ifdef __GNUC__
        #define dprintf(fmt, ...)
        #define dperror(head)
    #else
        #define dprintf (void)
        #define dperror (void)
    #endif
#endif

extern void transport_init(mysocket_t sd, bool_t is_active);

#endif  /* __TRANSPORT_H__ */
