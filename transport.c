/*
 * transport.c
 *
 * COS461: Assignment 3 (STCP)
 *
 * This file implements the STCP layer that sits between the
 * mysocket and network layers. You are required to fill in the STCP
 * functionality in this file.
 *
 */


#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <arpa/inet.h>
#include "mysock.h"
#include "stcp_api.h"
#include "transport.h"

#define MAX_WINDOW_SIZE 3027 /* Max size of sender window */
#define MAX_SEQ_SIZE 256

/* These states define status of a single STCP "connection" */
enum
{
  CSTATE_CLOSED,        // All connections start in this state
  CSTATE_SEND_SYN = 0,  // Client starts by sending SYN message, or a server will send this message.
  CSTATE_LISTEN,        // Server is waiting client SYN
  //CSTATE_SEND_ACK,    // Both devices will ACK a SYN message
  CSTATE_WAIT_FOR_ACK,  // Client is waiting for matching SYN from server
  CSTATE_SYN_RECVD,     // Last step before established -- just need ACK
  CSTATE_ESTABLISHED,   // Steady state of a connection
  CSTATE_SEND_FIN,      // Iniator ready to close connection
  CSTATE_FIN_RECVD,     // Open connection recieved a FIN, now ACK the FIN
  CSTATE_FIN_WAIT,      // Wait for ACK of sent FIN
};


/* this structure is global to a mysocket descriptor */
typedef struct
{
    bool_t done;    /* TRUE once connection is closed */

    mysocket_t sd;  /* Socket descriptor */
    int connection_state;   /* state of the connection (established, etc.) */
    tcp_seq initial_sequence_num; // A random number between 1 - 255 to start the sequence
    tcp_seq next_sequence_num;  // The "reciever" responds with the next sequence number it expects to recieve
    tcp_seq ack_num;  // The "reciver" responds by acknowledging the last packet it recieves

    /* any other connection-wide global variables go here */
} context_t;

static void generate_initial_seq_num(context_t *ctx);
static void control_loop(mysocket_t sd, context_t *ctx);


/* initialise the transport layer, and start the main loop, handling
 * any data from the peer or the application.  this function should not
 * return until the connection is closed.
 *
 * It is called by the transport thread function for a mysock (socket on STCP)
 * located in mysock.c -> static void *transport_thread_func(void *arg_ptr)
 */
void transport_init(mysocket_t sd, bool_t is_active)
{
    // Maybe we want this variable global?
    context_t *ctx;

    unsigned int wait_flags;
    STCPHeader *recvd_header;
    STCPHeader *syn_header;
    STCPHeader *syn_ack_header;
    STCPHeader *ack_header;
    char *segment;
    char *data;

    ctx = (context_t *) calloc(1, sizeof(context_t));
    assert(ctx);

    generate_initial_seq_num(ctx);
    ctx->sd = sd;

    /* XXX: you should send a SYN packet here if is_active, or wait for one
     * to arrive if !is_active.  after the handshake completes, unblock the
     * application with stcp_unblock_application(sd).  you may also use
     * this to communicate an error condition back to the application, e.g.
     * if connection fails; to do so, just set errno appropriately (e.g. to
     * ECONNREFUSED, etc.) before calling the function.
     */

     // Active Open -- typically called the "client"
     if (is_active)
     {
       // Step 1: Client begins connection setup by initiating SYN
       ctx->connection_state = CSTATE_SEND_SYN;

       while(!ctx->CSTATE_ESTABLISHED)
       {
         // Step 2: Now waiting for the matching SYN from the server and also ack_num
         // We either recieve both SYN + ACK from server simulataneously, or just SYN

         // We got a SYN, just need the ACK
         // ctx->connection_state = CSTATE_SYN_RECVD
         // Got the ACK Now (Or if we got them together)
         // ctx->connection_state = CSTATE_ESTABLISHED
       }
     }
     // Passive Open -- typically called the "server"
     else
     {
       // Step 1: Passive open on a TCP Port and set up context_t struct to manage the connection
       ctx->connection_state = CSTATE_LISTEN;
       // Step 2: Receieved SYN from client, now send SYN + ACK
       ctx->connection_state = CSTATE_SEND_SYN;
       ctx->connection_state = CSTATE_SEND_ACK;
       // Step 3: Wait for ACK of SYN before connection setup completes
       ctx->connection_state = CSTATE_SYN_RECVD;
       // ACK recieved, move to establised state
     }

    ctx->connection_state = CSTATE_ESTABLISHED;
    stcp_unblock_application(sd);

    control_loop(sd, ctx);

    /* do any cleanup here */
    free(ctx);
}


/* generate random initial sequence number for an STCP connection */
static void generate_initial_seq_num(context_t *ctx)
{
    assert(ctx);

#ifdef FIXED_INITNUM
    /* please don't change this! */
    ctx->initial_sequence_num = 1;
#else
    /* Generate a random number given the max sequence number size */
    ctx->initial_sequence_num = rand() % MAX_SEQ_SIZE;
#endif
}


/* control_loop() is the main STCP loop; it repeatedly waits for one of the
 * following events to happen:
 *   - incoming data from the peer
 *   - new data from the application (via mywrite())
 *   - the socket to be closed (via myclose())
 *   - a timeout
 */
static void control_loop(mysocket_t sd, context_t *ctx)
{
    assert(ctx);
    assert(!ctx->done);

    while (!ctx->done)
    {
        unsigned int event;

        /* see stcp_api.h or stcp_api.c for details of this function */
        /* XXX: you will need to change some of these arguments! */
        event = stcp_wait_for_event(sd, 0, NULL);

        /* check whether it was the network, app, or a close request */
        if (event & APP_DATA)
        {
            /* the application has requested that data be sent */
            /* see stcp_app_recv() */
        }

        /* etc. */
    }
}


/**********************************************************************/
/* our_dprintf
 *
 * Send a formatted message to stdout.
 *
 * format               A printf-style format string.
 *
 * This function is equivalent to a printf, but may be
 * changed to log errors to a file if desired.
 *
 * Calls to this function are generated by the dprintf amd
 * dperror macros in transport.h
 */
void our_dprintf(const char *format,...)
{
    va_list argptr;
    char buffer[1024];

    assert(format);
    va_start(argptr, format);
    vsnprintf(buffer, sizeof(buffer), format, argptr);
    va_end(argptr);
    fputs(buffer, stdout);
    fflush(stdout);
}
