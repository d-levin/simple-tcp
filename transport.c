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
#include <string.h>
#include <time.h>

#define MAX_WINDOW_SIZE 3027 /* Max size of sender window */
#define MAX_SEQ_SIZE 256

// /* These states define status of a single STCP "connection" */
enum
{
  CSTATE_CLOSED,        // All connections start in this state
  CSTATE_SEND_SYN,      // Client starts by sending SYN message, or a server will send this message.
  CSTATE_LISTEN,        // Server is waiting client SYN
  CSTATE_SENT_ACK,      // Both devices will ACK a SYN message
  CSTATE_WAIT_FOR_ACK
  CSTATE_SYN_ACK,       // Client is waiting for matching SYN + ACK from server
  CSTATE_SYN_RECVD,     // Last step before established -- just need ACK
  CSTATE_ESTABLISHED,   // Steady state of a connection
  CSTATE_SEND_FIN,      // Iniator ready to close connection
  CSTATE_FIN_RECVD,     // Open connection recieved a FIN, now ACK the FIN
  CSTATE_FIN_WAIT,      // Wait for ACK of sent FIN
};

//enum { CSTATE_ESTABLISHED, SYN, SYN_ACK }; /* you should have more states */

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

static void generate_initial_seq_num(context_t* ctx);
static void control_loop(mysocket_t sd, context_t* ctx);

/* initialise the transport layer, and start the main loop, handling
 * any data from the peer or the application.  this function should not
 * return until the connection is closed.
 */
void transport_init(mysocket_t sd, bool_t is_active) {

  //     unsigned int wait_flags;
  //     STCPHeader *recvd_header;
  //     STCPHeader *syn_header;
  //     STCPHeader *syn_ack_header;
  //     STCPHeader *ack_header;
  //     char *segment;
  //     char *data;

// Maybe we want this global?
  context_t* ctx;
  STCPHeader* activeHeader = NULL;
  STCPHeader* passiveHeader = NULL;

  char buffer[MAX_IP_PAYLOAD_LEN];

  ctx = (context_t*)calloc(1, sizeof(context_t));
  assert(ctx);

  generate_initial_seq_num(ctx);
  //     ctx->sd = sd;

  /* XXX: you should send a SYN packet here if is_active, or wait for one
 * to arrive if !is_active.  after the handshake completes, unblock the
 * application with stcp_unblock_application(sd).  you may also use
 * this to communicate an error condition back to the application, e.g.
 * if connection fails; to do so, just set errno appropriately (e.g. to
 * ECONNREFUSED, etc.) before calling the function.
 */
  if (is_active) {  // Client control path, initiate connection
    //        while(!ctx->CSTATE_ESTABLISHED)
    //        {
    //          // Step 2: Now waiting for the matching SYN from the server and also ack_num
    //          // We either recieve both SYN + ACK from server simulataneously, or just SYN
    //
    //          // We got a SYN, just need the ACK
    //          // ctx->connection_state = CSTATE_SYN_RECVD
    //          // Got the ACK Now (Or if we got them together)
    //          // ctx->connection_state = CSTATE_ESTABLISHED
    //        }
    // }

    // Step 1: Client begins connection setup by initiating SYN
    activeHeader = (STCPHeader*)malloc(sizeof(STCPHeader));
    activeHeader->th_seq = htonl(ctx->initial_sequence_num);
    activeHeader->th_acq = htonl(ctx->initial_sequence_num + 1);
    activeHeader->th_off = 5;         // header size offset for packed data
    activeHeader->th_flags = TH_SYN;  // set packet type to SYN
    activeHeader->th_win = 1;         // default value

    // Send SYN packet
    ssize_t sentBytes =
        stcp_network_send(sd, activeHeader, sizeof(STCPHeader), NULL);

    // Verify sending of SYN packet
    if (sentBytes) {  // If SYN packet suucessfully sent
      ctx->connection_state = CSTATE_SYN_ACK;
    } else {
      free(activeHeader);
      free(ctx);
      stcp_unblock_application(sd);
      errorno = ECONNREFUSED;  // TODO
      return;
    }

    // Wait for SYN-ACK packet
    unsigned int event = stcp_wait_for_event(sd, NETWORK_DATA, NULL);

    // Verify correct event
    if (event == NETWORK_DATA) {
      ssize_t receivedBytes = stcp_network_recv(sd, buffer, MAX_IP_PAYLOAD_LEN);

      // Verify size of received packet
      if (receivedBytes < sizeof(STCPHeader)) {
        free(activeHeader);
        free(ctx);
        stcp_unblock_application(sd);
        errorno = ECONNREFUSED;  // TODO
        return;
      }

      // Parse received data
      passiveHeader = (STCPHeader*)buffer;

      // Check for appropriate flags and set connection state
      // TODO: Verify that we are not supposed to catch situation in which we only recieve one flag at a time
      if (passiveHEADER->th_flags == (TH_ACK | TH_SYN)) {
        ctx->initial_get_seq = ntohl(passiveHEADER->th_seq) + 1;
        // This was SYN_ACK
        ctx->connection_state = CSTATE_SEND_ACK;
      }

      // Create ACK packet
      activeHeader->th_flags = TH_ACK;
      activeHeader->th_seq = htonl(ctx->initial_get_seq);
      activeHeader->th_ack = htonl(activeHeader->th_seq);

      // Send ACK packet
      sentBytes = stcp_network_send(sd, activeHeader, sizeof(STCPHeader), NULL);

      free(activeHeader);
    } else {
      free(activeHeader);
      free(ctx);
      stcp_unblock_application(sd);
      errorno = ECONNREFUSED;  // TODO
      return;
    }

  } else {  // Server control path, wait for connection

    // Step 1: Passive open on a TCP Port and set up context_t struct to manage the connection
    //        // Step 2: Receieved SYN from client, now send SYN + ACK
    //        ctx->connection_state = CSTATE_SEND_SYN;
    //        ctx->connection_state = CSTATE_SEND_ACK;
    //        // Step 3: Wait for ACK of SYN before connection setup completes
    //        ctx->connection_state = CSTATE_SYN_RECVD;
    //        // ACK recieved, move to establised state

    // Wait for SYN packet
    ctx->connection_state = CSTATE_LISTEN;
    unsigned int event = stcp_wait_for_event(sd, NETWORK_DATA, NULL);

    // Verify correct event
    if (event == NETWORK_DATA) {
      ssize_t receivedBytes = stcp_network_recv(sd, buffer, MAX_IP_PAYLOAD_LEN);

      if (receivedBytes < sizeof(STCPHeader)) {
        free(ctx);
        stcp_unblock_application(sd);
        errorno = ECONNREFUSED;  // TODO
        return;
      }

      activeHeader = (activeHeader*)buffer;
      // ctx->connection_state = SYN?
      ctx->connection_state = CSTATE_SYN_RECVD;
    }

    // Create SYN-ACK packet
    passiveHeader = (STCPHeader*)malloc(sizeof(STCPHeader));
    passiveHeader->th_seq = htonl(ctx->initial_sequence_num);
    passiveHeader->th_acq = htonl(ctx->initial_sequence_num + 1);
    passiveHeader->th_off = 5;
    passiveHeader->th_flags = TH_SYN | TH_ACK;
    passiveHeader->th_win = 1;

    // Send SYN-ACK password
    ssize_t sentBytes = stcp_network_send(sd, passiveHeader, sizeof(STCPHeader), NULL);

    // Verify sending of SYN-ACK packet
    if (sentBytes) {
      ctx->connection_state = CSTATE_WAIT_FOR_ACK;
    } else {
      free(passiveHeader);
      free(ctx);
      stcp_unblock_application(sd);
      errorno = ECONNREFUSED; // TODO
      return;
    }

    // Wait for ACK packet
    unsigned int event stcp_wait_for_event(sd, NETWORK_DATA, NULL);

    if (event == NETWORK_DATA) {
      ssize_t receivedBytes = stcp_network_recv(sd, buffer, MAX_IP_PAYLOAD_LEN);
    }

    // Verify size of received packet
    if (receivedBytes < sizeof(STCPHeader)) {
      free(ctx);
      stcp_unblock_application(sd);
      errorno = ECONNREFUSED; // TODO
      return;
    }

    // Parse received data
    activeHeader = (activeHeader*)buffer;

    if (activeHeader->th_flags == (TH_ACK)) {
      ctx->initial_get_seq = ntohl(activeHeader->th_seq) + 1;
    }
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
