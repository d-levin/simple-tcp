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
#include "network_io.h"

#define MAX_WINDOW_SIZE 3027 /* Max size of sender window */
#define MAX_SEQ_SIZE 256

// /* These states define status of a single STCP "connection" */
enum
{
  CSTATE_CLOSED,        // All connections start in this state
  CSTATE_SEND_SYN,      // Client starts by sending SYN message, or a server will send this message.
  CSTATE_LISTEN,        // Server is waiting client SYN
  CSTATE_SENT_ACK,      // Both devices will ACK a SYN message
  CSTATE_WAIT_FOR_ACK,
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
void transport_init(mysocket_t sd, bool_t is_active)
{
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
    // This will hold both data being sent from the application and data incoming from the link layer
    //char* buffer = NULL;
    //ssize_t buff_len;

    ctx = (context_t*)calloc(1, sizeof(context_t));
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
    if (is_active)
    {  // Client control path, initiate connection

        // Step 1: Client begins connection setup by initiating SYN
        activeHeader = (STCPHeader*)malloc(sizeof(STCPHeader));
        activeHeader->th_seq = htonl(ctx->initial_sequence_num);
        activeHeader->th_ack = htonl(ctx->initial_sequence_num + 1);
        activeHeader->th_off = 5;         // header size offset for packed data
        activeHeader->th_flags = TH_SYN;  // set packet type to SYN
        activeHeader->th_win = 1;         // default value

        printf("\nPreparing to send SYN");
        // Send SYN packet
        ssize_t sentBytes =
            stcp_network_send(sd, activeHeader, sizeof(STCPHeader), NULL);

        // Verify sending of SYN packet
        if (sentBytes)
        {  // If SYN packet suucessfully sent
          ctx->connection_state = CSTATE_SYN_ACK;
        }
        else
        {
          free(activeHeader);
          free(ctx);
          stcp_unblock_application(sd);
          errno = ECONNREFUSED;  // TODO
          return;
        }

        // Wait for SYN-ACK packet
        printf("\nWaiting for SYN-ACK");
        unsigned int event = stcp_wait_for_event(sd, NETWORK_DATA, NULL);

        // Verify correct event
        if (event == NETWORK_DATA)
        {
          ssize_t receivedBytes = stcp_network_recv(sd, buffer, MAX_IP_PAYLOAD_LEN);

          // Verify size of received packet
          if (receivedBytes < (int)sizeof(STCPHeader))
          {
            free(activeHeader);
            free(ctx);
            stcp_unblock_application(sd);
            errno = ECONNREFUSED;  // TODO
            return;
          }

          // Parse received data
          passiveHeader = (STCPHeader*)buffer;

          // Check for appropriate flags and set connection state
          // TODO: Verify that we are not supposed to catch situation in which we only recieve one flag at a time
          if (passiveHeader->th_flags == (TH_ACK | TH_SYN))
          {
            // Assuming "get_initial_seq_num" was supposed to be this
            ctx->initial_sequence_num = ntohl(passiveHeader->th_seq) + 1;
            ctx->connection_state = CSTATE_SENT_ACK;
          }

          // Create ACK packet
          activeHeader->th_flags = TH_ACK;
          activeHeader->th_seq = htonl(ctx->initial_sequence_num);
          activeHeader->th_ack = htonl(activeHeader->th_seq);

          // Send ACK packet
          printf("\nPreparing to send ACK");
          sentBytes = stcp_network_send(sd, activeHeader, sizeof(STCPHeader), NULL);

          free(activeHeader);
        }
        else
        {
          free(activeHeader);
          free(ctx);
          stcp_unblock_application(sd);
          errno = ECONNREFUSED;  // TODO
          return;
        }
    }
            // ** Server(Passive) control path -- wait for connection **
    else
    {
        ctx->connection_state = CSTATE_LISTEN;
        printf("\nListening for incoming SYN");
        unsigned int event = stcp_wait_for_event(sd, NETWORK_DATA, NULL);

        // Verify correct event
        if (event == NETWORK_DATA)
        {
          ssize_t receivedBytes = stcp_network_recv(sd, buffer, MAX_IP_PAYLOAD_LEN);

          if (receivedBytes < (int)sizeof(STCPHeader))
          {
            free(ctx);
            stcp_unblock_application(sd);
            errno = ECONNREFUSED;  // TODO
            return;
          }

          activeHeader = (STCPHeader*)buffer;
          // ctx->connection_state = SYN?
          ctx->connection_state = CSTATE_SYN_RECVD;
          printf("\nReceived Initial SYN");
        }

        // Create SYN-ACK packet
        passiveHeader = (STCPHeader*)malloc(sizeof(STCPHeader));
        passiveHeader->th_seq = htonl(ctx->initial_sequence_num);
        passiveHeader->th_ack = htonl(ctx->initial_sequence_num + 1);
        passiveHeader->th_off = 5;
        passiveHeader->th_flags = TH_SYN | TH_ACK;
        passiveHeader->th_win = 1;

        // Send SYN-ACK password
        printf("\nSending SYN+ACK");
        ssize_t sentBytes = stcp_network_send(sd, passiveHeader, sizeof(STCPHeader), NULL);

        // Verify sending of SYN-ACK packet
        if (sentBytes)
        {
          ctx->connection_state = CSTATE_WAIT_FOR_ACK;
        }
        else
        {
          free(passiveHeader);
          free(ctx);
          stcp_unblock_application(sd);
          errno = ECONNREFUSED; // TODO
          return;
        }

        printf("\nWaiting for ACK");
        // Wait for ACK packet
        event = stcp_wait_for_event(sd, NETWORK_DATA, NULL);

        // if (event == NETWORK_DATA)
        // {
          printf("\nPreparing to unblock the application");
          ssize_t receivedBytes = stcp_network_recv(sd, buffer, sizeof(buffer));
        // }

        // Verify size of received packet
        if (receivedBytes < (int)sizeof(STCPHeader))
        {
          free(ctx);
          stcp_unblock_application(sd);
          errno = ECONNREFUSED; // TODO
          return;
        }

        // Parse received data
        activeHeader = (STCPHeader*)buffer;

        if (activeHeader->th_flags == (TH_ACK))
        {
          ctx->initial_sequence_num = ntohl(activeHeader->th_seq) + 1;
        }
    }

    ctx->connection_state = CSTATE_ESTABLISHED;
    printf("\nConnection Established");
    stcp_unblock_application(sd);

    control_loop(sd, ctx);

    /* do any cleanup here */
    free(ctx);
  }

  /* generate random initial sequence number for an STCP connection */
  static void generate_initial_seq_num(context_t* ctx)
  {
      assert(ctx);
      const unsigned int MAX = 255;

      #ifdef FIXED_INITNUM
        /* please don't change this! */
        ctx->initial_sequence_num = 1;
      #else
        // Generate a random number 1 - 255
        //srand(TIME(NULL));  // seed random number generator
        ctx->initial_sequence_num = rand() % MAX + 1;
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
