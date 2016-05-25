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

#include "transport.h"
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "mysock.h"
#include "stcp_api.h"

const unsigned int WINDOW_SIZE = 3072;
const unsigned int MAX_IP_PAYLOAD_LEN = 1500;
const unsigned int MSS = 536;

enum {
  CSTATE_ESTABLISHED,
  SYN_SENT,
  SYN_RECEIVED,
  SYN_ACK_RECEIVED,
  SYN_ACK_SENT,
  CSTATE_CLOSED,
  FIN_SENT,
  FIN_RECEIVED
}; /* you should have more states */

typedef struct segment_t {
  unsigned int sequenceNumber;  // segment sequence number
  ssize_t length;               // segment length
  bool acked;  // this segment has been ack (used for sender segment)
  bool fin;    // this is a fin segment
  char* data;  // points to the data
};

/* this structure is global to a mysocket descriptor */
typedef struct context_t {
  bool_t done; /* TRUE once connection is closed */

  unsigned int connection_state;
  unsigned int seq_num;      // next sequence number to send
  unsigned int rec_seq_num;  // next wanted sequence number
  unsigned int rec_wind_size;

  /* any other connection-wide global variables go here */
  struct receriverBuffer* rb;
  struct senderBuffer* sb;
} ctx;

// represent sender windows
struct senderBuffer {
  char buffer[WINDOW_SIZE];
  char* endOfSegment;
  char* endOfAckdSegment;
  unsigned int nextSeq;
  segment_t* segments;
};

struct receriverBuffer {
  char buffer[WINDOW_SIZE];
  char* endOfSegment;
  unsigned int nextSeq;
  segment_t* segments;
};

static void generate_initial_seq_num(context_t* ctx);
static void control_loop(mysocket_t sd, context_t* ctx);
void initializeBuffers(context_t* ctx);
STCPHeader* create_SYN_packet(unsigned int seq, unsigned int ack);
bool send_SYN(mysocket_t sd, context_t* ctx);
void wait_for_SYN_ACK(mysocket_t sd, context_t* ctx);
STCPHeader* create_ACK_packet(unsigned int seq, unsigned int ack);
bool send_ACK(mysocket_t sd, context_t* ctx);
void wait_for_SYN(mysocket_t sd, context_t* ctx);
STCPHeader* create_SYN_ACK_packet(unsigned int seq, unsigned int ack);
bool send_SYN_ACK(mysocket_t sd, context_t* ctx);
void wait_for_ACK(mysocket_t sd, context_t* ctx);
void app_data_event(mysocket_t sd, context_t* ctx);
STCPHeader* create_DATA_packet(unsigned int seq, unsigned int ack,
                               char* payload);
bool send_DATA_packet_network(mysocket_t sd, context_t* ctx, char* payload);
void network_data_event(mysocket_t sd, context_t* ctx);
void send_DATA_packet_app(mysocket_t sd, context_t* ctx, char* payload,
                          size_t length);
void parse_DATA_packet(context_t* ctx, char* payload, bool& isACK, bool& isFIN);
STCPHeader* create_FIN_packet(unsigned int seq, unsigned int ack);
bool send_FIN_packet(mysocket_t sd, context_t* ctx);
void app_close_event(mysocket_t sd, context_t* ctx);

/* initialise the transport layer, and start the main loop, handling
 * any data from the peer or the application.  this function should not
 * return until the connection is closed.
 */
void transport_init(mysocket_t sd, bool_t is_active) {
  context_t* ctx;

  ctx = (context_t*)calloc(1, sizeof(context_t));
  assert(ctx);

  generate_initial_seq_num(ctx);
  printf("Initial sequence number is: %d\n", ctx->seq_num);

  /* XXX: you should send a SYN packet here if is_active, or wait for one
 * to arrive if !is_active.  after the handshake completes, unblock the
 * application with stcp_unblock_application(sd).  you may also use
 * this to communicate an error condition back to the application, e.g.
 * if connection fails; to do so, just set errno appropriately (e.g. to
 * ECONNREFUSED, etc.) before calling the function.
 */
  if (is_active) {  // Client control path, initiate connection
    // Send SYN
    if (!send_SYN(sd, ctx)) return;

    // Wait for SYN-ACK
    wait_for_SYN_ACK(sd, ctx);

    // Send ACK Packet
    if (!send_ACK(sd, ctx)) return;
  } else {  // Server control path, wait for connection
    wait_for_SYN(sd, ctx);

    if (!send_SYN_ACK(sd, ctx)) return;

    wait_for_ACK(sd, ctx);
    ctx->connection_state = CSTATE_ESTABLISHED;
  }

  stcp_unblock_application(sd);

  control_loop(sd, ctx);

  /* do any cleanup here */
  free(ctx);
}

/* generate random initial sequence number for an STCP connection */
static void generate_initial_seq_num(context_t* ctx) {
  assert(ctx);
  const unsigned int MAX = 255;

#ifdef FIXED_INITNUM
  /* please don't change this! */
  ctx->seq_num = 1;
#else
  /* you have to fill this up */
  /*ctx->seq_num =;*/
  srand(time(NULL));  // seed random number generator
  ctx->seq_num = rand() % MAX + 1;
#endif
}

/* control_loop() is the main STCP loop; it repeatedly waits for one of the
 * following to happen:
 *   - incoming data from the peer
 *   - new data from the application (via mywrite())
 *   - the socket to be closed (via myclose())
 *   - a timeout
 */
static void control_loop(mysocket_t sd, context_t* ctx) {
  assert(ctx);
  assert(!ctx->done);

  while (!ctx->done) {
    if (ctx->connection_state == CSTATE_CLOSED) {
      ctx->done = true;
      continue;
    }

    unsigned int event = stcp_wait_for_event(sd, ANY_EVENT, NULL);

    if (event == APP_DATA) {
      app_data_event(sd, ctx);
    }

    if (event == NETWORK_DATA) {
      network_data_event(sd, ctx);
    }

    if (event == APP_CLOSE_REQUESTED) {
      app_close_event(sd, ctx);
    }

    if (event == ANY_EVENT) {
      printf("ANY_EVENT\n");
    }
  }
}

STCPHeader* create_SYN_packet(unsigned int seq, unsigned int ack) {
  printf("Create SYN packet, seq: %d, ack: %d\n", seq, ack);
  STCPHeader* SYN_packet = (STCPHeader*)malloc(sizeof(STCPHeader));
  SYN_packet->th_seq = htonl(seq);
  SYN_packet->th_ack = htonl(ack);
  SYN_packet->th_off = 5;         // header size offset for packed data
  SYN_packet->th_flags = TH_SYN;  // set packet type to SYN
  SYN_packet->th_win = htons(WINDOW_SIZE);  // default value
  return SYN_packet;
}

bool send_SYN(mysocket_t sd, context_t* ctx) {
  // Create SYN Packet
  STCPHeader* SYN_packet = create_SYN_packet(ctx->seq_num, 0);
  ctx->seq_num++;

  // Send SYN packet
  ssize_t sentBytes =
      stcp_network_send(sd, SYN_packet, sizeof(STCPHeader), NULL);
  printf("Sent SYN packet: %d bytes\n", sentBytes);

  // Verify sending of SYN packet
  if (sentBytes > 0) {  // If SYN packet suucessfully sent
    printf("SYN packet successfully sent\n");

    ctx->connection_state = SYN_SENT;
    free(SYN_packet);
    return true;
  } else {
    printf("SYN packet did not send\n");
    printf("Close connection\n");

    free(SYN_packet);
    free(ctx);
    stcp_unblock_application(sd);
    errno = ECONNREFUSED;  // TODO
    return false;
  }
}

void wait_for_SYN_ACK(mysocket_t sd, context_t* ctx) {
  printf("Waiting for SYN-ACK\n");
  char buffer[sizeof(STCPHeader)];

  unsigned int event = stcp_wait_for_event(sd, NETWORK_DATA, NULL);

  printf("Received NETWORK_DATA event\n");

  ssize_t receivedBytes = stcp_network_recv(sd, buffer, MAX_IP_PAYLOAD_LEN);
  printf("Received packet: %d bytes\n", receivedBytes);

  // Verify size of received packet
  if (receivedBytes < sizeof(STCPHeader)) {
    printf("Received NETWORK_DATA event packet < sizeof(STCPHeader)\n");
    printf("Close connection\n");

    free(ctx);
    stcp_unblock_application(sd);
    errno = ECONNREFUSED;  // TODO
    return;
  }

  // Parse received data
  STCPHeader* receivedPacket = (STCPHeader*)buffer;

  // Check for appropriate flags and set connection state
  if (receivedPacket->th_flags == (TH_ACK | TH_SYN)) {
    printf("Received SYN_ACK packet\n");
    printf("Received SYN_ACK th_seq: %d\n", ntohl(receivedPacket->th_seq));
    printf("Setting ctx->rec_seq_num: %d\n", ntohl(receivedPacket->th_seq));
    printf("Received SYN_ACK th_win: %d\n", ntohs(receivedPacket->th_win));

    ctx->rec_seq_num = ntohl(receivedPacket->th_seq);
    ctx->rec_wind_size = ntohs(receivedPacket->th_win);
    ctx->connection_state = SYN_ACK_RECEIVED;
  }
}

STCPHeader* create_ACK_packet(unsigned int seq, unsigned int ack) {
  printf("Create ACK packet, seq: %d, ack: %d\n", seq, ack);
  STCPHeader* ACK_packet = (STCPHeader*)malloc(sizeof(STCPHeader));
  ACK_packet->th_seq = htonl(seq);
  ACK_packet->th_ack = htonl(ack);
  ACK_packet->th_off = 5;         // header size offset for packed data
  ACK_packet->th_flags = TH_ACK;  // set packet type to ACK
  ACK_packet->th_win = htons(WINDOW_SIZE);  // default value
  return ACK_packet;
}

bool send_ACK(mysocket_t sd, context_t* ctx) {
  // Create ACK Packet
  STCPHeader* ACK_packet =
      create_ACK_packet(ctx->seq_num, ctx->rec_seq_num + 1);

  // Send ACK packet
  ssize_t sentBytes =
      stcp_network_send(sd, ACK_packet, sizeof(STCPHeader), NULL);
  printf("Sent ACK packet: %d bytes\n", sentBytes);

  // Verify sending of ACK packet
  if (sentBytes > 0) {  // If ACK packet suucessfully sent
    printf("ACK packet successfully sent\n");
    ctx->connection_state = SYN_SENT;
    free(ACK_packet);
    return true;
  } else {
    printf("ACK packet did not send\n");
    printf("Close connection\n");

    free(ACK_packet);
    free(ctx);
    stcp_unblock_application(sd);
    errno = ECONNREFUSED;  // TODO
    return false;
  }
}

void wait_for_SYN(mysocket_t sd, context_t* ctx) {
  printf("Waiting for SYN\n");
  char buffer[sizeof(STCPHeader)];

  unsigned int event = stcp_wait_for_event(sd, NETWORK_DATA, NULL);

  printf("Received NETWORK_DATA event\n");

  ssize_t receivedBytes = stcp_network_recv(sd, buffer, MAX_IP_PAYLOAD_LEN);
  printf("Received packet: %d bytes\n", receivedBytes);

  // Verify size of received packet
  if (receivedBytes < sizeof(STCPHeader)) {
    printf("Received NETWORK_DATA event packet < sizeof(STCPHeader)\n");
    printf("Close connection\n");

    free(ctx);
    stcp_unblock_application(sd);
    errno = ECONNREFUSED;  // TODO
    return;
  }

  // Parse received data
  STCPHeader* receivedPacket = (STCPHeader*)buffer;

  // Check for appropriate flags and set connection state
  if (receivedPacket->th_flags == TH_SYN) {
    printf("Received SYN packet\n");
    printf("Received SYN th_seq: %d\n", ntohl(receivedPacket->th_seq));
    printf("Setting ctx->rec_seq_num: %d\n", ntohl(receivedPacket->th_seq));
    printf("Received SYN th_win: %d\n", ntohs(receivedPacket->th_win));

    ctx->rec_seq_num = ntohl(receivedPacket->th_seq);
    ctx->rec_wind_size = ntohs(receivedPacket->th_win);
    ctx->connection_state = SYN_RECEIVED;
  }
}

STCPHeader* create_SYN_ACK_packet(unsigned int seq, unsigned int ack) {
  printf("Create SYN_ACK packet, seq: %d, ack: %d\n", seq, ack);
  STCPHeader* SYN_ACK_packet = (STCPHeader*)malloc(sizeof(STCPHeader));
  SYN_ACK_packet->th_seq = htonl(seq);
  SYN_ACK_packet->th_ack = htonl(ack);
  SYN_ACK_packet->th_off = 5;  // header size offset for packed data
  SYN_ACK_packet->th_flags = (TH_SYN | TH_ACK);  // set packet type to SYN_ACK
  SYN_ACK_packet->th_win = htons(WINDOW_SIZE);   // default value
  return SYN_ACK_packet;
}

bool send_SYN_ACK(mysocket_t sd, context_t* ctx) {
  // Create SYN_ACK Packet
  STCPHeader* SYN_ACK_packet =
      create_SYN_ACK_packet(ctx->seq_num, ctx->rec_seq_num + 1);
  ctx->seq_num++;

  // Send SYN_ACK packet
  ssize_t sentBytes =
      stcp_network_send(sd, SYN_ACK_packet, sizeof(STCPHeader), NULL);
  printf("Sent SYN_ACK packet: %d bytes\n", sentBytes);

  // Verify sending of SYN_ACK packet
  if (sentBytes > 0) {  // If SYN_ACK packet suucessfully sent
    printf("SYN_ACK packet successfully sent\n");
    ctx->connection_state = SYN_SENT;
    free(SYN_ACK_packet);
    return true;
  } else {
    printf("SYN_ACK packet did not send\n");
    printf("Close connection\n");

    free(SYN_ACK_packet);
    free(ctx);
    stcp_unblock_application(sd);
    errno = ECONNREFUSED;  // TODO
    return false;
  }
}

void wait_for_ACK(mysocket_t sd, context_t* ctx) {
  printf("Waiting for ACK\n");
  char buffer[sizeof(STCPHeader)];

  unsigned int event = stcp_wait_for_event(sd, NETWORK_DATA, NULL);

  printf("Received NETWORK_DATA event\n");

  ssize_t receivedBytes = stcp_network_recv(sd, buffer, MAX_IP_PAYLOAD_LEN);
  printf("Received packet: %d bytes\n", receivedBytes);

  // Verify size of received packet
  if (receivedBytes < sizeof(STCPHeader)) {
    printf("Received NETWORK_DATA event packet < sizeof(STCPHeader)\n");
    printf("Close connection\n");

    free(ctx);
    stcp_unblock_application(sd);
    errno = ECONNREFUSED;  // TODO
    return;
  }

  // Parse received data
  STCPHeader* receivedPacket = (STCPHeader*)buffer;

  // Check for appropriate flags and set connection state
  if (receivedPacket->th_flags == TH_ACK) {
    printf("Received ACK packet\n");
    printf("Received ACK th_seq: %d\n", ntohl(receivedPacket->th_seq));
    printf("Setting ctx->rec_seq_num: %d\n", ntohl(receivedPacket->th_seq));
    printf("Received ACK th_win: %d\n", ntohs(receivedPacket->th_win));

    ctx->rec_seq_num = ntohl(receivedPacket->th_seq);
    ctx->rec_wind_size = ntohs(receivedPacket->th_win);
  }
}

void app_data_event(mysocket_t sd, context_t* ctx) {
  printf("Entered App Data Event\n");

  size_t max_payload_length = MSS - sizeof(STCPHeader);
  char payload[max_payload_length];
  ssize_t app_bytes = stcp_app_recv(sd, payload, max_payload_length);

  if (app_bytes == 0) {
    printf("Received app_data event packet < sizeof(STCPHeader)\n");
    printf("Close connection\n");

    free(ctx);
    stcp_unblock_application(sd);
    errno = ECONNREFUSED;  // TODO
    return;
  }

  if (!send_DATA_packet_network(sd, ctx, payload)) return;
}

void app_close_event(mysocket_t sd, context_t* ctx) {
  printf("Entered app close event\n");

  if (ctx->connection_state == CSTATE_ESTABLISHED) {
    if (!send_FIN_packet(sd, ctx)) return;
    ctx->connection_state = FIN_SENT;
  }
}

STCPHeader* create_FIN_packet(unsigned int seq, unsigned int ack) {
  printf("Create FIN packet, seq: %d, ack: %d\n", seq, ack);
  STCPHeader* FIN_packet = (STCPHeader*)malloc(sizeof(STCPHeader));

  FIN_packet->th_seq = htonl(seq);
  FIN_packet->th_ack = htonl(ack);
  FIN_packet->th_flags = TH_FIN;
  FIN_packet->th_win = htons(WINDOW_SIZE);
  FIN_packet->th_off = 5;

  return FIN_packet;
}

bool send_FIN_packet(mysocket_t sd, context_t* ctx) {
  STCPHeader* FIN_packet =
      create_FIN_packet(ctx->seq_num, ctx->rec_seq_num + 1);
  ctx->seq_num++;

  // Send FIN packet
  ssize_t sentBytes =
      stcp_network_send(sd, FIN_packet, sizeof(STCPHeader), NULL);
  printf("Sent DATA packet: %d bytes\n", sentBytes);

  // Verify sending of FIN packet
  if (sentBytes > 0) {  // If FIN packet suucessfully sent
    printf("FIN packet successfully sent to network\n");
    free(FIN_packet);
    return true;
  } else {
    printf("FIN packet did not send to network\n");
    printf("Close connection\n");

    free(FIN_packet);
    free(ctx);
    stcp_unblock_application(sd);
    errno = ECONNREFUSED;  // TODO
    return false;
  }
}

void network_data_event(mysocket_t sd, context_t* ctx) {
  bool isACK = false;
  bool isFIN = false;
  printf("Entered network data Event\n");
  char payload[WINDOW_SIZE];

  ssize_t network_bytes = stcp_network_recv(sd, payload, WINDOW_SIZE);
  printf("*Received network data: %d bytes\n", network_bytes);
  if (network_bytes < sizeof(STCPHeader)) {
    printf("Received NETWORK_DATA event packet < sizeof(STCPHeader)\n");
    // printf("Close connection\n");

    // free(ctx);
    // stcp_unblock_application(sd);
    errno = ECONNREFUSED;  // TODO
    return;
  }

  parse_DATA_packet(ctx, payload, isACK, isFIN);
  if (isACK) {
    printf("isACK\n");
    if (ctx->connection_state == FIN_RECEIVED) {
      ctx->connection_state = CSTATE_CLOSED;
    }
  } else if (isFIN) {
    printf("isFIN\n");
    ctx->connection_state = FIN_RECEIVED;
    stcp_fin_received(sd);
  }
  if (network_bytes - sizeof(STCPHeader)) {
    printf("send DATA packet to APP\n");
    send_DATA_packet_app(sd, ctx, payload, network_bytes);
  }
}

void send_DATA_packet_app(mysocket_t sd, context_t* ctx, char* payload,
                          size_t length) {
  // Send DATA packet
  stcp_app_send(sd, payload + sizeof(STCPHeader), length - sizeof(STCPHeader));
}

void parse_DATA_packet(context_t* ctx, char* payload, bool& isACK,
                       bool& isFIN) {
  STCPHeader* payloadHeader = (STCPHeader*)payload;
  ctx->rec_seq_num = ntohl(payloadHeader->th_seq);
  ctx->rec_wind_size = ntohs(payloadHeader->th_win);
  isACK = payloadHeader->th_ack == TH_ACK;
  isACK = payloadHeader->th_ack == TH_FIN;
  printf("Received network_event DATA packet\n");
  printf("Received network_event DATA th_seq: %d\n",
         ntohl(payloadHeader->th_seq));
  printf("Setting ctx->rec_seq_num: %d\n", ntohl(payloadHeader->th_seq));
  printf("*Received network_event DATA th_win: %d\n",
         ntohs(payloadHeader->th_win));
}

STCPHeader* create_DATA_packet(unsigned int seq, unsigned int ack,
                               char* payload) {
  printf("Create DATA packet, seq: %d, ack: %d\n", seq, ack);
  unsigned int DATA_packet_size = sizeof(STCPHeader) + sizeof(payload);
  STCPHeader* DATA_packet = (STCPHeader*)malloc(DATA_packet_size);

  DATA_packet->th_seq = htonl(seq);
  DATA_packet->th_ack = htonl(ack);
  DATA_packet->th_flags = 0;
  DATA_packet->th_win = htons(WINDOW_SIZE);
  DATA_packet->th_off = 5;

  memcpy((char*)DATA_packet + sizeof(STCPHeader), payload, sizeof(payload));
  return DATA_packet;
}

bool send_DATA_packet_network(mysocket_t sd, context_t* ctx, char* payload) {
  STCPHeader* DATA_packet =
      create_DATA_packet(ctx->seq_num, ctx->rec_seq_num + 1, payload);
  ctx->seq_num += sizeof(payload);

  // Send DATA packet
  ssize_t sentBytes = stcp_network_send(
      sd, DATA_packet, sizeof(STCPHeader) + sizeof(payload), NULL);
  printf("Sent DATA packet: %d bytes\n", sentBytes);

  if (sentBytes > 0) {  // If SYN_ACK packet suucessfully sent
    printf("DATA packet successfully sent to network\n");
    free(DATA_packet);
    return true;
  } else {
    printf("DATA packet did not send to network\n");
    printf("Close connection\n");

    free(DATA_packet);
    free(ctx);
    stcp_unblock_application(sd);
    errno = ECONNREFUSED;  // TODO
    return false;
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
void our_dprintf(const char* format, ...) {
  va_list argptr;
  char buffer[1024];

  assert(format);
  va_start(argptr, format);
  vsnprintf(buffer, sizeof(buffer), format, argptr);
  va_end(argptr);
  fputs(buffer, stdout);
  fflush(stdout);
}
