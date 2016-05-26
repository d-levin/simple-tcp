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

struct timespec spec;

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
                               char* payload, size_t payload_length);
bool send_DATA_packet_network(mysocket_t sd, context_t* ctx, char* payload,
                              size_t payload_length);
void network_data_event(mysocket_t sd, context_t* ctx);
void send_DATA_packet_app(mysocket_t sd, context_t* ctx, char* payload,
                          size_t length);
void parse_DATA_packet(context_t* ctx, char* payload, bool& isACK, bool& isFIN);
STCPHeader* create_FIN_packet(unsigned int seq, unsigned int ack);
bool send_FIN_packet(mysocket_t sd, context_t* ctx);
void app_close_event(mysocket_t sd, context_t* ctx);
void printSTCPHeader(STCPHeader* print);

/* initialise the transport layer, and start the main loop, handling
 * any data from the peer or the application.  this function should not
 * return until the connection is closed.
 */
void transport_init(mysocket_t sd, bool_t is_active) {
  context_t* ctx;

  ctx = (context_t*)calloc(1, sizeof(context_t));
  assert(ctx);

  generate_initial_seq_num(ctx);

  if (is_active) {  // Client control path, initiate connection
    ctx->seq_num = 1;
    // Send SYN
    if (!send_SYN(sd, ctx)) return;

    // Wait for SYN-ACK
    wait_for_SYN_ACK(sd, ctx);

    // Send ACK Packet
    if (!send_ACK(sd, ctx)) return;
  } else {  // Server control path, wait for connection
    ctx->seq_num = 101;
    wait_for_SYN(sd, ctx);

    if (!send_SYN_ACK(sd, ctx)) return;

    wait_for_ACK(sd, ctx);
  }
  ctx->connection_state = CSTATE_ESTABLISHED;
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
  int count = 0;

  while (!ctx->done) {
    if (ctx->connection_state == CSTATE_CLOSED) {
      ctx->done = true;
      break;
    }

    unsigned int event = stcp_wait_for_event(sd, ANY_EVENT, NULL);

    if (event == APP_DATA) {
      clock_gettime(CLOCK_REALTIME, &spec);
      printf("%d APP DATA EVENT\n", spec.tv_nsec);
      app_data_event(sd, ctx);
    }

    if (event == NETWORK_DATA) {
      clock_gettime(CLOCK_REALTIME, &spec);
      printf("%d NETWORK DATA EVENT\n", spec.tv_nsec);
      network_data_event(sd, ctx);
    }

    if (event == APP_CLOSE_REQUESTED) {
      clock_gettime(CLOCK_REALTIME, &spec);
      printf("%d APP CLOSE EVENT\n", spec.tv_nsec);
      app_close_event(sd, ctx);
    }

    if (event == ANY_EVENT) {
      clock_gettime(CLOCK_REALTIME, &spec);
      printf("%d ANY EVENT\n", spec.tv_nsec);
    }
  }
}

STCPHeader* create_SYN_packet(unsigned int seq, unsigned int ack) {
  STCPHeader* SYN_packet = (STCPHeader*)malloc(sizeof(STCPHeader));
  SYN_packet->th_seq = htonl(seq);
  SYN_packet->th_ack = htonl(ack);
  SYN_packet->th_off = htons(5);  // header size offset for packed data
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

  // Verify sending of SYN packet
  if (sentBytes > 0) {  // If SYN packet suucessfully sent

    ctx->connection_state = SYN_SENT;
    free(SYN_packet);
    return true;
  } else {
    free(SYN_packet);
    free(ctx);
    stcp_unblock_application(sd);
    errno = ECONNREFUSED;
    return false;
  }
}

void wait_for_SYN_ACK(mysocket_t sd, context_t* ctx) {
  char buffer[sizeof(STCPHeader)];

  unsigned int event = stcp_wait_for_event(sd, NETWORK_DATA, NULL);

  ssize_t receivedBytes = stcp_network_recv(sd, buffer, MAX_IP_PAYLOAD_LEN);

  // Verify size of received packet
  if (receivedBytes < sizeof(STCPHeader)) {
    free(ctx);
    stcp_unblock_application(sd);
    errno = ECONNREFUSED;  // TODO
    return;
  }

  // Parse received data
  STCPHeader* receivedPacket = (STCPHeader*)buffer;

  // Check for appropriate flags and set connection state
  if (receivedPacket->th_flags == (TH_ACK | TH_SYN)) {
    ctx->rec_seq_num = ntohl(receivedPacket->th_seq);
    ctx->rec_wind_size = ntohs(receivedPacket->th_win);
    ctx->connection_state = SYN_ACK_RECEIVED;
  }
}

STCPHeader* create_ACK_packet(unsigned int seq, unsigned int ack) {
  STCPHeader* ACK_packet = (STCPHeader*)malloc(sizeof(STCPHeader));
  ACK_packet->th_seq = htonl(seq);
  ACK_packet->th_ack = htonl(ack);
  ACK_packet->th_off = htons(5);  // header size offset for packed data
  ACK_packet->th_flags = TH_ACK;  // set packet type to ACK
  ACK_packet->th_win = htons(WINDOW_SIZE);  // default value
  return ACK_packet;
}

bool send_ACK(mysocket_t sd, context_t* ctx) {
  printf("Sending ACK\n");
  // Create ACK Packet
  STCPHeader* ACK_packet =
      create_ACK_packet(ctx->seq_num, ctx->rec_seq_num + 1);

  // Send ACK packet
  ssize_t sentBytes =
      stcp_network_send(sd, ACK_packet, sizeof(STCPHeader), NULL);

  // Verify sending of ACK packet
  if (sentBytes > 0) {  // If ACK packet suucessfully sent
    ctx->connection_state = SYN_SENT;
    free(ACK_packet);
    return true;
  } else {
    free(ACK_packet);
    free(ctx);
    stcp_unblock_application(sd);
    errno = ECONNREFUSED;  // TODO
    return false;
  }
}

void wait_for_SYN(mysocket_t sd, context_t* ctx) {
  char buffer[sizeof(STCPHeader)];

  unsigned int event = stcp_wait_for_event(sd, NETWORK_DATA, NULL);

  ssize_t receivedBytes = stcp_network_recv(sd, buffer, MAX_IP_PAYLOAD_LEN);

  // Verify size of received packet
  if (receivedBytes < sizeof(STCPHeader)) {
    free(ctx);
    stcp_unblock_application(sd);
    errno = ECONNREFUSED;  // TODO
    return;
  }

  // Parse received data
  STCPHeader* receivedPacket = (STCPHeader*)buffer;

  // Check for appropriate flags and set connection state
  if (receivedPacket->th_flags == TH_SYN) {
    ctx->rec_seq_num = ntohl(receivedPacket->th_seq);
    ctx->rec_wind_size = ntohs(receivedPacket->th_win);
    ctx->connection_state = SYN_RECEIVED;
  }
}

STCPHeader* create_SYN_ACK_packet(unsigned int seq, unsigned int ack) {
  STCPHeader* SYN_ACK_packet = (STCPHeader*)malloc(sizeof(STCPHeader));
  SYN_ACK_packet->th_seq = htonl(seq);
  SYN_ACK_packet->th_ack = htonl(ack);
  SYN_ACK_packet->th_off = htons(5);  // header size offset for packed data
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

  // Verify sending of SYN_ACK packet
  if (sentBytes > 0) {  // If SYN_ACK packet suucessfully sent
    ctx->connection_state = SYN_SENT;
    free(SYN_ACK_packet);
    return true;
  } else {
    free(SYN_ACK_packet);
    free(ctx);
    stcp_unblock_application(sd);
    errno = ECONNREFUSED;  // TODO
    return false;
  }
}

void wait_for_ACK(mysocket_t sd, context_t* ctx) {
  char buffer[sizeof(STCPHeader)];

  unsigned int event = stcp_wait_for_event(sd, NETWORK_DATA, NULL);

  ssize_t receivedBytes = stcp_network_recv(sd, buffer, MAX_IP_PAYLOAD_LEN);

  // Verify size of received packet
  if (receivedBytes < sizeof(STCPHeader)) {
    free(ctx);
    stcp_unblock_application(sd);
    errno = ECONNREFUSED;  // TODO
    return;
  }

  // Parse received data
  STCPHeader* receivedPacket = (STCPHeader*)buffer;

  printf("Received ACK\n");
  printSTCPHeader(receivedPacket);

  // Check for appropriate flags and set connection state
  if (receivedPacket->th_flags == TH_ACK) {
    ctx->rec_seq_num = ntohl(receivedPacket->th_seq);
    ctx->rec_wind_size = ntohs(receivedPacket->th_win);
  }
}

void app_data_event(mysocket_t sd, context_t* ctx) {
  size_t max_payload_length = MSS - sizeof(STCPHeader);
  char payload[max_payload_length];
  ssize_t app_bytes = stcp_app_recv(sd, payload, max_payload_length);
  printf("App Data Bytes: %d\n", app_bytes);
  printf("App Data Payload: %s\n", payload);

  if (app_bytes == 0) {
    free(ctx);
    stcp_unblock_application(sd);
    errno = ECONNREFUSED;  // TODO
    return;
  }

  send_DATA_packet_network(sd, ctx, payload, app_bytes);
  wait_for_ACK(sd, ctx);
}

void app_close_event(mysocket_t sd, context_t* ctx) {
  if (ctx->connection_state == CSTATE_ESTABLISHED) {
    if (!send_FIN_packet(sd, ctx)) return;
    ctx->connection_state = FIN_SENT;
  }
}

STCPHeader* create_FIN_packet(unsigned int seq, unsigned int ack) {
  STCPHeader* FIN_packet = (STCPHeader*)malloc(sizeof(STCPHeader));
  FIN_packet->th_seq = htonl(seq);
  FIN_packet->th_ack = htonl(ack);
  FIN_packet->th_flags = TH_FIN;
  FIN_packet->th_win = htons(WINDOW_SIZE);
  FIN_packet->th_off = htons(5);
  return FIN_packet;
}

bool send_FIN_packet(mysocket_t sd, context_t* ctx) {
  STCPHeader* FIN_packet =
      create_FIN_packet(ctx->seq_num, ctx->rec_seq_num + 1);
  ctx->seq_num++;

  // Send FIN packet
  ssize_t sentBytes =
      stcp_network_send(sd, FIN_packet, sizeof(STCPHeader), NULL);

  // Verify sending of FIN packet
  if (sentBytes > 0) {  // If FIN packet suucessfully sent
    free(FIN_packet);
    return true;
  } else {
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
  char payload[WINDOW_SIZE];

  ssize_t network_bytes = stcp_network_recv(sd, payload, WINDOW_SIZE);
  if (network_bytes < sizeof(STCPHeader)) {
    free(ctx);
    stcp_unblock_application(sd);
    errno = ECONNREFUSED;  // TODO
    return;
  }

  printSTCPHeader((STCPHeader*)payload);
  printf("Network Data Payload: %s\n", payload + sizeof(STCPHeader));
  printf("Network Bytes: %d\n", network_bytes);

  parse_DATA_packet(ctx, payload, isACK, isFIN);
  if (isACK) {
    clock_gettime(CLOCK_REALTIME, &spec);
    printf("%d isACK\n", spec.tv_nsec);
    if (ctx->connection_state == FIN_RECEIVED) {
      ctx->connection_state = CSTATE_CLOSED;
    }
  }
  if (isFIN) {
    clock_gettime(CLOCK_REALTIME, &spec);
    printf("%d isFIN\n", spec.tv_nsec);
    ctx->connection_state = FIN_RECEIVED;
    stcp_fin_received(sd);
    send_ACK(sd, ctx);
  }
  if (network_bytes - sizeof(STCPHeader)) {
    printf("isDATA\n");
    send_DATA_packet_app(sd, ctx, payload, network_bytes);
    send_ACK(sd, ctx);
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
  isFIN = payloadHeader->th_flags == TH_FIN;
}

STCPHeader* create_DATA_packet(unsigned int seq, unsigned int ack,
                               char* payload, size_t payload_length) {
  printf("Create DATA Packet Payload: %s\n", payload);
  unsigned int DATA_packet_size = sizeof(STCPHeader) + payload_length;
  printf("DATA Packet Payload Size: %d\n", DATA_packet_size);
  STCPHeader* DATA_packet = (STCPHeader*)malloc(DATA_packet_size);

  DATA_packet->th_seq = htonl(seq);
  DATA_packet->th_ack = htonl(ack);
  DATA_packet->th_flags = NETWORK_DATA;
  DATA_packet->th_win = htons(WINDOW_SIZE);
  DATA_packet->th_off = htons(5);

  memcpy((char*)DATA_packet + sizeof(STCPHeader), payload, payload_length);
  return DATA_packet;
}

bool send_DATA_packet_network(mysocket_t sd, context_t* ctx, char* payload,
                              size_t payload_length) {
  STCPHeader* DATA_packet = create_DATA_packet(
      ctx->seq_num, ctx->rec_seq_num + 1, payload, payload_length);
  printSTCPHeader(DATA_packet);
  ctx->seq_num += payload_length;

  // Send DATA packet
  ssize_t sentBytes = stcp_network_send(
      sd, DATA_packet, sizeof(STCPHeader) + payload_length, NULL);
  printf("Network Sent Bytes: %d\n", sentBytes);

  if (sentBytes > 0) {  // If SYN_ACK packet suucessfully sent
    free(DATA_packet);
    return true;
  } else {
    free(DATA_packet);
    free(ctx);
    stcp_unblock_application(sd);
    errno = ECONNREFUSED;  // TODO
    return false;
  }
}

void printSTCPHeader(STCPHeader* print) {
  printf("\n****HEADER****\n");
  printf("th_sport: %d\n", ntohs(print->th_sport)); /* source port */
  printf("th_dport: %d\n", ntohs(print->th_dport)); /* destination port */
  printf("th_seq: %d\n", ntohl(print->th_seq));     /* sequence number */
  printf("th_ack: %d\n", ntohl(print->th_ack));     /* acknowledgement number */
  printf("th_flags: %d\n", print->th_flags);
  printf("th_win: %d\n", ntohs(print->th_win)); /* window */
  printf("th_off: %d\n", ntohs(print->th_off));
  printf("th_sum: %d\n", ntohs(print->th_sum)); /* checksum */
  printf("th_urp: %d\n",
         ntohs(print->th_urp)); /* urgent pointer (unused in STCP) */
  printf("\n****HEADER****\n\n");
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
