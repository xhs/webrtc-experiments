// gcc -o test_rtcdc_over_sctp test_rtcdc_over_sctp.c -I/usr/local/include -L/usr/local/lib -lusrsctp

#include <poll.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>

#include <usrsctp.h>

#define DTLS_CLIENT_PORT   "60001"
#define DTLS_SERVER_PORT   "60002"
#define SOCKET_CLIENT_PORT "60003"
#define SOCKET_SERVER_PORT "60004"
#define BUFFER_SIZE 2048

#define DATA_CHANNEL_OPEN 0x03
#define DATA_CHANNEL_ACK  0x02

#define DATA_CHANNEL_RELIABLE_ORDERED                  0x00
#define DATA_CHANNEL_RELIABLE_UNORDERED                0x80
#define DATA_CHANNEL_PARTIAL_RELIABLE_REXMIT           0x01
#define DATA_CHANNEL_PARTIAL_RELIABLE_REXMIT_UNORDERED 0x81
#define DATA_CHANNEL_PARTIAL_RELIABLE_TIMED            0x02
#define DATA_CHANNEL_PARTIAL_RELIABLE_TIMED_UNORDERED  0x82

struct __attribute__((packed, aligned(1))) webrtc_dcep_open_message {
  uint8_t message_type;
  uint8_t channel_type;
  uint16_t priority;
  uint32_t reliability;
  uint16_t label_length;
  uint16_t protocol_length;
  char label_protocol[0];
};

struct __attribute__((packed, aligned(1))) webrtc_dcep_ack_message {
  uint8_t message_type;
};

int main(int argc, char *argv[])
{
  return 0;
}
