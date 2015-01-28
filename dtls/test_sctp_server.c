// gcc -DSCTP_DEBUG -o test_sctp_server test_sctp_server.c -I/usr/local/include -L/usr/local/lib -lusrsctp

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

#define BUFFER_SIZE (1 << 16)
#define SCTP_DEBUG_NONE 0

#define DATA_CHANNEL_PPID_CONTROL      50
#define DATA_CHANNEL_PPID_STRING       51
#define DATA_CHANNEL_PPID_STRING_EMPTY 56
#define DATA_CHANNEL_PPID_BINARY       53
#define DATA_CHANNEL_PPID_BINARY_EMPTY 57

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
  if (argc != 5) {
    fprintf(stderr, "usage: %s local_udp_port remote_udp_port listen_address listen_sctp_port\n", argv[0]);
    return -1;
  }

  usrsctp_init(atoi(argv[1]));
  usrsctp_sysctl_set_sctp_debug_on(SCTP_DEBUG_NONE);

  struct socket *sk = usrsctp_socket(AF_INET, SOCK_STREAM, IPPROTO_SCTP, NULL, NULL, 0, NULL);
  if (sk == NULL) {
    fprintf(stderr, "socket error\n");
    return -1;
  }

  struct sctp_udpencaps udpencaps;
  memset(&udpencaps, 0, sizeof udpencaps);
  udpencaps.sue_address.ss_family = AF_INET;
  udpencaps.sue_port = htons(atoi(argv[2]));
  usrsctp_setsockopt(sk, IPPROTO_SCTP, SCTP_REMOTE_UDP_ENCAPS_PORT, &udpencaps, sizeof udpencaps);

  struct sockaddr_in listen_address;
  memset(&listen_address, 0, sizeof listen_address);
  inet_pton(AF_INET, argv[3], &listen_address.sin_addr);
  listen_address.sin_family = AF_INET;
  listen_address.sin_port = htons(atoi(argv[4]));

  if (usrsctp_bind(sk, (struct sockaddr *)&listen_address, sizeof listen_address) < 0) {
    fprintf(stderr, "connect error\n");
    return -1;
  }

  if (usrsctp_listen(sk, 1) < 0) {
    fprintf(stderr, "listen error\n");
    return -1;
  }

  char buf[BUFFER_SIZE];
  struct sockaddr_in client_address;
  int addr_len;
  struct sctp_rcvinfo info;
  int info_len;
  unsigned int info_type;
  int message_flags;
  while (1) {
    addr_len = sizeof client_address;
    info_len = sizeof info;
    info_type = 0;
    message_flags = 0;

    int nbytes = usrsctp_recvv(sk, buf, sizeof buf, (struct sockaddr *)&client_address, (socklen_t *)&addr_len,
                               &info, (socklen_t *)&info_len, &info_type, &message_flags);
  }

  usrsctp_close(sk);
  while (usrsctp_finish() != 0);

  return 0;
}
