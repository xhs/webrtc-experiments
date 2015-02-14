// gcc -DSCTP_DEBUG -o test_sctp_client test_sctp_client.c -I/usr/local/include -L/usr/local/lib -lusrsctp

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
    fprintf(stderr, "usage: %s local_udp_port remote_udp_port server_address server_sctp_port\n", argv[0]);
    return -1;
  }

  usrsctp_init(atoi(argv[1]), NULL, NULL);
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

  struct sockaddr_in server_address;
  memset(&server_address, 0, sizeof server_address);
  inet_pton(AF_INET, argv[3], &server_address.sin_addr);
  server_address.sin_family = AF_INET;
  server_address.sin_port = htons(atoi(argv[4]));

  if (usrsctp_connect(sk, (struct sockaddr *)&server_address, sizeof server_address) < 0) {
    fprintf(stderr, "connect error\n");
    return -1;
  }

  struct webrtc_dcep_open_message open_req;
  memset(&open_req, 0, sizeof open_req);
  open_req.message_type = DATA_CHANNEL_OPEN;
  open_req.channel_type = DATA_CHANNEL_RELIABLE_UNORDERED;

  struct sctp_sndinfo send_info;
  memset(&send_info, 0, sizeof send_info);
  send_info.snd_sid = 0;
  send_info.snd_ppid = htonl(DATA_CHANNEL_PPID_CONTROL);

  int nbytes = usrsctp_sendv(sk, &open_req, sizeof open_req, NULL, 0,
                             &send_info, sizeof send_info, SCTP_SENDV_SNDINFO, 0);
  if (nbytes < 0) {
    fprintf(stderr, "send error\n");
    return -1;
  }

  usrsctp_close(sk);
  while (usrsctp_finish() != 0);

  return 0;
}
