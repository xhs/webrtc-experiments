// gcc -o test_udp_client test_udp_client.c

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

const char *usage =
"usage:\n"
"  %s address port\n";

const char *data = "hello, foobar";

int main(int argc, char *argv[]) {
  if (argc != 3) {
    fprintf(stderr, usage, argv[0]);
    return 1;
  }

  int ecode, sockfd;
  struct addrinfo hints, *servinfo, *p;

  memset(&hints, 0, sizeof hints);
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_DGRAM;
  
  if ((ecode = getaddrinfo(argv[1], argv[2], &hints, &servinfo)) != 0) {
    fprintf(stderr, "getaddrinfo error: %s\n", gai_strerror(ecode));
    return 1;
  }

  for (p = servinfo; p; p = p->ai_next) {
    if ((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
      fprintf(stderr, "socket error\n");
      continue;
    }

    if (connect(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
      close(sockfd);
      fprintf(stderr, "connect error\n");
      continue;
    }

    break;
  }

  if (p == NULL) {
    fprintf(stderr, "network error\n");
    return 1;
  }

  freeaddrinfo(servinfo);

  if (send(sockfd, data, strlen(data), 0) == -1) {
    fprintf(stderr, "send error\n");
    close(sockfd);
    return 1;
  }

  close(sockfd);

  return 0;
}
