// gcc -o test_udp_server test_udp_server.c

#include <sys/poll.h>
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
"  %s port\n";

char buf[1 << 16];

int main(int argc, char *argv[]) {
  if (argc != 2) {
    fprintf(stderr, usage, argv[0]);
    return 1;
  }

  int ecode, sockfd, numbytes, n;
  struct addrinfo hints, *servinfo, *p;
  struct pollfd ufds[1];

  memset(&hints, 0, sizeof hints);
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_flags = AI_PASSIVE;
  
  if ((ecode = getaddrinfo(NULL, argv[1], &hints, &servinfo)) != 0) {
    fprintf(stderr, "getaddrinfo error: %s\n", gai_strerror(ecode));
    return 1;
  }

  for (p = servinfo; p; p = p->ai_next) {
    if ((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
      fprintf(stderr, "socket error\n");
      continue;
    }

    if (bind(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
      close(sockfd);
      fprintf(stderr, "bind error\n");
      continue;
    }

    ufds[0].fd = sockfd;
    ufds[0].events = POLLIN;

    break;
  }

  if (p == NULL) {
    fprintf(stderr, "network error\n");
    return 1;
  }

  freeaddrinfo(servinfo);

  n = poll(ufds, 1, -1);
  if (n == -1) {
    fprintf(stderr, "poll error\n");
  } else if (n == 0) {
    fprintf(stderr, "unlikely\n");
  } else {
    if (ufds[0].revents & POLLIN) {
      numbytes = recv(sockfd, buf, sizeof buf, 0);
      buf[numbytes] = 0;
      printf("received: %s\n", buf);
    }
  }

  close(sockfd);

  return 0;
}
