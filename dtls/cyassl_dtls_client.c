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

#include <cyassl/ssl.h>

struct sockaddr_in server_addr;
int on = 1;

int open_udp_socket(const char *address, const char *port) {
  int ecode, sd;
  struct addrinfo hints, *servinfo, *p;

  memset(&hints, 0, sizeof hints);
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_DGRAM;
  
  if ((ecode = getaddrinfo(address, port, &hints, &servinfo)) != 0) {
    fprintf(stderr, "getaddrinfo error: %s\n", gai_strerror(ecode));
    return 1;
  }

  memset(&server_addr, 0, sizeof server_addr);
  for (p = servinfo; p; p = p->ai_next) {
    if ((sd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
      fprintf(stderr, "socket error\n");
      continue;
    }

    setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof on);
    setsockopt(sd, SOL_SOCKET, SO_REUSEPORT, &on, sizeof on);

    memcpy(&server_addr, p->ai_addr, p->ai_addrlen);

    break;
  }

  if (p == NULL) {
    fprintf(stderr, "network error\n");
    return 1;
  }

  freeaddrinfo(servinfo);

  return sd;
}

CYASSL_CTX *init_ssl_context(const char *cert, const char *key) {
  CyaSSL_Init();
  //CyaSSL_Debugging_ON();

  CYASSL_METHOD *method = CyaDTLSv1_client_method();
  assert(method != NULL);

  CYASSL_CTX *ctx = CyaSSL_CTX_new(method);
  if (ctx == NULL) {
    fprintf(stderr, "ssl context error\n");
    return NULL;
  }

  CyaSSL_CTX_use_certificate_file(ctx, cert, SSL_FILETYPE_PEM);
  CyaSSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM);

  return ctx;
}

int main(int argc, char *argv[]) {
  if (argc != 3) {
    fprintf(stderr, "usage: %s address port\n", argv[0]);
    return 1;
  }

  CYASSL_CTX *ctx = init_ssl_context("./test.crt", "./test.key");
  assert(ctx);

  int sd = open_udp_socket(argv[1], argv[2]);
  assert(sd);

  //CyaSSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, 0);
  CYASSL *ssl = CyaSSL_new(ctx);
  CyaSSL_dtls_set_peer(ssl, &server_addr, sizeof server_addr);
  CyaSSL_set_fd(ssl, sd);

  if (CyaSSL_connect(ssl) != SSL_SUCCESS) {
    CyaSSL_free(ssl);
    CyaSSL_CTX_free(ctx);
    close(sd);
    return -1;
  }

  // read & write

  CyaSSL_shutdown(ssl);
  CyaSSL_free(ssl);
  CyaSSL_CTX_free(ctx);
  close(sd);

  return 0;
}
