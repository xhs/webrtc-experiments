// gcc -o test_dtls_client test_dtls_client.c `pkg-config --cflags --libs openssl`

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

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rand.h>

struct sockaddr_in server_addr;
int client_fd;
SSL_CTX *context;
int on = 1;

int open_udp_socket(const char *address, const char *port) {
  int ecode, fd;
  struct addrinfo hints, *servinfo, *p;

  memset(&hints, 0, sizeof hints);
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_flags = AI_PASSIVE;
  hints.ai_protocol = 0;
  
  if ((ecode = getaddrinfo(address, port, &hints, &servinfo)) != 0) {
    fprintf(stderr, "getaddrinfo error: %s\n", gai_strerror(ecode));
    return -1;
  }

  for (p = servinfo; p; p = p->ai_next) {
    if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
      fprintf(stderr, "socket error\n");
      continue;
    }

    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof on);
    setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &on, sizeof on);

    if (connect(fd, p->ai_addr, p->ai_addrlen) == -1) {
      close(fd);
      fprintf(stderr, "bind error\n");
      continue;
    }

    memcpy(&server_addr, p->ai_addr, sizeof server_addr);

    break;
  }

  if (p == NULL) {
    fprintf(stderr, "network error\n");
    return -1;
  }

  freeaddrinfo(servinfo);

  return fd;
}

int verify_cert_cb(int ok, X509_STORE_CTX *ctx) {
  return 1;
}

SSL_CTX* init_ssl_context(const char *cert, const char *key) {
  SSL_CTX *ctx;

  SSL_library_init();
  OpenSSL_add_ssl_algorithms();
  SSL_load_error_strings();

  ctx = SSL_CTX_new(DTLSv1_client_method());
  if (ctx == NULL) {
    ERR_print_errors_fp(stderr);
    return NULL;
  }

  if (SSL_CTX_use_certificate_file(ctx, cert, SSL_FILETYPE_PEM) <= 0)
    goto label_fail;

  if (SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM) <= 0)
    goto label_fail;

  if (!SSL_CTX_check_private_key(ctx))
    goto label_fail;

  SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verify_cert_cb);

  return ctx;

label_fail:
  ERR_print_errors_fp(stderr);
  SSL_CTX_free(ctx);
  return NULL;
}

int main(int argc, char *argv[]) {
  if (argc != 3) {
    fprintf(stderr, "usage: %s address port\n", argv[0]);
    return -1;
  }

  context = init_ssl_context("./test.crt", "./test.key");
  if (context == NULL) {
    fprintf(stderr, "ssl context error\n");
    return -1;
  }

  memset(&server_addr, 0, sizeof server_addr);
  client_fd = open_udp_socket(argv[1], argv[2]);
  if (client_fd <= 0) {
    fprintf(stderr, "open udp error\n");
    return -1;
  }

  BIO *bio = BIO_new_dgram(client_fd, BIO_NOCLOSE);
  BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_CONNECTED, 0, &server_addr);

  SSL *ssl = SSL_new(context);
  SSL_set_bio(ssl, bio, bio);

  SSL_connect(ssl);

  // read & write

  SSL_shutdown(ssl);
  close(client_fd);
  SSL_free(ssl);

  return 0;
}
