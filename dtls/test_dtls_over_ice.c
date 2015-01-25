// gcc -DCYASSL_DTLS -o test_dtls_over_ice test_dtls_over_ice.c `pkg-config --cflags --libs cyassl nice`

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

#include <cyassl/ssl.h>
#include <agent.h>

#define DTLS_CLIENT_PORT "60001"
#define DTLS_SERVER_PORT "60002"
#define SOCKET_CLIENT_PORT "60003"
#define SOCKET_SERVER_PORT "60004"
#define BUFFER_SIZE 2048

static GMainLoop *gloop;
static gboolean controlling;
static gboolean exit_thread;

static gboolean candidate_gathering_done, candidate_negotiation_done;
static GMutex gather_mutex, negotiate_mutex;
static GCond gather_cond, negotiate_cond;

static gboolean dtls_ready, dtls_handshake_done;
static GMutex dtls_ready_mutex, dtls_handshake_mutex;
static GCond dtls_ready_cond, dtls_handshake_cond;

static gboolean socket_ready;
static GMutex socket_ready_mutex;
static GCond socket_ready_cond;

static int encrypt_pipe[2];
static int decrypt_pipe[2];
static int insocket_pipe[2];
static int outsocket_pipe[2];
struct sockaddr_in dtls_addr, socket_addr;
int on = 1, incoming = 0, outgoing = 1;

static void
candidate_gathering_done_cb(NiceAgent *agent, guint stream_id,
  gpointer user_data)
{
  g_mutex_lock(&gather_mutex);
  candidate_gathering_done = TRUE;
  g_cond_signal(&gather_cond);
  g_mutex_unlock(&gather_mutex);
}

static void
component_state_changed_cb(NiceAgent *agent, guint stream_id, 
  guint component_id, guint state, gpointer user_data)
{
  if (state == NICE_COMPONENT_STATE_READY) {
    g_mutex_lock(&negotiate_mutex);
    candidate_negotiation_done = TRUE;
    g_cond_signal(&negotiate_cond);
    g_mutex_unlock(&negotiate_mutex);
  } else if (state == NICE_COMPONENT_STATE_FAILED) {
    g_main_loop_quit(gloop);
  }
}

static void
data_received_cb(NiceAgent *agent, guint stream_id, guint component_id,
  guint len, gchar *buf, gpointer user_data)
{
  fprintf(stderr, "[ice] received encrypted data from wire\n");
  write(insocket_pipe[outgoing], buf, len);
}

static gpointer
ice_thread(gpointer data)
{
  NiceAgent *agent = nice_agent_new(g_main_loop_get_context(gloop),
    NICE_COMPATIBILITY_RFC5245);
  if (agent == NULL)
    g_error("unable to create agent");

  g_object_set(G_OBJECT(agent), "controlling-mode", controlling, NULL);
  //g_object_set(G_OBJECT(agent), "keepalive-conncheck", TRUE, NULL); // for google

  g_signal_connect(G_OBJECT(agent), "candidate-gathering-done",
    G_CALLBACK(candidate_gathering_done_cb), NULL);
  g_signal_connect(G_OBJECT(agent), "component-state-changed",
    G_CALLBACK(component_state_changed_cb), NULL);

  guint stream_id = nice_agent_add_stream(agent, 1);
  if (stream_id == 0)
    g_error("unable to add stream");

  nice_agent_set_stream_name(agent, stream_id, "application");

  nice_agent_attach_recv(agent, stream_id, 1,
    g_main_loop_get_context(gloop), data_received_cb, NULL);

  if (!nice_agent_gather_candidates(agent, stream_id))
    g_error("unable to gather candidates");

  g_mutex_lock(&gather_mutex);
  while (!exit_thread && !candidate_gathering_done)
    g_cond_wait(&gather_cond, &gather_mutex);
  g_mutex_unlock(&gather_mutex);

  if (exit_thread)
    goto l_cleanup;

  gchar *sdp = nice_agent_generate_local_sdp(agent);
  printf("local sdp:\n%s\n", sdp);
  gchar *sdp64 = g_base64_encode((const guchar *)sdp, strlen(sdp));
  printf("base64 encoded local sdp:\n%s\n\n", sdp64);
  g_free(sdp);
  g_free(sdp64);

  GIOChannel *io_stdin = g_io_channel_unix_new(fileno(stdin));
  g_io_channel_set_flags(io_stdin, G_IO_FLAG_NONBLOCK, NULL);

  printf("enter base64 encoded remote sdp:\n");
  printf("> ");
  fflush(stdout);
  while (!exit_thread) {
    gchar *line = NULL;
    if (g_io_channel_read_line(io_stdin, &line, NULL, NULL, NULL) == G_IO_STATUS_NORMAL) {
      gsize sdp_len;
      gchar *rsdp = (gchar *)g_base64_decode(line, &sdp_len);
      printf("\nremote sdp:\n%s\n", rsdp);

      if (rsdp && nice_agent_parse_remote_sdp(agent, rsdp) > 0) {
        g_free(rsdp);
        g_free(line);
        break;
      } else {
        fprintf(stderr, "invalid remote sdp: %s\n", line);
        printf("enter base64 encoded remote sdp:\n");
        printf("> ");
        fflush(stdout);
      }

      g_free(rsdp);
      g_free(line);
    } else {
      usleep(100000);
    }
  }

  fprintf(stderr, "[ice] parsed remote sdp\n");

  struct pollfd fds[2];
  fds[0].fd = outsocket_pipe[incoming];
  fds[0].events = POLLIN;
  fds[1].fd = decrypt_pipe[incoming];
  fds[1].events = POLLIN;

  char buf[BUFFER_SIZE];

  while (!exit_thread) {
    int rc = poll(fds, 1, 100);
    if (rc < 0) {
      fprintf(stderr, "poll error\n");
    } else if (rc > 0) {
      if (fds[0].revents & POLLIN) {
        fprintf(stderr, "[ice] received encrypted data from socket\n");
        int nbytes = read(outsocket_pipe[incoming], buf, sizeof buf);
        if (nbytes > 0)
          nice_agent_send(agent, stream_id, 1, nbytes, buf);
      }
    }

    g_mutex_lock(&dtls_handshake_mutex);
    if (dtls_handshake_done) break;
    g_mutex_unlock(&dtls_handshake_mutex);
  }

  printf("send data:\n");
  fflush(stdout);
  while (!exit_thread) {
    gchar *line;
    GIOStatus s = g_io_channel_read_line(io_stdin, &line, NULL, NULL, NULL);

    if (s == G_IO_STATUS_NORMAL) {
      write(encrypt_pipe[outgoing], line, strlen(line));
      g_free(line);
    } else if (s == G_IO_STATUS_AGAIN) {
      usleep(100000);
      continue;
    } else {
      // Ctrl-D was pressed
      break;
    }

    int rc = poll(fds, 2, 100);
    if (rc < 0) {
      fprintf(stderr, "poll error\n");
    } else if (rc > 0) {
      if (fds[0].revents & POLLIN) {
        int nbytes = read(outsocket_pipe[incoming], buf, sizeof buf);
        if (nbytes > 0)
          nice_agent_send(agent, stream_id, 1, nbytes, buf);
      }

      if (fds[1].revents & POLLIN) {
        int nbytes = read(decrypt_pipe[incoming], buf, sizeof buf);
        if (nbytes > 0)
          printf("received: %s\n", buf);
      }
    }
  }

l_cleanup:
  g_object_unref(agent);
  g_io_channel_unref(io_stdin);
  g_main_loop_quit(gloop);
  close(insocket_pipe[outgoing]);
  close(outsocket_pipe[incoming]);
  close(encrypt_pipe[outgoing]);
  close(decrypt_pipe[incoming]);

  return NULL;
}

static CYASSL_CTX *
init_dtls_context(const char *cert, const char *key, int controlling) {
  CYASSL_METHOD *method;
  if (controlling)
    method = CyaDTLSv1_client_method();
  else
    method = CyaDTLSv1_server_method();

  CYASSL_CTX *ctx = CyaSSL_CTX_new(method);
  if (ctx == NULL) {
    fprintf(stderr, "ssl context error\n");
    return NULL;
  }

  CyaSSL_CTX_use_certificate_file(ctx, cert, SSL_FILETYPE_PEM);
  CyaSSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM);
  if (controlling)
    CyaSSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, 0);

  return ctx;
}

int
udp_socket(const char *port, int client, struct sockaddr_in *addr) {
  int ecode, sd;
  struct addrinfo hints, *servinfo, *p;

  memset(&hints, 0, sizeof hints);
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_protocol = 0;
  
  if ((ecode = getaddrinfo("127.0.0.1", port, &hints, &servinfo)) != 0) {
    fprintf(stderr, "getaddrinfo error: %s\n", gai_strerror(ecode));
    return -1;
  }

  for (p = servinfo; p; p = p->ai_next) {
    if ((sd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
      fprintf(stderr, "socket create error\n");
      continue;
    }

    setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof on);
    setsockopt(sd, SOL_SOCKET, SO_REUSEPORT, &on, sizeof on);

    if (!client) {
      if (bind(sd, p->ai_addr, p->ai_addrlen) == -1) {
        close(sd);
        fprintf(stderr, "bind error\n");
        continue;
      }
    }
    memcpy(addr, p->ai_addr, p->ai_addrlen);
    break;
  }

  if (p == NULL) {
    fprintf(stderr, "network error\n");
    return -1;
  }

  freeaddrinfo(servinfo);
  return sd;
}

static gpointer
dtls_thread(gpointer data)
{
  CYASSL_CTX *ctx = init_dtls_context("./test.crt", "./test.key", controlling);
  if (ctx == NULL)
    g_error("unable to initialize DTLS context");

  memset(&dtls_addr, 0, sizeof dtls_addr);
  int sd;
  CYASSL *ssl;
  char buf[BUFFER_SIZE];

  struct pollfd fds[2];
  fds[0].fd = encrypt_pipe[incoming];
  fds[0].events = POLLIN;
  
  if (controlling) {
    sd = udp_socket(DTLS_CLIENT_PORT, 0, &dtls_addr);
    if (sd <= 0)
      g_error("unable to open socket");

    fds[1].fd = sd;
    fds[1].events = POLLIN;

    g_mutex_lock(&dtls_ready_mutex);
    dtls_ready = TRUE;
    g_cond_signal(&dtls_ready_cond);
    g_mutex_unlock(&dtls_ready_mutex);

    fprintf(stderr, "[dtls] ready as a client\n");

    g_mutex_lock(&socket_ready_mutex);
    while (!exit_thread && !socket_ready)
      g_cond_wait(&socket_ready_cond, &socket_ready_mutex);
    g_mutex_unlock(&socket_ready_mutex);

    fprintf(stderr, "[dtls] socket ready\n");

    g_mutex_lock(&negotiate_mutex);
    while (!exit_thread && !candidate_negotiation_done)
      g_cond_wait(&negotiate_cond, &negotiate_mutex);
    g_mutex_unlock(&negotiate_mutex);

    fprintf(stderr, "[dtls] candidate negotiate done\n");

    ssl = CyaSSL_new(ctx);
    CyaSSL_dtls_set_peer(ssl, &socket_addr, sizeof socket_addr);
    CyaSSL_set_fd(ssl, sd);
    //CyaSSL_dtls_set_timeout_init(ssl, 3);

    if (CyaSSL_connect(ssl) != SSL_SUCCESS) {
      fprintf(stderr, "DTLS connect error\n");
      CyaSSL_free(ssl);
      close(sd);
      return NULL;
    }

    fprintf(stderr, "[dtls] session connected\n");

  } else {
    sd = udp_socket(DTLS_SERVER_PORT, 0, &dtls_addr);
    if (sd <= 0)
      g_error("unable to open socket");

    fds[1].fd = sd;
    fds[1].events = POLLIN;

    g_mutex_lock(&dtls_ready_mutex);
    dtls_ready = TRUE;
    g_cond_signal(&dtls_ready_cond);
    g_mutex_unlock(&dtls_ready_mutex);

    fprintf(stderr, "[dtls] ready as a server\n");

    g_mutex_lock(&negotiate_mutex);
    while (!exit_thread && !candidate_negotiation_done)
      g_cond_wait(&negotiate_cond, &negotiate_mutex);
    g_mutex_unlock(&negotiate_mutex);

    fprintf(stderr, "[dtls] candidate negotiate done\n");

    struct sockaddr_in client_addr;
    socklen_t len = sizeof client_addr;
    memset(&client_addr, 0, sizeof client_addr);
    int n = recvfrom(sd, buf, sizeof buf, MSG_PEEK, (struct sockaddr*)&client_addr, &len);
    if (n <= 0) {
      fprintf(stderr, "recvfrom error\n");
      close(sd);
      return NULL;
    }

    fprintf(stderr, "[dtls] got a message from client\n");

    if (connect(sd, (const struct sockaddr*)&client_addr, sizeof client_addr) == -1) {
      fprintf(stderr, "socket connect error");
      close(sd);
      return NULL;
    }

    fprintf(stderr, "[dtls] connect to client\n");

    ssl = CyaSSL_new(ctx);
    CyaSSL_set_fd(ssl, sd);
    //CyaSSL_dtls_set_timeout_init(ssl, 3);

    if (CyaSSL_accept(ssl) != SSL_SUCCESS) {
      CyaSSL_free(ssl);
      close(sd);
      return NULL;
    }

    fprintf(stderr, "[dtls] session accepted\n");
  }

  g_mutex_lock(&dtls_handshake_mutex);
  dtls_handshake_done = TRUE;
  g_cond_signal(&dtls_handshake_cond);
  g_mutex_unlock(&dtls_handshake_mutex);

  while (!exit_thread) {
    int rc = poll(fds, 2, -1);
    if (rc < 0) {
      fprintf(stderr, "poll error\n");
    } else if (rc == 0) {
      fprintf(stderr, "unlikely\n");
    } else {
      if (fds[0].revents & POLLIN) {
        int nbytes = read(encrypt_pipe[incoming], buf, sizeof buf);
        if (nbytes > 0)
          CyaSSL_write(ssl, buf, nbytes);
      }

      if (fds[1].revents & POLLIN) {
        int nbytes = CyaSSL_read(ssl, buf, sizeof buf);
        if (nbytes > 0)
          write(decrypt_pipe[outgoing], buf, nbytes);
      }
    } 
  }

  CyaSSL_shutdown(ssl);
  CyaSSL_free(ssl);
  close(sd);

  return NULL;
}

static gpointer
socket_thread(gpointer data)
{
  int sd;
  memset(&socket_addr, 0, sizeof socket_addr);
  char buf[BUFFER_SIZE];

  struct pollfd fds[2];
  fds[0].fd = insocket_pipe[incoming];
  fds[0].events = POLLIN;

  if (controlling) {
    sd = udp_socket(SOCKET_SERVER_PORT, 0, &socket_addr);
    if (sd <= 0)
      g_error("unable to open socket");

    fds[1].fd = sd;
    fds[1].events = POLLIN;
  } else {
    sd = udp_socket(SOCKET_CLIENT_PORT, 1, &dtls_addr);
    if (sd <= 0)
      g_error("unable to open socket");

    fds[1].fd = sd;
    fds[1].events = POLLIN;
  }

  g_mutex_lock(&socket_ready_mutex);
  socket_ready = TRUE;
  g_cond_signal(&socket_ready_cond);
  g_mutex_unlock(&socket_ready_mutex);

  if (controlling)
    fprintf(stderr, "[socket] ready as a server\n");
  else
    fprintf(stderr, "[socket] ready as a client\n");

  while (!exit_thread) {
    int rc = poll(fds, 2, -1);
    if (rc < 0) {
      fprintf(stderr, "poll error\n");
    } else if (rc == 0) {
      fprintf(stderr, "unlikely\n");
    } else {
      if (fds[0].revents & POLLIN) {
        int nbytes = read(insocket_pipe[incoming], buf, sizeof buf);
        fprintf(stderr, "[socket] received encrypted data from ice\n");
        if (nbytes > 0)
          sendto(sd, buf, nbytes, 0, (const struct sockaddr*)&dtls_addr, sizeof dtls_addr);
      }

      if (fds[1].revents & POLLIN) {
        fprintf(stderr, "[socket] received encrypted data from dtls\n");
        struct sockaddr dummyaddr;
        socklen_t dummylen = sizeof dummyaddr;

        int nbytes = recvfrom(sd, buf, sizeof buf, 0, &dummyaddr, &dummylen);
        if (nbytes > 0)
          write(outsocket_pipe[outgoing], buf, nbytes);
      }
    }
  }

  close(outsocket_pipe[outgoing]);
  close(insocket_pipe[incoming]);
  close(sd);

  return NULL;
}

int
main(int argc, char *argv[])
{
  if (argc != 2) {
    fprintf(stderr, "usage: %s client|server\n", argv[0]);
    return EXIT_FAILURE;
  }

  if (strcmp(argv[1], "client") == 0)
    controlling = 1;
  else if (strcmp(argv[1], "server") == 0)
    controlling = 0;
  else {
    fprintf(stderr, "usage: %s client|server\n", argv[0]);
    return EXIT_FAILURE;
  }

#if !GLIB_CHECK_VERSION(2, 36, 0)
  g_type_init();
#endif

  if (pipe(encrypt_pipe) == -1)
    g_error("unable to open pipe");
  if (pipe(decrypt_pipe) == -1)
    g_error("unable to open pipe");
  if (pipe(insocket_pipe) == -1)
    g_error("unable to open pipe");
  if (pipe(outsocket_pipe) == -1)
    g_error("unable to open pipe");

  CyaSSL_Init();
  //CyaSSL_Debugging_ON();

  gloop = g_main_loop_new(NULL, FALSE);

  exit_thread = FALSE;
  candidate_gathering_done = FALSE;
  candidate_negotiation_done = FALSE;
  socket_ready = FALSE;
  dtls_ready = FALSE;
  dtls_handshake_done = FALSE;
  GThread *gthread_ice = g_thread_new("ice thread", &ice_thread, NULL);
  GThread *gthread_dtls = g_thread_new("dtls thread", &dtls_thread, NULL);
  GThread *gthread_socket = g_thread_new("socket thread", &socket_thread, NULL);
  g_main_loop_run(gloop);
  exit_thread = TRUE;

  g_thread_join(gthread_ice);
  g_thread_join(gthread_dtls);
  g_thread_join(gthread_socket);
  g_main_loop_unref(gloop);

  return EXIT_SUCCESS;
}
