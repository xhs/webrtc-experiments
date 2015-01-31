// gcc -o test_sctp_dtls_ice test_sctp_dtls_ice.c `pkg-config --cflags --libs openssl nice` -lusrsctp

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

#include <agent.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <usrsctp.h>

#define BUFFER_SIZE 1500
#define PEER_CLIENT 1
#define PEER_SERVER 0

static GMainLoop *gloop;
static gboolean exit_thread;

static gboolean candidate_gathering_done, candidate_negotiation_done;
static GMutex gather_mutex, negotiate_mutex;
static GCond gather_cond, negotiate_cond;

struct dtls_transport {
  SSL *ssl;
  BIO *incoming_bio;
  BIO *outgoing_bio;
  GMutex dtls_mutex;
};

struct sctp_transport {
  struct socket *sk;
  BIO *incoming_bio;
  BIO *outgoing_bio;
  GMutex sctp_mutex;
};

struct peer_connection {
  struct dtls_transport *dtls;
  struct sctp_transport *sctp;
  SSL_CTX *ctx;
  char fingerprint[BUFFER_SIZE];
  int role;
};

static int
verify_certificate_cb(int ok, X509_STORE_CTX *ctx) {
  return 1;
}

static SSL_CTX*
init_dtls_context(const char *cert, const char *key, char *fingerprint)
{
  SSL_library_init();
  SSL_load_error_strings();
  ERR_load_BIO_strings();
  OpenSSL_add_all_algorithms();

  SSL_CTX *ctx = SSL_CTX_new(DTLSv1_method());
  if (ctx == NULL) {
    fprintf(stderr, "ssl create context error\n");
    return NULL;
  }

  // ALL:NULL:eNULL:aNULL
  // ALL:!ADH:!LOW:!EXP:!MD5:@STRENGTH
  if (SSL_CTX_set_cipher_list(ctx, "ALL:!ADH:!LOW:!EXP:!MD5:@STRENGTH") != 1) {
    fprintf(stderr, "ssl set cipher error\n");
    return NULL;
  }

  SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER|SSL_VERIFY_FAIL_IF_NO_PEER_CERT, verify_certificate_cb);
  SSL_CTX_use_certificate_file(ctx, cert, SSL_FILETYPE_PEM);
  SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM);
  if (SSL_CTX_check_private_key(ctx) != 1) {
    fprintf(stderr, "ssl private key error\n");
    return NULL;
  }

  BIO *cert_bio = BIO_new(BIO_s_file());
  if (cert_bio == NULL) {
    fprintf(stderr, "ssl file bio error\n");
    return NULL;
  }
  BIO_read_filename(cert_bio, cert);
  X509 *x509_cert = PEM_read_bio_X509(cert_bio, NULL, 0, NULL);
  unsigned int len;
  unsigned char buf[BUFFER_SIZE];
  X509_digest(x509_cert, EVP_sha256(), buf, &len);
  BIO_free_all(cert_bio);
  X509_free(x509_cert);

  char *p = fingerprint;
  for (int i = 0; i < len; ++i) {
    snprintf(p, 4, "%02X:", buf[i]);
    p += 3;
  }
  *(p - 1) = 0;

  return ctx;
}

static int
init_dtls_transport(SSL_CTX *ctx, struct peer_connection *pc)
{
  struct dtls_transport *dtls = pc->dtls;
  dtls->ssl = SSL_new(ctx);
  dtls->incoming_bio = BIO_new(BIO_s_mem());
  BIO_set_mem_eof_return(dtls->incoming_bio, -1);
  dtls->outgoing_bio = BIO_new(BIO_s_mem());
  BIO_set_mem_eof_return(dtls->outgoing_bio, -1);

  SSL_set_bio(dtls->ssl, dtls->incoming_bio, dtls->outgoing_bio);
  if (pc->role == PEER_CLIENT)
    SSL_set_connect_state(dtls->ssl);
  else
    SSL_set_accept_state(dtls->ssl);

  EC_KEY *ecdh = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
  SSL_set_options(dtls->ssl, SSL_OP_SINGLE_ECDH_USE);
  SSL_set_tmp_ecdh(dtls->ssl, ecdh);
  EC_KEY_free(ecdh);

  return 0;
}

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

void print_binary(unsigned char *binary, int length)
{
  for (int i = 0; i < length; ++i) {
    printf(i % 8 == 7 ? " %02x\n" : " %02x", binary[i]);
  }
  fprintf(stdout, "\n");
}

static void
data_received_cb(NiceAgent *agent, guint stream_id, guint component_id,
  guint len, gchar *buf, gpointer user_data)
{
  struct peer_connection *pc = (struct peer_connection *)user_data;
  struct dtls_transport *dtls = pc->dtls;
  if (candidate_negotiation_done) {
    g_mutex_lock(&dtls->dtls_mutex);
    fprintf(stderr, "[ice] received encrypted data of length %u from wire\n", len);
    BIO_write(dtls->incoming_bio, buf, len);

    if (SSL_is_init_finished(dtls->ssl) != 1) {
      fprintf(stderr, "continue handshake\n");
      SSL_do_handshake(dtls->ssl);
    } else {
      unsigned char buf[BUFFER_SIZE];
      int nbytes = SSL_read(dtls->ssl, buf, sizeof buf);
      if (nbytes > 0)
        print_binary(buf, nbytes);
    }
    g_mutex_unlock(&dtls->dtls_mutex);
  }
}

static gpointer
ice_thread(gpointer user_data)
{
  struct peer_connection *pc = (struct peer_connection *)user_data;
  struct dtls_transport *dtls = pc->dtls;

  NiceAgent *agent = nice_agent_new(g_main_loop_get_context(gloop),
    NICE_COMPATIBILITY_RFC5245);
  if (agent == NULL)
    g_error("unable to create agent");

  g_object_set(G_OBJECT(agent), "controlling-mode", pc->role, NULL);
  g_object_set(G_OBJECT(agent), "keepalive-conncheck", TRUE, NULL); // for google

  g_signal_connect(G_OBJECT(agent), "candidate-gathering-done",
    G_CALLBACK(candidate_gathering_done_cb), NULL);
  g_signal_connect(G_OBJECT(agent), "component-state-changed",
    G_CALLBACK(component_state_changed_cb), NULL);

  guint stream_id = nice_agent_add_stream(agent, 1);
  if (stream_id == 0)
    g_error("unable to add stream");

  nice_agent_set_stream_name(agent, stream_id, "application");

  nice_agent_attach_recv(agent, stream_id, 1,
    g_main_loop_get_context(gloop), data_received_cb, user_data);

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

  gchar answer[BUFFER_SIZE];
  memset(answer, 0, sizeof answer);
  sprintf(answer, "%s",
    "v=0\n"
    "o=- 5131418131730071224 2 IN IP4 127.0.0.1\n"
    "s=-\n"
    "t=0 0\n"
    "a=msid-semantic: WMS\n"
    "m=application 1 DTLS/SCTP 5000\n"
    "c=IN IP4 0.0.0.0\n");

  gchar **lines = g_strsplit(sdp, "\n", 0);
  for (int i = 0; lines && lines[i]; ++i) {
    if (g_str_has_prefix(lines[i], "a=ice-ufrag:")
        || g_str_has_prefix(lines[i], "a=ice-pwd:")) {
      strcat(answer, lines[i]);
      strcat(answer, "\n");
    }
  }
  strcat(answer, "a=fingerprint:sha-256 ");
  strcat(answer, pc->fingerprint);
  strcat(answer, "\n");
  if (pc->role == PEER_CLIENT)
    strcat(answer, "a=setup:active\n");
  else
    strcat(answer, "a=setup:passive\n");
  strcat(answer,
    "a=mid:data\n"
    "a=sctpmap:5000 webrtc-datachannel 1024\n");
  g_strfreev(lines);
  printf("local offer:\n%s\n", answer);

  gchar *answer64 = g_base64_encode((const guchar *)answer, strlen(answer));
  printf("base64 encoded local offer:\n%s\n\n", answer64);
  g_free(answer64);

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

  g_mutex_lock(&negotiate_mutex);
  while (!exit_thread && !candidate_negotiation_done)
    g_cond_wait(&negotiate_cond, &negotiate_mutex);
  g_mutex_unlock(&negotiate_mutex);

  if (pc->role == PEER_CLIENT)
    SSL_do_handshake(dtls->ssl);

  char buf[BUFFER_SIZE];
  while (!exit_thread) {
    if (BIO_ctrl_pending(dtls->outgoing_bio) > 0) {
      g_mutex_lock(&dtls->dtls_mutex);
      int nbytes = BIO_read(dtls->outgoing_bio, buf, sizeof buf);
      fprintf(stderr, "[ice] received encrypted data of length %d from dtls\n", nbytes);
      if (nbytes > 0) {
        nice_agent_send(agent, stream_id, 1, nbytes, buf);
      }

      if (SSL_is_init_finished(dtls->ssl) != 1) {
        fprintf(stderr, "continue handshake\n");
        SSL_do_handshake(dtls->ssl);
      }
      g_mutex_unlock(&dtls->dtls_mutex);
    } else {
      g_usleep(5000);
    }
  }

l_cleanup:
  g_object_unref(agent);
  g_io_channel_unref(io_stdin);
  g_main_loop_quit(gloop);

  return NULL;
}

int
main(int argc, char *argv[])
{
  if (argc != 2) {
    fprintf(stderr, "usage: %s client|server\n", argv[0]);
    return EXIT_FAILURE;
  }

  struct peer_connection *pc = (struct peer_connection *)malloc(sizeof *pc);
  memset(pc, 0, sizeof *pc);

  struct dtls_transport *dtls = (struct dtls_transport *)malloc(sizeof *dtls);
  memset(dtls, 0, sizeof *dtls);

  if (strcmp(argv[1], "client") == 0)
    pc->role = PEER_CLIENT;
  else if (strcmp(argv[1], "server") == 0)
    pc->role = PEER_SERVER;
  else {
    fprintf(stderr, "usage: %s client|server\n", argv[0]);
    return EXIT_FAILURE;
  }

#if !GLIB_CHECK_VERSION(2, 36, 0)
  g_type_init();
#endif

  SSL_CTX *context = init_dtls_context("./test.crt", "./test.key", pc->fingerprint);
  if (context == NULL)
    return EXIT_FAILURE;
  pc->ctx = context;
  printf("fingerprint: %s\n", pc->fingerprint);

  pc->dtls = dtls;
  init_dtls_transport(context, pc);

  gloop = g_main_loop_new(NULL, FALSE);

  exit_thread = FALSE;
  candidate_gathering_done = FALSE;
  candidate_negotiation_done = FALSE;
  GThread *gthread_ice = g_thread_new("ice thread", &ice_thread, pc);
  g_main_loop_run(gloop);
  exit_thread = TRUE;

  g_thread_join(gthread_ice);
  g_main_loop_unref(gloop);

  return EXIT_SUCCESS;
}
