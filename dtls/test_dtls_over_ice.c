// gcc -DCYASSL_DTLS -o test_dtls_over_ice test_dtls_over_ice.c `pkg-config --cflags --libs cyassl nice`

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

static GMainLoop *gloop;
static gboolean controlling;
static gboolean exit_thread, candidate_gathering_done, negotiation_done;
static GMutex gather_mutex, negotiate_mutex;
static GCond gather_cond, negotiate_cond;

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
    negotiation_done = TRUE;
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
  if (len == 1 && buf[0] == '\0')
    g_main_loop_quit(gloop);

  fprintf(stdout, "%.*s\n", len, buf);
}

static gpointer
ice_thread(gpointer data)
{
  NiceAgent *agent = nice_agent_new(g_main_loop_get_context(gloop),
    NICE_COMPATIBILITY_RFC5245);
  if (agent == NULL)
    g_error("unable to create agent");

  g_object_set(G_OBJECT(agent), "controlling-mode", controlling, NULL);

  g_signal_connect(G_OBJECT(agent), "candidate-gathering-done",
    G_CALLBACK(candidate_gathering_done_cb), NULL);
  g_signal_connect(G_OBJECT(agent), "component-state-changed",
    G_CALLBACK(component_state_changed_cb), NULL);

  guint stream_id = nice_agent_add_stream(agent, 1);
  if (stream_id == 0)
    g_error("unable to add stream");

  nice_agent_set_stream_name (agent, stream_id, "application");

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

  sdp = nice_agent_generate_local_sdp (agent);
  sdp64 = g_base64_encode ((const guchar *)sdp, strlen (sdp));
  g_free (sdp);
  g_free (sdp64);

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

  g_mutex_lock(&negotiate_mutex);
  while (!exit_thread && !negotiation_done)
    g_cond_wait(&negotiate_cond, &negotiate_mutex);
  g_mutex_unlock(&negotiate_mutex);

  if (exit_thread)
    goto l_cleanup;

  printf("send data:\n");
  fflush(stdout);
  while (!exit_thread) {
    gchar *line;
    GIOStatus s = g_io_channel_read_line(io_stdin, &line, NULL, NULL, NULL);

    if (s == G_IO_STATUS_NORMAL) {
      nice_agent_send(agent, stream_id, 1, strlen(line), line);
      g_free (line);
    } else if (s == G_IO_STATUS_AGAIN) {
      usleep (100000);
    } else {
      // Ctrl-D was pressed
      nice_agent_send(agent, stream_id, 1, 1, "\0");
      break;
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

  gloop = g_main_loop_new(NULL, FALSE);

  exit_thread = FALSE;
  candidate_gathering_done = FALSE;
  negotiation_done = FALSE;
  GThread *gicethread = g_thread_new("ice thread", &ice_thread, NULL);
  g_main_loop_run(gloop);
  exit_thread = TRUE;

  g_thread_join(gicethread);
  g_main_loop_unref(gloop);

  return EXIT_SUCCESS;
}
