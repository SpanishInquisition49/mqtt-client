#include "../lib/mqtt.h"
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

char *host = "localhost";
int port = 1883;
char *username = NULL;
char *password = NULL;
unsigned char qos = 0;
unsigned char retain = 0;
unsigned char clean_session = 1;
unsigned short keep_alive = 0;
char *will_topic = NULL;   //"/crash/client";
char *will_message = NULL; //"client crashed";
unsigned char will_qos = 0;
unsigned char will_retain = 0;
int random_fd;
static volatile sig_atomic_t keep_running = 1;

void *worker(void *args);
void listener(void);
void sigint_handler(int signum) {
  if (signum == SIGINT)
    keep_running = 0;
}

/**
 * The main function of the MQTT client.
 *
 * @param argc Number of arguments
 * @param argv Arguments
 */
int main(int argc, char *argv[]) {
  // Create N MQTT clients the number of clients is specified as an arguments
  if (argc != 2) {
    fprintf(stderr, "Usage: %s <N>\n", argv[0]);
    return EXIT_FAILURE;
  }
  int N = atoi(argv[1]);
  if (N < 0) {
    fprintf(stderr, "N must be a positive integer\n");
    return EXIT_FAILURE;
  }

  // Handle SIGINT
  struct sigaction action;
  action.sa_handler = SIG_IGN;
  action.sa_flags = 0;
  action.sa_handler = sigint_handler;
  sigemptyset(&action.sa_mask);
  sigaction(SIGINT, &action, NULL);

  // open /dev/random, we will use this to generate random data
  random_fd = open("/dev/random", O_RDONLY);
  if (random_fd < 0) {
    perror("open");
    exit(EXIT_FAILURE);
  }

  if (N > 0) {
    // Create N threads
    pthread_t threads[N];
    for (int i = 0; i < N; i++) {
      pthread_create(&threads[i], NULL, worker, NULL);
    }

    // Wait for SIGINT
    while (keep_running) {
      sched_yield();
    }
  } else {
    listener();
  }

  return EXIT_SUCCESS;
}

void *worker(void *args) {
  if (args != NULL) {
    free(args);
  }
  // detach the thread
  pthread_detach(pthread_self());

  // append the thread id to the client id
  char *id = malloc(100);
  snprintf(id, 100, "client-%ld", pthread_self());
  mqtt_client_t *client = mqtt_client_create(
      host, port, id, username, password, qos, retain, clean_session,
      keep_alive, will_topic, will_message, will_qos, will_retain);
  if (client == NULL) {
    fprintf(stderr, "Could not create the client\n");
    exit(EXIT_FAILURE);
  }

  connack_reason_code_t ret = mqtt_client_connect(client, 0);
  if (ret != CONNACK_SUCCESS) {
    exit(EXIT_FAILURE);
  }
  while (keep_running) {
    // Read from /dev/random and publish the data
    char buf[10];
    int n = read(random_fd, buf, sizeof(buf));
    if (n < 0) {
      sched_yield();
      continue;
    }
    mqtt_client_publish(client, "/test", buf, 0);
    sched_yield();
  }
  dprintf(2, "%s: disconnecting\n", id);
  mqtt_client_disconnect(client);
  mqtt_client_destroy(client);
  return NULL;
}

void listener() {
  mqtt_client_t *client = mqtt_client_create(
      host, port, "client", username, password, qos, retain, clean_session,
      keep_alive, will_topic, will_message, will_qos, will_retain);
  if (client == NULL) {
    fprintf(stderr, "Could not create the client\n");
    exit(EXIT_FAILURE);
  }
  connack_reason_code_t ret = mqtt_client_connect(client, 0);
  if (ret != CONNACK_SUCCESS) {
    exit(EXIT_FAILURE);
  }

  dprintf(2, "subscribing to /test\n");
  mqtt_client_subscribe(client, "/test");
  while (keep_running) {
    // read the incoming MQTT PUBLISH messages
    char buf[1024];
    ssize_t n = read(client->socket, buf, sizeof(buf));
    if (n < 0) {
      perror("read");
      exit(EXIT_FAILURE);
    }
    if (n == 0) {
      break;
    }
    // parse the incoming MQTT PUBLISH messages
    // and print the topic and payload
    if (buf[0] != PACKET_TYPE_PUBLISH) {
      continue;
    }
    ssize_t remaining_length = buf[1];
    // check if i already have the remaining length
    if (n < 2 + remaining_length) {
      // read the remaining length
      while (n < 2 + remaining_length) {
        ssize_t m = read(client->socket, buf + n, sizeof(buf) - n);
        if (m < 0) {
          perror("read");
          exit(EXIT_FAILURE);
        }
        n += m;
      }
    }
    // parse the topic
    size_t topic_length = (buf[2] << 8) | buf[3];
    char topic[topic_length + 1];
    memcpy(topic, buf + 4, topic_length);
    topic[topic_length] = '\0';
    // parse the payload
    // the payload starts at 2 + 2 + topic_length
    // the payload length is remaining_length - 2 - topic_length
    size_t payload_length = remaining_length - 2 - topic_length;
    char payload[payload_length + 1];
    memcpy(payload, buf + 4 + topic_length, payload_length);
    payload[payload_length] = '\0';
    dprintf(2, "topic: %s, payload: %s\n", topic, payload);
  }
}
