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
char *username = "Pippo";
char *password = "password";
unsigned char qos = 0;
unsigned char retain = 0;
unsigned char clean_session = 1;
unsigned short keep_alive = 0;
char *will_topic = "/crash/client";
char *will_message = "client crashed";
unsigned char will_qos = 0;
unsigned char will_retain = 0;
int random_fd;
static volatile sig_atomic_t keep_running = 1;

int N = 0;

void *worker(void *args);
void mqtt_subscribe_handler(mqtt_message_t *message) {
  printf("Received message on topic %s: %s\n", message->topic, message->message);
  mqtt_message_destroy(message);
}
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
    // Set the subscribe handler
    void *client = mqtt_client_create(
        host, port, "client", username, password, qos, retain, clean_session,
        keep_alive, will_topic, will_message, will_qos, will_retain);
    if (client == NULL) {
      dprintf(2, "Could not create the client\n");
      return EXIT_FAILURE;
    }
    mqtt_client_set_subscribe_handler(client, mqtt_subscribe_handler);
    connack_reason_code_t ret = mqtt_client_connect(client, 0);
    if (ret != CONNACK_SUCCESS) {
      return EXIT_FAILURE;
    }
    mqtt_client_subscribe(client, "/test");
    mqtt_client_subscribe(client, "/test/2");
    mqtt_client_loop(client);
    while (keep_running) {
      //mqtt_client_publish(client, "/test", "Hello, World!", 0);
      sleep(1);
    }
    mqtt_client_unsubscribe(client, "/test");
    mqtt_client_stop(client);
    mqtt_client_disconnect(client, 1);
    mqtt_client_destroy(client);
    
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
  void *client = mqtt_client_create(
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
  mqtt_client_loop(client);
  while (keep_running) {
    // Read from /dev/random and publish the data
    char buf[10];
    int n = read(random_fd, buf, sizeof(buf));
    if (n < 0) {
      sched_yield();
      continue;
    }
    mqtt_client_publish(client, "/test", "Hello World!", 0);
    sched_yield();
  }
  dprintf(2, "%s: disconnecting\n", id);
  mqtt_client_stop(client);
  mqtt_client_disconnect(client, 0);
  mqtt_client_destroy(client);
  return NULL;
}

