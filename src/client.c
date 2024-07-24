#include "../lib/mqtt.h"
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

/**
 * The main function of the MQTT client.
 *
 * @param argc Number of arguments
 * @param argv Arguments
 */
int main(void) {

  char *host = "localhost";
  int port = 1883;
  char *client_id = "porco dio";
  char *username = NULL;
  char *password = NULL;
  unsigned char qos = 0;
  unsigned char retain = 0;
  unsigned char clean_session = 1;
  unsigned short keep_alive = 60;
  char *will_topic = NULL;   //"/crash/client";
  char *will_message = NULL; //"client crashed";
  unsigned char will_qos = 0;
  unsigned char will_retain = 0;

  dprintf(2, "Creating the client\n");
  mqtt_client_t *client = mqtt_client_create(
      host, port, client_id, username, password, qos, retain, clean_session,
      keep_alive, will_topic, will_message, will_qos, will_retain);
  if (client == NULL) {
    fprintf(stderr, "Could not create the client\n");
    return EXIT_FAILURE;
  }

  dprintf(2, "Connecting to the broker\n");
  connack_reason_code_t ret = mqtt_client_connect(client, 0);
  dprintf(2, "Reason code: %s\n", connack_reason_code_to_string(ret));
  if (ret != CONNACK_SUCCESS) {
    dprintf(2, "Could not connect to the broker\n");
    return EXIT_FAILURE;
  }
  mqtt_client_disconnect(client);
  return EXIT_SUCCESS;
}
