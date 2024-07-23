#include "../lib/mqtt.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sched.h>

/**
 * The main function of the MQTT client.
 *
 * @param argc Number of arguments
 * @param argv Arguments
 */
int main(void) {

  char *host = "localhost";
  int port = 1883;
  char *client_id = "mqtt_client";
  char *username = "user";
  char *password = "password";
  unsigned char qos = 0;
  unsigned char retain = 0;
  unsigned char clean_session = 1;
  unsigned short keep_alive = 60;
  char *will_topic = "crash";
  char *will_message = "mqtt_client crashed";
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
  mqtt_reason_code_t ret = mqtt_client_connect(client);
  dprintf(2, "Reason code returned: %s\n", mqtt_reason_code_to_string(ret, PACKET_TYPE_CONNACK));
  if (ret != MQTT_SUCCESS) {
    fprintf(stderr, "Could not connect to the broker\n");
    mqtt_client_destroy(client);
    return EXIT_FAILURE;
  }
  return EXIT_SUCCESS;
}
