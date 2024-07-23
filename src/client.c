#include "../lib/mqtt.h"
#include <stdio.h>
#include <stdlib.h>

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
  char *username = NULL;
  char *password = NULL;
  mqtt_client_t *client = mqtt_client_create(host, port, client_id, username,
                                             password, 0, 0, 1, 60);
  if (client == NULL) {
    dprintf(2, "Error creating the MQTT client\n");
    return EXIT_FAILURE;
  };

  if (mqtt_client_connect(client) != OK) {
    dprintf(2, "Error connecting to the MQTT broker\n");
    return EXIT_FAILURE;
  }

  // Publish a message every 5 seconds
  for (;;) {
    if (mqtt_client_publish(client, "test", "Test MQTT message") != OK) {
      dprintf(2, "Error publishing the message\n");
      return EXIT_FAILURE;
    }
  }

  return EXIT_SUCCESS;
}
