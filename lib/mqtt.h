#ifndef MQTT_H
#define MQTT_H
#include "connack.h"
#include <stdint.h>

// MQTT packet types
enum {
  PACKET_TYPE_CONNECT = 0x10,
  PACKET_TYPE_CONNACK = 0x20,
  PACKET_TYPE_PUBLISH = 0x30,
  PACKET_TYPE_PUBACK = 0x40,
  PACKET_TYPE_PUBREC = 0x50,
  PACKET_TYPE_PUBREL = 0x60,
  PACKET_TYPE_PUBCOMP = 0x70,
  PACKET_TYPE_SUBSCRIBE = 0x80,
  PACKET_TYPE_SUBACK = 0x90,
  PACKET_TYPE_UNSUBSCRIBE = 0xA0,
  PACKET_TYPE_UNSUBACK = 0xB0,
  PACKET_TYPE_PINGREQ = 0xC0,
  PACKET_TYPE_PINGRESP = 0xD0,
  PACKET_TYPE_DISCONNECT = 0xE0,
};

// MQTT QoS levels
typedef enum {
  QOS_0 = 0,
  QOS_1 = 1,
  QOS_2 = 2,
} mqtt_qos_t;

typedef struct {
  int socket;
  char *host;
  int port;
  char *client_id;
  char *username;
  char *password;
  int subscribed_topics;
  char **topics;
  unsigned char qos;
  unsigned char retain;
  unsigned char clean_session;
  unsigned short keep_alive;
  // will
  char *will_topic;
  char *will_message;
  unsigned char will_qos;
  unsigned char will_retain;
} mqtt_client_t;

/**
 * Create a new MQTT client.
 *
 * @param host The MQTT broker host
 * @param port The MQTT broker port
 * @param client_id The client ID
 * @param username The username
 * @param password The password
 * @param qos The QoS level
 * @param retain The retain flag
 * @param clean_session The clean session flag
 * @param keep_alive The keep alive time
 * @param will_topic The will topic
 * @param will_message The will message
 * @param will_qos The will QoS level
 * @param will_retain The will retain flag
 * @return The MQTT client
 * @return NULL if the client could not be created
 */
mqtt_client_t *mqtt_client_create(char *host, int port, char *client_id,
                                  char *username, char *password,
                                  unsigned char qos, unsigned char retain,
                                  unsigned char clean_session,
                                  unsigned short keep_alive, char *will_topic,
                                  char *will_message, unsigned char will_qos,
                                  unsigned char will_retain);

/**
 * Connect to the MQTT broker.
 *
 * @param client The MQTT client
 * @param send_packet_only Send only the CONNECT packet, used for generating
 * wrong MQTT traffic
 * @return MQTT_SUCCESS if the connection was successful, an error code
 */
connack_reason_code_t mqtt_client_connect(mqtt_client_t *client,
                                          int send_packet_only);

/**
 * Disconnect from the MQTT broker.
 *
 * @param client The MQTT client
 */
void mqtt_client_disconnect(mqtt_client_t *client);

/**
 * Subscribe to a topic.
 *
 * @param client The MQTT client
 * @param topic The topic to subscribe to
 * @return MQTT_SUCCESS if the subscription was successful, an error code
 */
void mqtt_client_subscribe(mqtt_client_t *client, char *topic);

/**
 * Destroy a MQTT client.
 *
 * @param client The MQTT client to destroy
 */
void mqtt_client_destroy(mqtt_client_t *client);

#endif // MQTT_H
