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

/**
 * MQTT message.
 *
 * @brief The MQTT message used for the subscribe handler callback.
 */
typedef struct {
  char *topic;
  char *message;
} mqtt_message_t;

/**
 * MQTT subscribe handler callback.
 *
 * @brief The MQTT subscribe handler callback.
 */
typedef void (*mqtt_subscribe_handler_t)(mqtt_message_t *message);

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
void *mqtt_client_create(char *host, int port, char *client_id, char *username,
                         char *password, unsigned char qos,
                         unsigned char retain, unsigned char clean_session,
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
connack_reason_code_t mqtt_client_connect(void *client, int send_packet_only);

/**
 * Disconnect from the MQTT broker.
 *
 * @param client The MQTT client
 */
void mqtt_client_disconnect(void *client);

/**
 * Set the MQTT subscribe handler.
 *
 * @brief The MQTT subscribe handler is called when a message is received.
 * @param client The MQTT client
 * @param handler The MQTT subscribe handler
 */
void mqtt_client_set_subscribe_handler(void *client,
                                       mqtt_subscribe_handler_t handler);

/**
 * Start the MQTT client loop.
 *
 * @brief The MQTT client loop is started when the client is connected.
 * @note This function will spawn a new thread.
 * @param client The MQTT client
 */
void mqtt_client_loop(void *client);

/**
 * Stop the MQTT client loop.
 * @brief The MQTT client loop is stopped when the client is disconnected.
 * @note This function is blocking.
 * @param client The MQTT client
 */
void mqtt_client_stop(void *client);

/**
 * Subscribe to a topic.
 *
 * @param client The MQTT client
 * @param topic The topic to subscribe to
 * @return MQTT_SUCCESS if the subscription was successful, an error code
 */
void mqtt_client_subscribe(void *client, char *topic);

/**
 * Publish a message to a topic.
 *
 * @param client The MQTT client
 * @param topic The topic to publish to
 * @param message The message to publish
 * @param qos The QoS level
 */
void mqtt_client_publish(void *client, char *topic, char *message,
                         unsigned char qos);

/**
 * Destroy a MQTT client.
 *
 * @param client The MQTT client to destroy
 */
void mqtt_client_destroy(void *client);

/**
 * Destroy a MQTT message.
 *
 * @param message The MQTT message to destroy
 */
void mqtt_message_destroy(mqtt_message_t *message);

#endif // MQTT_H
