#ifndef MQTT_H
#define MQTT_H

#define MQTT_CONNECT 0x10
#define MQTT_CONNACK 0x20
#define MQTT_PUBLISH 0x30
#define MQTT_PUBACK 0x40
#define MQTT_PUBREC 0x50
#define MQTT_PUBREL 0x60
#define MQTT_PUBCOMP 0x70
#define MQTT_SUBSCRIBE 0x80
#define MQTT_SUBACK 0x90
#define MQTT_UNSUBSCRIBE 0xA0
#define MQTT_UNSUBACK 0xB0
#define MQTT_PINGREQ 0xC0
#define MQTT_PINGRESP 0xD0
#define MQTT_DISCONNECT 0xE0

#define MQTT_QOS_0 0x00
#define MQTT_QOS_1 0x01
#define MQTT_QOS_2 0x02

// Error codes
typedef enum {
  OK,
  TOPIC_NOT_SUBSCRIBED,
  TOPIC_ALREADY_SUBSCRIBED,
  SOCKET_ERROR,
  CONNECT_ERROR,
  SUBSCRIBE_ERROR,
  SUBACK_NOT_RECEIVED,
  PUBLISH_ERROR,
  PUBACK_NOT_RECEIVED,
  PUBREC_NOT_RECEIVED,
  PUBREL_NOT_SENT,
  PUBCOMP_NOT_RECEIVED,
} mqtt_error_t;

typedef struct {
  unsigned char type;
  unsigned char flags;
  unsigned short lenght;
  unsigned char *data;
} mqtt_message_t;

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
} mqtt_client_t;

/**
 * Create a new MQTT message.
 *
 * @param type Type of the message
 * @param flags Flags of the message
 * @param lenght Lenght of the message
 * @param data Data of the message
 * @return The new MQTT message
 */
mqtt_message_t *mqtt_create(unsigned char type, unsigned char flags,
                            unsigned short lenght, unsigned char *data);

/**
 * Destroy a MQTT message.
 *
 * @param message The message to Destroy
 */
void mqtt_destroy(mqtt_message_t *message);

/**
 * Create a new MQTT client.
 */
mqtt_client_t *mqtt_client_create(char *host, int port, char *client_id,
                                  char *username, char *password,
                                  unsigned char qos, unsigned char retain,
                                  unsigned char clean_session,
                                  unsigned short keep_alive);

/**
 * Connect to the MQTT broker.
 *
 * @param client The MQTT client
 * @return OK if the connection was successful, an error code otherwise
 */
mqtt_error_t mqtt_client_connect(mqtt_client_t *client);

/**
 * Disconnect from the MQTT broker.
 *
 * @param client The MQTT client
 * @return OK if the disconnection was successful, an error code otherwise
 */
mqtt_error_t mqtt_client_disconnect(mqtt_client_t *client);

/**
 * Subscribe to a topic.
 *
 * @param client The MQTT client
 * @param topic The topic to subscribed_topics
 * @return OK if the subscription was successeful, an error code otherwise
 */
mqtt_error_t mqtt_client_subscribe(mqtt_client_t *client, char *topic);

/**
 * Check if a client is subscribed to a topic.
 *
 * @param client The MQTT client
 * @param topic The topic to Check
 * @return 1 if the client is subscribed to the topic, 0 otherwise
 */
int mqtt_client_is_subscribed(mqtt_client_t *client, char *topic);

/**
 * Unsubscribe from a topic.
 *
 * @param client The MQTT client
 * @param topic The topic to Unsubscribe
 * @return OK if the unsubscribe was successeful, an error code otherwise
 */
mqtt_error_t mqtt_client_unsubscribe(mqtt_client_t *client, char *topic);

/**
 * Publish a message to a topic.
 *
 * @param client The MQTT client
 * @param topic The topic where the message will be published
 * @param payload The message to be published
 * @return OK if the publish was successeful, an error code otherwise
 */
mqtt_error_t mqtt_client_publish(mqtt_client_t *client, char *topic,
                                 char *payload);

/**
 * Destroy a MQTT client.
 *
 * @param client The MQTT client to destroy
 */
void mqtt_client_destroy(mqtt_client_t *client);

#endif // MQTT_H
