#ifndef MQTT_H
#define MQTT_H

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
typedef unsigned char mqtt_packet_type_t;

// MQTT QoS levels
typedef enum {
  QOS_0 = 0,
  QOS_1 = 1,
  QOS_2 = 2,
} mqtt_qos_t;

// MQTT reason codes
// https://docs.oasis-open.org/mqtt/mqtt/v5.0/os/mqtt-v5.0-os.html#_Toc3901033
typedef enum {
  MQTT_ERROR = -1, // non-standard error code
  MQTT_SUCCESS = 0x00,
  MQTT_NORMAL_DISCONNECTION = 0x00,
  MQTT_GRANTED_QOS_0 = 0x00,
  MQTT_GRANTED_QOS_1 = 0x01,
  MQTT_GRANTED_QOS_2 = 0x02,
  MQTT_DISCONNECT_WITH_WILL_MESSAGE = 0x04,
  MQTT_NO_MATCHING_SUBSCRIBERS = 0x10,
  MQTT_NO_SUBSCRIPTION_EXISTED = 0x11,
  MQTT_CONTINUE_AUTHENTICATION = 0x18,
  MQTT_RE_AUTHENTICATE = 0x19,
  MQTT_UNSPECIFIED_ERROR = 0x80,
  MQTT_MALFORMED_PACKET = 0x81,
  MQTT_PROTOCOL_ERROR = 0x82,
  MQTT_IMPLEMENTATION_SPECIFIC_ERROR = 0x83,
  MQTT_UNSUPPORTED_PROTOCOL_VERSION = 0x84,
  MQTT_CLIENT_IDENTIFIER_NOT_VALID = 0x85,
  MQTT_BAD_USER_NAME_OR_PASSWORD = 0x86,
  MQTT_NOT_AUTHORIZED = 0x87,
  MQTT_SERVER_UNAVAILABLE = 0x88,
  MQTT_SERVER_BUSY = 0x89,
  MQTT_BANNED = 0x8A,
  MQTT_SERVER_SHUTTING_DOWN = 0x8B,
  MQTT_BAD_AUTHENTICATION_METHOD = 0x8C,
  MQTT_KEEP_ALIVE_TIMEOUT = 0x8D,
  MQTT_SESSION_TAKEN_OVER = 0x8E,
  MQTT_TOPIC_FILTER_INVALID = 0x8F,
  MQTT_TOPIC_NAME_INVALID = 0x90,
  MQTT_PACKET_IDENTIFIER_IN_USE = 0x91,
  MQTT_PACKET_IDENTIFIER_NOT_FOUND = 0x92,
  MQTT_RECEIVE_MAXIMUM_EXCEEDED = 0x93,
  MQTT_TOPIC_ALIAS_INVALID = 0x94,
  MQTT_PACKET_TOO_LARGE = 0x95,
  MQTT_MESSAGE_RATE_TOO_HIGH = 0x96,
  MQTT_QUOTA_EXCEEDED = 0x97,
  MQTT_ADMINISTRATIVE_ACTION = 0x98,
  MQTT_PAYLOAD_FORMAT_INVALID = 0x99,
  MQTT_RETAIN_NOT_SUPPORTED = 0x9A,
  MQTT_QOS_NOT_SUPPORTED = 0x9B,
} mqtt_reason_code_t;

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
 * @return MQTT_SUCCESS if the connection was successful, an error code
 */
mqtt_reason_code_t mqtt_client_connect(mqtt_client_t *client);

/**
 * Loop to handle incoming messages.
 *
 * @param client The MQTT client
 * @return MQTT_SUCCESS if the loop was successful, an error code
 */
mqtt_reason_code_t mqtt_client_loop(mqtt_client_t *client);

/**
 * Disconnect from the MQTT broker.
 *
 * @param client The MQTT client
 * @return MQTT_NORMAL_DISCONNECTION if the disconnection was successful, an
 * error
 */
mqtt_reason_code_t mqtt_client_disconnect(mqtt_client_t *client);

/**
 * Subscribe to a topic.
 *
 * @param client The MQTT client
 * @param topic The topic to subscribed_topics
 * @return MQTT_SUCCESS if the subscription was successful, an error code
 */
mqtt_reason_code_t mqtt_client_subscribe(mqtt_client_t *client, char *topic);

/**
 * Check if a client is subscribed to a topic.
 *
 * @param client The MQTT client
 * @param topic The topic to Check
 * @return 1 if the client is subscribed to the topic, 0 otherwise
 */
int mqtt_client_is_subscribed(mqtt_client_t *client, char *topic);

/**
 * Wait for a message on a topic.
 *
 * @param client The MQTT client
 * @param topic The topic to wait for a message
 * @param message The message received
 * @return MQTT_SUCCESS if the message was received, an error code otherwise
 */
mqtt_reason_code_t mqtt_client_wait_message_on_topic(mqtt_client_t *client,
                                                     char *topic,
                                                     char **message);

/**
 * Unsubscribe from a topic.
 *
 * @param client The MQTT client
 * @param topic The topic to Unsubscribe
 * @return MQTT_SUCCESS if the unsubscription was successful, an error code
 */
mqtt_reason_code_t mqtt_client_unsubscribe(mqtt_client_t *client, char *topic);

/**
 * Publish a message to a topic.
 *
 * @param client The MQTT client
 * @param topic The topic where the message will be published
 * @param payload The message to be published
 * @return MQTT_SUCCESS if the message was published, an error code otherwise
 */
mqtt_reason_code_t mqtt_client_publish(mqtt_client_t *client, char *topic,
                                       char *payload);

/**
 * Destroy a MQTT client.
 *
 * @param client The MQTT client to destroy
 */
void mqtt_client_destroy(mqtt_client_t *client);

/**
 * Convert a reason code to a string.
 *
 * @param reason_code The reason code
 * @param packet_type The packet type
 * @return The string representation of the reason code
 */
char *mqtt_reason_code_to_string(mqtt_reason_code_t reason_code, mqtt_packet_type_t packet_type);

#endif // MQTT_H
